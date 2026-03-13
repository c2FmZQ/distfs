// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
)

func createTestStorage(t *testing.T, dir string) (*storage.Storage, storage_crypto.MasterKey) {
	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(dir, mk)
	return st, mk
}

var nextTestUID uint32 = 1000

func createUser(t *testing.T, raftNode *metadata.RaftNode, user metadata.User) {
	metadata.CreateUser(t, raftNode, user)
}

func waitLeader(t *testing.T, r *raft.Raft) {
	leader := false
	for i := 0; i < 50; i++ {
		if r.State() == raft.Leader {
			leader = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !leader {
		t.Fatal("Node did not become leader")
	}
}

func bootstrapCluster(t *testing.T, raftNode *metadata.RaftNode) (*mlkem.EncapsulationKey768, *mlkem.DecapsulationKey768, []byte) {
	waitLeader(t, raftNode.Raft)
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	key := metadata.ClusterKey{
		ID:        "key-1",
		EncKey:    ek.Bytes(),
		DecKey:    nil, // DO NOT store private key in FSM
		CreatedAt: time.Now().Unix(),
	}
	keyBytes, _ := json.Marshal(key)
	cmd := metadata.LogCommand{Type: metadata.CmdRotateKey, Data: keyBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := raftNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap cluster key apply failed: %v", err)
	}

	// Bootstrap cluster sign key
	csk, _ := crypto.GenerateIdentityKey()
	cskData := metadata.ClusterSignKey{
		Public:           csk.Public(),
		EncryptedPrivate: csk.MarshalPrivate(),
	}
	cskBytes, _ := json.Marshal(cskData)
	future = raftNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdSetClusterSignKey, Data: cskBytes}.Marshal(), 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap sign key apply failed: %v", err)
	}

	return dk.EncapsulationKey(), dk, csk.Public()
}

func registerNode(t *testing.T, serverURL, secret string, node metadata.Node) {
	if node.LastHeartbeat == 0 {
		node.LastHeartbeat = time.Now().Unix()
	}
	body, _ := json.Marshal(node)
	req, _ := http.NewRequest("POST", serverURL+"/v1/node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Raft-Secret", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Register node failed: %d", resp.StatusCode)
	}
}

func TestClientIntegration(t *testing.T) {
	// 1. Setup Metadata Node
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	// Bootstrap
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})

	// Wait for leader
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	// Generate User Keys
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()

	// Register User
	user := metadata.User{
		ID:      "user-1",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUser(t, metaNode, user)

	// 2. Setup Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)

	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	node := metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNode(t, tsMeta.URL, "testsecret", node)

	// 3. Client
	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// 4. Write File (Raw)
	content := []byte("hello distributed filesystem world")
	nonce := make([]byte, 16)
	rand.Read(nonce)
	fileID := metadata.GenerateInodeID("user-1", nonce)
	key, err := c.WriteFile(t.Context(), fileID, nonce, bytes.NewReader(content), int64(len(content)), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 5. Read File (Raw)
	rc, err := c.ReadFile(t.Context(), fileID, key)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	readBack, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("ReadFile read failed: %v", err)
	}

	if string(readBack) != string(content) {
		t.Errorf("Content mismatch: got %s, want %s", readBack, content)
	}

	// 6. FS Integration
	if _, err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	fileName := "/file-2.txt"
	if err := c.CreateFile(t.Context(), fileName, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	dfs := c.FS(t.Context())
	f, err := dfs.Open("file-2.txt")
	if err != nil {
		t.Fatalf("FS Open failed: %v", err)
	}
	defer f.Close()

	buf := make([]byte, len(content))
	if _, err := f.Read(buf); err != nil {
		t.Fatalf("FS Read failed: %v", err)
	}
	if string(buf) != string(content) {
		t.Error("FS Read mismatch")
	}

	info, _ := f.Stat()
	if info.Size() != int64(len(content)) {
		t.Error("Stat size mismatch")
	}
}

func TestReplication(t *testing.T) {
	// 1. Setup Metadata Node
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})

	// Wait for leader
	leader := false
	for i := 0; i < 50; i++ {
		if metaNode.Raft.State() == raft.Leader {
			leader = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !leader {
		t.Fatal("Node did not become leader")
	}

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	// Generate User Keys
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()

	// Register User
	user := metadata.User{
		ID:      "user-1",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUser(t, metaNode, user)

	// 2. Three Data Nodes
	nodes := make([]*httptest.Server, 3)
	stores := make([]data.Store, 3)
	for i := 0; i < 3; i++ {
		dir := t.TempDir()
		st, _ := createTestStorage(t, dir)
		store, _ := data.NewDiskStore(st)
		stores[i] = store
		server := data.NewServer(store, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
		ts := httptest.NewServer(server)
		nodes[i] = ts
		defer ts.Close()

		// Register with Metadata
		node := metadata.Node{
			ID:      fmt.Sprintf("data-%d", i),
			Address: ts.URL,
			Status:  metadata.NodeStatusActive,
		}
		registerNode(t, tsMeta.URL, "testsecret", node)
	}

	// 3. Client
	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// 4. Write
	content := bytes.Repeat([]byte("replicated data "), 500) // ~8KB
	nonceRepl := make([]byte, 16)
	rand.Read(nonceRepl)
	fileID := metadata.GenerateInodeID("user-1", nonceRepl)
	_, err = c.WriteFile(t.Context(), fileID, nonceRepl, bytes.NewReader(content), int64(len(content)), 0644)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// 5. Verify on ALL nodes
	chunks := stores[0].ListChunks()
	var chunkID string
	for id := range chunks {
		chunkID = id
		break
	}

	if chunkID == "" {
		t.Fatal("No chunks found on primary")
	}

	for i := 0; i < 3; i++ {
		has, _ := stores[i].HasChunk(chunkID)
		if !has {
			t.Errorf("Node %d missing chunk %s", i, chunkID)
		}
	}
}

func TestDirectories(t *testing.T) {
	// Setup Cluster (Single node fine for logic)
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	// Generate User Keys
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()

	// Register User
	user := metadata.User{
		ID:      "user-1",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUser(t, metaNode, user)

	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	node := metadata.Node{
		ID:      "data-1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNode(t, tsMeta.URL, "testsecret", node)

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// Ensure Root
	if _, err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// Mkdir /a
	if err := c.Mkdir(t.Context(), "/a", 0755); err != nil {
		t.Fatalf("Mkdir /a failed: %v", err)
	}

	// Mkdir /a/b
	if err := c.Mkdir(t.Context(), "/a/b", 0755); err != nil {
		t.Fatalf("Mkdir /a/b failed: %v", err)
	}

	// Create File
	content := []byte("file content")
	if err := c.CreateFile(t.Context(), "/a/b/f.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// Resolve
	inode, key, err := c.ResolvePath(t.Context(), "/a/b/f.txt")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	// Read
	rc, err := c.ReadFile(t.Context(), inode.ID, key)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	readBack, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("ReadFile read failed: %v", err)
	}
	if string(readBack) != string(content) {
		t.Errorf("Content mismatch")
	}
}

func TestReplicationRepair(t *testing.T) {
	// 1. Setup Metadata
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	// Generate User Keys
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()

	// Register User
	user := metadata.User{
		ID:      "user-1",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUser(t, metaNode, user)

	// 2. Start ONE Data Node initially
	dataDir1 := t.TempDir()
	st1, _ := createTestStorage(t, dataDir1)
	store1, _ := data.NewDiskStore(st1)
	server1 := data.NewServer(store1, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	ts1 := httptest.NewServer(server1)
	defer ts1.Close()

	node1 := metadata.Node{ID: "data-1", Address: ts1.URL, Status: metadata.NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	registerNode(t, tsMeta.URL, "testsecret", node1)

	// 3. Write File (Will have 1 replica)
	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	content := bytes.Repeat([]byte("repair me "), 1000) // ~10KB
	nonceRepair := make([]byte, 16)
	rand.Read(nonceRepair)
	fileID := metadata.GenerateInodeID("user-1", nonceRepair)
	_, err = c.WriteFile(t.Context(), fileID, nonceRepair, bytes.NewReader(content), int64(len(content)), 0644) // Raw write
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Get Chunk ID
	chunks := store1.ListChunks()
	var chunkID string
	for id := range chunks {
		chunkID = id
		break
	}
	if chunkID == "" {
		t.Fatal("No chunks found on primary")
	}

	// 4. Start 2 more Data Nodes
	dataDir2 := t.TempDir()
	st2, _ := createTestStorage(t, dataDir2)
	store2, _ := data.NewDiskStore(st2)
	server2 := data.NewServer(store2, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	ts2 := httptest.NewServer(server2)
	defer ts2.Close()

	dataDir3 := t.TempDir()
	st3, _ := createTestStorage(t, dataDir3)
	store3, _ := data.NewDiskStore(st3)
	server3 := data.NewServer(store3, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	ts3 := httptest.NewServer(server3)
	defer ts3.Close()

	node2 := metadata.Node{ID: "data-2", Address: ts2.URL, Status: metadata.NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	registerNode(t, tsMeta.URL, "testsecret", node2)

	node3 := metadata.Node{ID: "data-3", Address: ts3.URL, Status: metadata.NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	registerNode(t, tsMeta.URL, "testsecret", node3)

	// 5. Trigger Repair
	metaServer.ForceReplicationScan()

	// 6. Wait for verify
	start := time.Now()
	repaired := false
	for time.Since(start) < 5*time.Second {
		h2, _ := store2.HasChunk(chunkID)
		h3, _ := store3.HasChunk(chunkID)
		if h2 && h3 {
			repaired = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !repaired {
		t.Fatal("Chunk not repaired to new nodes")
	}
}

func TestReadAhead(t *testing.T) {
	// 1. Setup Metadata
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	// Register User
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      "user-1",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUser(t, metaNode, user)

	// 2. Setup Data Node with Tracking
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	realHandler := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)

	requestLog := make([]string, 0)
	var logMu sync.Mutex

	tsData := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logMu.Lock()
		requestLog = append(requestLog, r.Method+" "+r.URL.Path)
		logMu.Unlock()
		realHandler.ServeHTTP(w, r)
	}))
	defer tsData.Close()

	// Register Data Node
	node := metadata.Node{
		ID:      "data-1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNode(t, tsMeta.URL, "testsecret", node)

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// 3. Create File with 5 Chunks
	dataSize := 5 * 1024 * 1024
	content := make([]byte, dataSize)
	content[0] = 'A'
	content[dataSize-1] = 'Z'

	nonceRA := make([]byte, 16)
	rand.Read(nonceRA)
	fileID := metadata.GenerateInodeID("user-1", nonceRA)

	key, err := c.WriteFile(t.Context(), fileID, nonceRA, bytes.NewReader(content), int64(dataSize), 0644)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Clear log before reading
	logMu.Lock()
	requestLog = make([]string, 0)
	logMu.Unlock()

	// 4. Read File (Linearly)
	reader, err := c.NewReader(t.Context(), fileID, key)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	if len(reader.inode.ChunkManifest) != 5 {
		t.Fatalf("Expected 5 chunks, got %d", len(reader.inode.ChunkManifest))
	}

	// Read first 100 bytes (triggers Chunk 0 read)
	buf := make([]byte, 100)
	if _, err := reader.Read(buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Wait a bit for async prefetch
	time.Sleep(500 * time.Millisecond)

	// Check logs
	logMu.Lock()
	defer logMu.Unlock()

	count := 0
	for _, req := range requestLog {
		if len(req) > 3 && req[:3] == "GET" {
			count++
		}
	}

	if count < 4 {
		t.Errorf("Expected at least 4 chunk GET requests (Read-Ahead), got %d", count)
		for _, k := range requestLog {
			t.Logf("Request: %s", k)
		}
	}
}

func TestGarbageCollection(t *testing.T) {
	// 1. Setup Metadata
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	// Register User
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      "user-1",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUser(t, metaNode, user)

	// 2. Setup Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	node := metadata.Node{
		ID:      "data-1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNode(t, tsMeta.URL, "testsecret", node)

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// 3. Create File
	if _, err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("garbage "), 1000) // ~8KB
	if err := c.CreateFile(t.Context(), "/gc-test", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}

	// 4. Verify Chunk Exists
	chunks := dataStore.ListChunks()
	var chunkID string
	count := 0
	for id, err := range chunks {
		if err != nil {
			t.Fatal(err)
		}
		chunkID = id
		count++
		break
	}
	if count == 0 {
		t.Fatal("No chunks found")
	}

	// 5. Delete File
	if err := c.RemoveEntry(t.Context(), "/gc-test"); err != nil {
		t.Fatal(err)
	}

	// 6. Trigger GC
	metaServer.ForceGCScan()

	// 7. Verify Deletion
	start := time.Now()
	deleted := false
	for time.Since(start) < 5*time.Second {
		exists, _ := dataStore.HasChunk(chunkID)
		if !exists {
			deleted = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !deleted {
		t.Error("Chunk was not garbage collected")
	}
}

func TestResolvePathComplex(t *testing.T) {
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, []byte("test-cluster-secret"))
	defer metaNode.Shutdown()
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	metaServer.StopKeyRotation()
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	createUser(t, metaNode, metadata.User{
		ID: "user-1", SignKey: userSignKey.Public(), EncKey: dk.EncapsulationKey().Bytes(),
	})

	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()
	registerNode(t, tsMeta.URL, "testsecret", metadata.Node{
		ID: "d1", Address: tsData.URL, Status: metadata.NodeStatusActive,
	})

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	if _, err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatal(err)
	}

	c.Mkdir(t.Context(), "/a", 0755)
	c.Mkdir(t.Context(), "/a/b", 0755)
	c.Mkdir(t.Context(), "/a/b/c", 0755)
	content := []byte("data")
	c.CreateFile(t.Context(), "/a/b/c/file.txt", bytes.NewReader(content), int64(len(content)))

	inode, _, err := c.ResolvePath(t.Context(), "/a/b/c/file.txt")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if inode.ID == "" {
		t.Error("Empty ID")
	}

	_, _, err = c.ResolvePath(t.Context(), "/missing")
	if err == nil {
		t.Error("Expected error")
	}
}
