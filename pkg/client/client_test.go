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

func createUser(t *testing.T, raftNode *metadata.RaftNode, user metadata.User) {
	userBytes, _ := json.Marshal(user)
	cmd := metadata.LogCommand{Type: metadata.CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := raftNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Create user raft apply failed: %v", err)
	}
	if resp := future.Response(); resp != nil {
		if err, ok := resp.(error); ok {
			t.Fatalf("Create user fsm failed: %v", err)
		}
	}
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

func bootstrapCluster(t *testing.T, raftNode *metadata.RaftNode) *mlkem.EncapsulationKey768 {
	waitLeader(t, raftNode.Raft)
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	key := metadata.ClusterKey{
		ID:        "key-1",
		EncKey:    ek.Bytes(),
		DecKey:    dk.Bytes(),
		CreatedAt: time.Now().Unix(),
	}
	keyBytes, _ := json.Marshal(key)
	cmd := metadata.LogCommand{Type: metadata.CmdRotateKey, Data: keyBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := raftNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap cluster key apply failed: %v", err)
	}
	return dk.EncapsulationKey()
}

func registerNode(t *testing.T, serverURL, secret string, node metadata.Node) {
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
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

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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

	dataServer := data.NewServer(dataStore, signKey.Public(), nil)
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
	fileID := "file-1"
	key, err := c.WriteFile(fileID, bytes.NewReader(content), int64(len(content)), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 5. Read File (Raw)
	rc, err := c.ReadFile(fileID, key)
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
	if err := c.EnsureRoot(); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	fileName := "/file-2.txt"
	if err := c.CreateFile(fileName, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	dfs := c.FS()
	f, err := dfs.Open(fileName)
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
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

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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
		server := data.NewServer(store, signKey.Public(), nil)
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
	_, err = c.WriteFile("repl-file", bytes.NewReader(content), int64(len(content)), 0644)
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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
	dataServer := data.NewServer(dataStore, signKey.Public(), nil)
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
	if err := c.EnsureRoot(); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// Mkdir /a
	if err := c.Mkdir("/a"); err != nil {
		t.Fatalf("Mkdir /a failed: %v", err)
	}

	// Mkdir /a/b
	if err := c.Mkdir("/a/b"); err != nil {
		t.Fatalf("Mkdir /a/b failed: %v", err)
	}

	// Create File
	content := []byte("file content")
	if err := c.CreateFile("/a/b/f.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// Resolve
	inode, key, err := c.ResolvePath("/a/b/f.txt")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	// Read
	rc, err := c.ReadFile(inode.ID, key)
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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
	server1 := data.NewServer(store1, signKey.Public(), nil)
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
	_, err = c.WriteFile("repair-file", bytes.NewReader(content), int64(len(content)), 0644) // Raw write
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
	server2 := data.NewServer(store2, signKey.Public(), nil)
	ts2 := httptest.NewServer(server2)
	defer ts2.Close()

	dataDir3 := t.TempDir()
	st3, _ := createTestStorage(t, dataDir3)
	store3, _ := data.NewDiskStore(st3)
	server3 := data.NewServer(store3, signKey.Public(), nil)
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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
	realHandler := data.NewServer(dataStore, signKey.Public(), nil)

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

	key, err := c.WriteFile("readahead-file", bytes.NewReader(content), int64(dataSize), 0644)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Clear log before reading
	logMu.Lock()
	requestLog = make([]string, 0)
	logMu.Unlock()

	// 4. Read File (Linearly)
	reader, err := c.NewReader("readahead-file", key)
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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
	dataServer := data.NewServer(dataStore, signKey.Public(), nil)
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
	if err := c.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("garbage "), 1000) // ~8KB
	if err := c.CreateFile("/gc-test", bytes.NewReader(content), int64(len(content))); err != nil {
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
	if err := c.RemoveEntry("/gc-test"); err != nil {
		t.Fatal(err)
	}

	// 6. Trigger GC
	metaServer.ForceGCScan()

	// 7. Verify Deletion
	start := time.Now()
	deleted := false
	for time.Since(start) < 2*time.Second {
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	defer metaNode.Shutdown()
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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
	dataServer := data.NewServer(dataStore, signKey.Public(), nil)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()
	registerNode(t, tsMeta.URL, "testsecret", metadata.Node{
		ID: "d1", Address: tsData.URL, Status: metadata.NodeStatusActive,
	})

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	if err := c.EnsureRoot(); err != nil {
		t.Fatal(err)
	}

	c.Mkdir("/a")
	c.Mkdir("/a/b")
	c.Mkdir("/a/b/c")
	content := []byte("data")
	c.CreateFile("/a/b/c/file.txt", bytes.NewReader(content), int64(len(content)))

	inode, _, err := c.ResolvePath("/a/b/c/file.txt")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if inode.ID == "" {
		t.Error("Empty ID")
	}

	_, _, err = c.ResolvePath("/missing")
	if err == nil {
		t.Error("Expected error")
	}
}
