//go:build !wasm

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
	"strings"
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

func createUser(t *testing.T, raftNode *metadata.RaftNode, user metadata.User, userSK *crypto.IdentityKey, adminID string, adminSK *crypto.IdentityKey) {
	metadata.CreateUser(t, raftNode, user, userSK, adminID, adminSK)
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
	cskCmdBytes, err := metadata.LogCommand{Type: metadata.CmdSetClusterSignKey, Data: cskBytes}.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal bootstrap sign key: %v", err)
	}
	future = raftNode.Raft.Apply(cskCmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap sign key apply failed: %v", err)
	}

	return dk.EncapsulationKey(), dk, csk.Public()
}

func registerNode(t *testing.T, serverEndpoint, secret string, node metadata.Node) {
	if node.LastHeartbeat == 0 {
		node.LastHeartbeat = time.Now().Unix()
	}
	body, _ := json.Marshal(node)
	req, _ := http.NewRequest("POST", serverEndpoint+"/v1/node", bytes.NewReader(body))
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
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)

	// 1. Setup User (Bob)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// Admin provisions a home directory for user-1
	if err := adminClient.Mkdir(t.Context(), "/home", 0755); err != nil {
		t.Fatalf("Admin failed to create /home: %v", err)
	}
	if err := adminClient.MkdirExtended(t.Context(), "/home/user-1", 0755, MkdirOptions{OwnerID: "user-1"}); err != nil {
		t.Fatalf("Admin failed to create /home/user-1: %v", err)
	}

	// 4. Write File (Raw)
	content := []byte("hello distributed filesystem world")
	nonce := metadata.GenerateNonce()
	fileID := metadata.GenerateInodeID("user-1", nonce)
	key, err := c.writeFile(t.Context(), fileID, nonce, bytes.NewReader(content), int64(len(content)), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 5. Read File (Raw)
	rc, err := c.readFile(t.Context(), fileID, key)
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
	fileName := "/home/user-1/file-2.txt"
	if err := c.CreateFile(t.Context(), fileName, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	dfs := c.FS(t.Context())
	f, err := dfs.Open("home/user-1/file-2.txt")
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

	finfo, _ := f.Stat()
	if finfo.Size() != int64(len(content)) {
		t.Error("Stat size mismatch")
	}
}

func TestReplication(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)

	// 1. Setup User (Bob)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// 2. Extra Data Nodes
	stores := make([]data.Store, 2)
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		st, _ := createTestStorage(t, dir)
		store, _ := data.NewDiskStore(st)
		stores[i] = store
		server := data.NewServer(store, adminClient.signKey.Public(), metaNode.FSM, data.NoopValidator{}, true, true)
		tsDN := httptest.NewServer(server)
		t.Cleanup(func() { tsDN.Close() })

		registerNode(t, ts.URL, "testsecret", metadata.Node{
			ID:      fmt.Sprintf("data-%d", i+2),
			Address: tsDN.URL,
			Status:  metadata.NodeStatusActive,
		})
	}

	// Admin provisions a home directory for user-1
	if err := adminClient.Mkdir(t.Context(), "/home", 0755); err != nil {
		t.Fatalf("Admin failed to create /home: %v", err)
	}
	if err := adminClient.MkdirExtended(t.Context(), "/home/user-1", 0755, MkdirOptions{OwnerID: "user-1"}); err != nil {
		t.Fatalf("Admin failed to create /home/user-1: %v", err)
	}

	// 4. Write
	content := bytes.Repeat([]byte("replicated data "), 500) // ~8KB
	if err := c.CreateFile(t.Context(), "/home/user-1/repl.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 5. Read back
	inode, key, err := c.resolvePath(t.Context(), "/home/user-1/repl.txt")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	rc, err := c.readFile(t.Context(), inode.ID, key)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	readBack, _ := io.ReadAll(rc)
	rc.Close()

	if !bytes.Equal(readBack, content) {
		t.Fatal("content mismatch")
	}
}

func TestDirectories(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)

	// 1. Setup User (Bob)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// Admin provisions a home directory for user-1
	if _, err := c.EnsureRoot(t.Context()); err != nil && err != metadata.ErrExists {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// Mkdir /a
	if err := adminClient.Mkdir(t.Context(), "/a", 0755); err != nil {
		t.Fatalf("Mkdir /a failed: %v", err)
	}

	// Mkdir /a/b
	if err := adminClient.Mkdir(t.Context(), "/a/b", 0755); err != nil {
		t.Fatalf("Mkdir /a/b failed: %v", err)
	}

	// Create File
	content := []byte("file content")
	if err := adminClient.CreateFile(t.Context(), "/a/b/f.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// Resolve
	inode, key, err := adminClient.resolvePath(t.Context(), "/a/b/f.txt")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	// Read
	rc, err := adminClient.readFile(t.Context(), inode.ID, key)
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
	adminClient, metaNode, metaServer, ts, adminID, adminSK := setupTestClient(t)
	defer metaNode.Shutdown()
	defer ts.Close()
	// 1. Setup User (Bob)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// Admin provisions a home directory for user-1
	content := bytes.Repeat([]byte("repair me "), 1000) // ~10KB
	nonceRepair := metadata.GenerateNonce()
	fileID := metadata.GenerateInodeID("user-1", nonceRepair)
	_, err := c.writeFile(t.Context(), fileID, nonceRepair, bytes.NewReader(content), int64(len(content)), 0644) // Raw write
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// 4. Start 2 more Data Nodes
	stores := make([]data.Store, 2)
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		st, _ := createTestStorage(t, dir)
		store, _ := data.NewDiskStore(st)
		stores[i] = store
		server := data.NewServer(store, adminClient.signKey.Public(), metaNode.FSM, data.NoopValidator{}, true, true)
		tsDN := httptest.NewServer(server)
		t.Cleanup(func() { tsDN.Close() })

		registerNode(t, ts.URL, "testsecret", metadata.Node{
			ID:      fmt.Sprintf("data-%d", i+2),
			Address: tsDN.URL,
			Status:  metadata.NodeStatusActive,
		})
	}

	// 5. Trigger Repair
	metaServer.ForceReplicationScan()

	// 6. Wait for verify
	start := time.Now()
	repaired := false
	for time.Since(start) < 10*time.Second {
		// We need the chunk ID. Since we only wrote one file, we can look it up in metadata.
		inode, _ := c.getInode(t.Context(), fileID)
		var chunkID string
		if len(inode.ChunkManifest) > 0 {
			chunkID = inode.ChunkManifest[0].ID
		}
		if chunkID != "" {
			h2, _ := stores[0].HasChunk(chunkID)
			h3, _ := stores[1].HasChunk(chunkID)
			if h2 && h3 {
				repaired = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !repaired {
		t.Fatal("Chunk not repaired to new nodes")
	}
}

func TestReadAhead(t *testing.T) {
	// 1. Setup a fresh cluster to avoid interference from default nodes
	tc := metadata.SetupRawCluster(t)
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 2. Setup Tracking Data Node as the ONLY data node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)

	csk := metadata.GetClusterSignKey(tc.Node.FSM)
	realHandler := data.NewServer(dataStore, csk.Public, tc.Node.FSM, data.NoopValidator{}, true, true)

	requestLog := make([]string, 0)
	var logMu sync.Mutex

	tsData := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logMu.Lock()
		requestLog = append(requestLog, r.Method+" "+r.URL.Path)
		logMu.Unlock()
		realHandler.ServeHTTP(w, r)
	}))
	defer tsData.Close()

	registerNode(t, tc.TS.URL, "testsecret", metadata.Node{
		ID:      "data-tracking",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	})

	// 3. Setup Admin Client to provision the backbone
	svKey, _ := crypto.UnmarshalEncapsulationKey(tc.EpochEK)
	adminClient := NewClient(tc.TS.URL).
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithAdmin(true).
		withServerKey(svKey).
		WithRegistry("/registry")

	if err := adminClient.Login(t.Context()); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}
	if err := adminClient.BootstrapFileSystem(t.Context()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// 4. Provision User-1
	c, _, _ := provisionUser(t, tc.TS, tc.Node, adminClient, tc.AdminID, tc.AdminSK, "user-1")

	// Ensure client uses the correct node configuration
	c.ClearNodeCache()

	// 5. Create File with 20 Chunks
	dataSize := 20 * 1024 * 1024
	content := make([]byte, dataSize)
	content[0] = 'A'
	content[dataSize-1] = 'Z'

	nonceRA := metadata.GenerateNonce()
	fileID := metadata.GenerateInodeID("user-1", nonceRA)

	key, err := c.writeFile(t.Context(), fileID, nonceRA, bytes.NewReader(content), int64(dataSize), 0644)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Clear log before reading
	logMu.Lock()
	requestLog = make([]string, 0)
	logMu.Unlock()

	// 6. Read File (Linearly)
	reader, err := c.newReader(t.Context(), fileID, key)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	if len(reader.inode.ChunkManifest) != 20 {
		t.Fatalf("Expected 20 chunks, got %d", len(reader.inode.ChunkManifest))
	}

	// Read first 2 chunks (triggers readaheads for others)
	for i := 0; i < 2; i++ {
		buf := make([]byte, 100)
		if _, err := reader.Read(buf); err != nil {
			t.Fatalf("Read chunk %d failed: %v", i, err)
		}
		// Skip to next chunk to trigger sequential prefetch
		reader.offset = int64((i + 1) * crypto.ChunkSize)
	}

	// Wait a bit for async prefetch
	time.Sleep(2 * time.Second)

	// Check logs
	logMu.Lock()
	defer logMu.Unlock()

	count := 0
	for _, req := range requestLog {
		if strings.Contains(req, "GET /v1/data/") {
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
	adminClient, metaNode, metaServer, ts, adminID, adminSK := setupTestClient(t)
	defer metaNode.Shutdown()
	defer ts.Close()

	// 1. Setup User (Bob)
	_, _, _ = provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// Admin provisions a home directory for user-1
	content := bytes.Repeat([]byte("garbage "), 1000) // ~8KB
	if err := adminClient.CreateFile(t.Context(), "/gc-test", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}

	// 5. Delete File
	if err := adminClient.Remove(t.Context(), "/gc-test"); err != nil {
		t.Fatal(err)
	}

	// 6. Trigger GC
	metaServer.ForceGCScan()

	// 7. Verify Deletion (In metadata at least, chunk GC is async)
	time.Sleep(1 * time.Second)
}

func TestResolvePathComplex(t *testing.T) {
	adminClient, metaNode, metaServer, ts, adminID, adminSK := setupTestClient(t)
	defer metaNode.Shutdown()
	defer ts.Close()
	metaServer.StopKeyRotation()
	// 1. Setup User (Bob)
	_, _, _ = provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// Admin provisions a home directory for user-1
	if err := adminClient.Mkdir(t.Context(), "/a", 0755); err != nil {
		t.Fatal(err)
	}
	if err := adminClient.Mkdir(t.Context(), "/a/b", 0755); err != nil {
		t.Fatal(err)
	}
	if err := adminClient.Mkdir(t.Context(), "/a/b/c", 0755); err != nil {
		t.Fatal(err)
	}
	content := []byte("data")
	if err := adminClient.CreateFile(t.Context(), "/a/b/c/file.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}

	inode, _, err := adminClient.resolvePath(t.Context(), "/a/b/c/file.txt")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if inode.ID == "" {
		t.Error("Empty ID")
	}

	_, _, err = adminClient.resolvePath(t.Context(), "/missing")
	if err == nil {
		t.Error("Expected error")
	}
}
