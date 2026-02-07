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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestClientIntegration(t *testing.T) {
	// 1. Setup Metadata Node
	metaDir := t.TempDir()
	metaKey := make([]byte, 32)
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", metaDir, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	// Bootstrap
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})

	// Wait for leader
	time.Sleep(2 * time.Second)

	metaServer := metadata.NewServer(metaNode.Raft, metaNode.FSM, "", nil)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()

	// 2. Setup Data Node
	dataDir := t.TempDir()
	dataStore, err := data.NewDiskStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	dataServer := data.NewServer(dataStore)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// 3. Client
	c := NewClient(tsMeta.URL, tsData.URL)

	// 4. Write File (Raw)
	content := []byte("hello distributed filesystem world")
	fileID := "file-1"
	key, err := c.WriteFile(fileID, content)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 5. Read File (Raw)
	readBack, err := c.ReadFile(fileID, key)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(readBack) != string(content) {
		t.Errorf("Content mismatch: got %s, want %s", readBack, content)
	}

	// 6. FS Integration (With Identity)
	dk, _ := crypto.GenerateEncryptionKey()
	c = c.WithIdentity("user-1", dk)

	if err := c.EnsureRoot(); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	fileName := "/file-2.txt"
	if err := c.CreateFile(fileName, content); err != nil {
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
	metaKey := make([]byte, 32)
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", metaDir, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})

	time.Sleep(2 * time.Second)

	metaServer := metadata.NewServer(metaNode.Raft, metaNode.FSM, "", nil)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()

	// 2. Three Data Nodes
	nodes := make([]*httptest.Server, 3)
	stores := make([]data.Store, 3)
	for i := 0; i < 3; i++ {
		dir := t.TempDir()
		store, _ := data.NewDiskStore(dir)
		stores[i] = store
		server := data.NewServer(store)
		ts := httptest.NewServer(server)
		nodes[i] = ts
		defer ts.Close()

		// Register with Metadata
		node := metadata.Node{
			ID:      fmt.Sprintf("data-%d", i),
			Address: ts.URL,
			Status:  metadata.NodeStatusActive,
		}
		body, _ := json.Marshal(node)
		http.Post(tsMeta.URL+"/v1/node", "application/json", bytes.NewReader(body))
	}

	// 3. Client
	c := NewClient(tsMeta.URL, nodes[0].URL)

	// 4. Write
	content := []byte("replicated data")
	_, err = c.WriteFile("repl-file", content)
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
	metaKey := make([]byte, 32)
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", metaDir, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	time.Sleep(2 * time.Second)

	metaServer := metadata.NewServer(metaNode.Raft, metaNode.FSM, "", nil)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()

	dataDir := t.TempDir()
	dataStore, _ := data.NewDiskStore(dataDir)
	dataServer := data.NewServer(dataStore)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	node := metadata.Node{
		ID:      "data-1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	body, _ := json.Marshal(node)
	http.Post(tsMeta.URL+"/v1/node", "application/json", bytes.NewReader(body))

	c := NewClient(tsMeta.URL, tsData.URL)
	
	// Identity needed for Lockbox (Mkdir uses writeInodeContent which uses Lockbox)
	dk, _ := crypto.GenerateEncryptionKey()
	c = c.WithIdentity("user-1", dk)

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
	if err := c.CreateFile("/a/b/f.txt", content); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// Resolve
	inode, key, err := c.ResolvePath("/a/b/f.txt")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	// Read
	readBack, err := c.ReadFile(inode.ID, key)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(readBack) != string(content) {
		t.Errorf("Content mismatch")
	}
}
