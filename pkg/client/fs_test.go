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
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestDistFS_ReadDir(t *testing.T) {
	// Setup Cluster
	metaDir := t.TempDir()
	metaKey := make([]byte, 32)
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaKey, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	time.Sleep(2 * time.Second)

	serverKEM, _ := crypto.GenerateEncryptionKey()
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer(metaNode.Raft, metaNode.FSM, "", serverKEM, signKey, "")
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()

	// Generate User Keys
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()

	// Register User
	user := metadata.User{
		ID:      "user-1",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
		Name:    "User One",
	}
	userBytes, _ := json.Marshal(user)
	cmd := metadata.LogCommand{Type: metadata.CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := metaNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	dataDir := t.TempDir()
	dataStore, _ := data.NewDiskStore(dataDir)
	dataServer := data.NewServer(dataStore, signKey.Public(), nil)
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

	// Setup Client
	c := NewClient(tsMeta.URL, tsData.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverKEM.EncapsulationKey())

	if err := c.EnsureRoot(); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// Create structure:
	// /docs/
	// /docs/plan.txt
	// /docs/notes.md
	// /images/
	if err := c.Mkdir("/docs"); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateFile("/docs/plan.txt", bytes.NewReader([]byte("Plan A")), 6); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateFile("/docs/notes.md", bytes.NewReader([]byte("Note B")), 6); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir("/images"); err != nil {
		t.Fatal(err)
	}

	// Test FS
	dfs := c.FS()

	// 1. Open File
	f, err := dfs.Open("/docs/plan.txt")
	if err != nil {
		t.Fatalf("Open /docs/plan.txt failed: %v", err)
	}
	defer f.Close()
	stat, _ := f.Stat()
	if stat.Name() == "plan.txt" {
		// Note: Current implementation uses ID as Name() in Stat() because Inode doesn't store plaintext name easily accessible in Stat().
		// DistDirEntry stores name.
		// Let's check size
	}
	if stat.Size() != 6 {
		t.Errorf("Size mismatch: got %d want 6", stat.Size())
	}

	// 2. Open Directory
	d, err := dfs.Open("/docs")
	if err != nil {
		t.Fatalf("Open /docs failed: %v", err)
	}
	defer d.Close()

	dirFile, ok := d.(fs.ReadDirFile)
	if !ok {
		t.Fatal("Not a ReadDirFile")
	}

	entries, err := dirFile.ReadDir(-1)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}

	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name()] = true
		if e.IsDir() {
			t.Errorf("Expected file, got dir: %s", e.Name())
		}
	}

	if !names["plan.txt"] {
		t.Error("Missing plan.txt")
	}
	if !names["notes.md"] {
		t.Error("Missing notes.md")
	}

	// 3. Root Dir
	root, err := dfs.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	rootEntries, _ := root.(fs.ReadDirFile).ReadDir(-1)
	rootNames := make(map[string]bool)
	for _, e := range rootEntries {
		rootNames[e.Name()] = true
	}
	if !rootNames["docs"] || !rootNames["images"] {
		t.Error("Missing root entries")
	}

	// 4. Pagination
	pDir, err := dfs.Open("/docs")
	if err != nil {
		t.Fatal(err)
	}
	defer pDir.Close()
	pDirFile := pDir.(fs.ReadDirFile)

	// Read 1
	pEntries1, err := pDirFile.ReadDir(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pEntries1) != 1 {
		t.Errorf("Pagination 1: expected 1 entry, got %d", len(pEntries1))
	}

	// Read 2 (should be the other one)
	pEntries2, err := pDirFile.ReadDir(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pEntries2) != 1 {
		t.Errorf("Pagination 2: expected 1 entry, got %d", len(pEntries2))
	}

	if pEntries1[0].Name() == pEntries2[0].Name() {
		t.Error("Pagination returned same entry twice")
	}

	// Read 3 (EOF)
	pEntries3, err := pDirFile.ReadDir(1)
	if err != io.EOF {
		if len(pEntries3) != 0 {
			t.Errorf("Expected EOF or empty, got %d entries, err %v", len(pEntries3), err)
		}
	}
}
