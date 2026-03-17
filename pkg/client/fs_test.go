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
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestDistFS_ReadDir(t *testing.T) {
	// 1. Setup Cluster
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, []byte("test-cluster-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true)
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
	metadata.CreateUser(t, metaNode, user)

	// Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	node := metadata.Node{
		ID:            "data1",
		Address:       tsData.URL,
		Status:        metadata.NodeStatusActive,
		LastHeartbeat: time.Now().Unix(),
	}
	registerNode(t, tsMeta.URL, "testsecret", node)

	// 2. Client
	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	if _, err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// 3. Create Structure
	// /dir1
	// /dir1/file1
	// /dir1/file2
	c.Mkdir(t.Context(), "/dir1", 0755)
	c.CreateFile(t.Context(), "/dir1/file1", bytes.NewReader([]byte("content")), 7)
	c.CreateFile(t.Context(), "/dir1/file2", bytes.NewReader([]byte("content")), 7)

	// 4. ReadDir
	dfs := c.FS(t.Context())
	entries, err := fs.ReadDir(dfs, "dir1")
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}

	// Verify names
	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name()] = true
		if e.IsDir() {
			t.Error("Expected file, got dir")
		}
	}
	if !names["file1"] || !names["file2"] {
		t.Error("Missing expected files")
	}

	// Test ReadDirFile
	f, _ := dfs.Open("dir1")
	dirFile, ok := f.(fs.ReadDirFile)
	if !ok {
		t.Fatal("Open directory did not return ReadDirFile")
	}
	defer dirFile.Close()

	// Read n
	pEntries, err := dirFile.ReadDir(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pEntries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(pEntries))
	}

	// Read rest
	pEntries2, err := dirFile.ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pEntries2) != 1 {
		t.Errorf("Expected 1 remaining entry, got %d", len(pEntries2))
	}

	// Read EOF
	pEntries3, err := dirFile.ReadDir(-1)
	if err != io.EOF {
		if len(pEntries3) != 0 {
			t.Errorf("Expected EOF or empty, got %d entries, err %v", len(pEntries3), err)
		}
	}
}

func TestReadDirPaginated(t *testing.T) {
	node, ts, serverSignKey, serverEK, srv := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	defer srv.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	userID := "test-user"

	metadata.CreateUser(t, node, metadata.User{
		ID:      userID,
		UID:     1000,
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	})
	token := metadata.LoginSessionForTest(t, ts, userID, userSignKey)

	svKey, _ := crypto.UnmarshalEncapsulationKey(serverEK)
	c := NewClient(ts.URL).
		WithIdentity(userID, dk).
		WithSignKey(userSignKey).
		WithServerKey(svKey)
	c.sessionToken = token
	c.serverSignPK = serverSignKey.Public()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	dirPath := "/paginated_dir"
	c.Mkdir(ctx, dirPath, 0755)

	// Create 250 empty files inline
	for i := 0; i < 250; i++ {
		fileName := fmt.Sprintf("file_%04d.txt", i)
		filePath := dirPath + "/" + fileName
		err := c.CreateFile(ctx, filePath, bytes.NewReader(nil), 0)
		if err != nil {
			t.Fatalf("CreateFile %d failed: %v", i, err)
		}
	}

	page1, total, err := c.ReadDirPaginated(ctx, dirPath, 0, 100)
	if err != nil {
		t.Fatalf("ReadDirPaginated page 1 failed: %v", err)
	}
	if total != 250 {
		t.Fatalf("Expected total 250, got %d", total)
	}
	if len(page1) != 100 {
		t.Fatalf("Expected page 1 len 100, got %d", len(page1))
	}

	page2, total2, err := c.ReadDirPaginated(ctx, dirPath, 100, 100)
	if err != nil {
		t.Fatalf("ReadDirPaginated page 2 failed: %v", err)
	}
	if total2 != 250 {
		t.Fatalf("Expected total 250, got %d", total2)
	}
	if len(page2) != 100 {
		t.Fatalf("Expected page 2 len 100, got %d", len(page2))
	}

	page3, total3, err := c.ReadDirPaginated(ctx, dirPath, 200, 100)
	if err != nil {
		t.Fatalf("ReadDirPaginated page 3 failed: %v", err)
	}
	if total3 != 250 {
		t.Fatalf("Expected total 250, got %d", total3)
	}
	if len(page3) != 50 {
		t.Fatalf("Expected page 3 len 50, got %d", len(page3))
	}

	// Verify all files are present across pages
	allSeen := make(map[string]bool)
	for _, e := range page1 {
		allSeen[e.Name()] = true
	}
	for _, e := range page2 {
		allSeen[e.Name()] = true
	}
	for _, e := range page3 {
		allSeen[e.Name()] = true
	}

	if len(allSeen) != 250 {
		t.Errorf("Expected 250 unique files across pages, got %d", len(allSeen))
	}

	for i := 0; i < 250; i++ {
		name := fmt.Sprintf("file_%04d.txt", i)
		if !allSeen[name] {
			t.Errorf("Missing file %s in paginated results", name)
		}
	}
}
