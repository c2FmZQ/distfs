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

func bootstrapClusterFS(t *testing.T, raftNode *metadata.RaftNode) (*mlkem.EncapsulationKey768, []byte) {
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

	return dk.EncapsulationKey(), csk.Public()
}

func TestDistFS_ReadDir(t *testing.T) {
	// 1. Setup Cluster
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
	time.Sleep(2 * time.Second)

	serverEK, metaSignPK := bootstrapClusterFS(t, metaNode)
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
	userBytes, _ := json.Marshal(user)
	cmd := metadata.LogCommand{Type: metadata.CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	if err := metaNode.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Apply user failed: %v", err)
	}

	// Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	node := metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNode(t, tsMeta.URL, "testsecret", node)

	// 2. Client
	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	if err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// 3. Create Structure
	// /dir1
	// /dir1/file1
	// /dir1/file2
	c.Mkdir(t.Context(), "/dir1")
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
