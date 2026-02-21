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
	"io"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestSmallFileInlining(t *testing.T) {
	// 1. Setup Cluster
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	defer metaNode.Shutdown()
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	createUser(t, metaNode, metadata.User{
		ID: "user-1", SignKey: userSignKey.Public(), EncKey: dk.EncapsulationKey().Bytes(),
	})

	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()
	registerNode(t, tsMeta.URL, "testsecret", metadata.Node{
		ID: "d1", Address: tsData.URL, Status: metadata.NodeStatusActive,
	})

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity("user-1", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// 2. Write Small File (Inlined)
	smallContent := []byte("small file content")
	if _, err := c.WriteFile(t.Context(), "small-1", bytes.NewReader(smallContent), int64(len(smallContent)), 0644); err != nil {
		t.Fatalf("Write small file failed: %v", err)
	}

	// 3. Verify Inode state
	inode, err := c.GetInode(t.Context(), "small-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(inode.GetInlineData()) == 0 {
		t.Error("Expected InlineData to be set for small file")
	}
	if len(inode.ChunkManifest) != 0 {
		t.Error("Expected ChunkManifest to be empty for inlined file")
	}

	// 4. Read back
	rc, err := c.ReadFile(t.Context(), "small-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	readBack, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(readBack, smallContent) {
		t.Errorf("Read back mismatch: got %s, want %s", readBack, smallContent)
	}

	// 5. Grow file beyond InlineLimit (Eviction)
	largeSize := metadata.InlineLimit + 100
	largeContent := bytes.Repeat([]byte("A"), largeSize)
	if _, err := c.WriteFile(t.Context(), "small-1", bytes.NewReader(largeContent), int64(len(largeContent)), 0644); err != nil {
		t.Fatalf("Grow file failed: %v", err)
	}

	// 6. Verify Eviction
	inode, err = c.GetInode(t.Context(), "small-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(inode.GetInlineData()) > 0 {
		t.Error("Expected InlineData to be cleared after growth")
	}
	if len(inode.ChunkManifest) == 0 {
		t.Error("Expected ChunkManifest to be populated after growth")
	}

	// 7. Read back large
	rc, err = c.ReadFile(t.Context(), "small-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	readBackLarge, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(readBackLarge, largeContent) {
		t.Error("Large read back mismatch")
	}
}
