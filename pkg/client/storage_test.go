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
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

type testData struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

func TestStorageAPI_Leases(t *testing.T) {
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

	serverEK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	userID := "user-storage"
	createUser(t, metaNode, metadata.User{
		ID: userID, SignKey: userSignKey.Public(), EncKey: dk.EncapsulationKey().Bytes(),
	})

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity(userID, dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := c.EnsureRoot(); err != nil {
		t.Fatal(err)
	}

	// 2. Create files
	if err := c.Mkdir("/dir"); err != nil {
		t.Fatal(err)
	}
	f1 := "/dir/f1"
	f2 := "/dir/f2"
	data := testData{Name: "Initial", Value: 100}
	if err := c.SaveDataFile(f1, data); err != nil {
		t.Fatalf("Save f1 failed: %v", err)
	}
	if err := c.SaveDataFile(f2, data); err != nil {
		t.Fatalf("Save f2 failed: %v", err)
	}

	// 3. Test Atomic Acquire
	ids := []string{f1, f2}
	if err := c.AcquireLeases(ctx, ids, 10*time.Second, nil); err != nil {
		t.Fatalf("AcquireLeases failed: %v", err)
	}

	// 4. Test Conflict (Second client)
	c2 := NewClient(tsMeta.URL)
	dk2, _ := crypto.GenerateEncryptionKey()
	sk2, _ := crypto.GenerateIdentityKey()
	createUser(t, metaNode, metadata.User{
		ID: "user-2", SignKey: sk2.Public(), EncKey: dk2.EncapsulationKey().Bytes(),
	})
	c2 = c2.WithIdentity("user-2", dk2).WithSignKey(sk2).WithServerKey(serverEK)
	if err := c2.Login(); err != nil {
		t.Fatal(err)
	}

	err := c2.AcquireLeases(ctx, []string{f1}, 5*time.Second, nil)
	if err == nil {
		t.Error("Expected conflict error for leased file, got nil")
	}

	// 5. Test Release and Re-acquire
	if err := c.ReleaseLeases(ctx, ids); err != nil {
		t.Fatalf("ReleaseLeases failed: %v", err)
	}

	if err := c2.AcquireLeases(ctx, []string{f1}, 5*time.Second, nil); err != nil {
		t.Fatalf("c2 failed to acquire released lease: %v", err)
	}
}

func TestStorageAPI_TransactionalUpdate(t *testing.T) {
	// 1. Setup (reuse setup logic if possible, but keep self-contained for now)
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
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	createUser(t, metaNode, metadata.User{
		ID: "u1", SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes(),
	})

	c := NewClient(tsMeta.URL).WithIdentity("u1", dk).WithSignKey(sk).WithServerKey(serverEK)
	c.Login()
	c.EnsureRoot()

	// 2. Prepare file
	path := "/tx-test.json"
	data := testData{Name: "v1", Value: 1}
	c.SaveDataFile(path, data)

	// 3. Perform Transactional Update
	commit, err := c.OpenForUpdate(path, &data)
	if err != nil {
		t.Fatalf("OpenForUpdate failed: %v", err)
	}

	data.Value = 2
	data.Name = "v2"
	commit(true)

	// 4. Verify result
	var final testData
	if err := c.ReadDataFile(path, &final); err != nil {
		t.Fatal(err)
	}
	if final.Value != 2 || final.Name != "v2" {
		t.Errorf("Transaction result mismatch: %+v", final)
	}

	// 5. Test Abort
	commit2, _ := c.OpenForUpdate(path, &data)
	data.Value = 999
	commit2(false) // Abort

	c.ReadDataFile(path, &final)
	if final.Value != 2 {
		t.Errorf("Abort failed, data was updated to %d", final.Value)
	}
}
