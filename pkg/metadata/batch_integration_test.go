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

package metadata_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	bolt "go.etcd.io/bbolt"
)

func TestRequestBatching(t *testing.T) {
	node, _, _, _, server := metadata.SetupCluster(t)
	defer node.Shutdown()

	// Wait for leader
	metadata.WaitLeader(t, node.Raft)

	// Launch concurrent requests
	const numReqs = 50
	var wg sync.WaitGroup
	errCh := make(chan error, numReqs)

	for i := 0; i < numReqs; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			dk, _ := crypto.GenerateEncryptionKey()
			sk, _ := crypto.GenerateIdentityKey()
			user := metadata.User{
				ID:      fmt.Sprintf("user-%d", id),
				SignKey: sk.Public(),
				EncKey:  dk.EncapsulationKey().Bytes(),
			}
			body, _ := json.Marshal(user)

			_, err := server.ApplyRaftCommandInternal(metadata.CmdCreateUser, body)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Request failed: %v", err)
	}

	// Verify all users created
	for i := 0; i < numReqs; i++ {
		// Read FSM directly
		server.FSM().DB().View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("users"))
			v := b.Get([]byte(fmt.Sprintf("user-%d", i)))
			if v == nil {
				t.Errorf("User %d not found in FSM", i)
			}
			return nil
		})
	}
}

func TestSessionKeyMemoization(t *testing.T) {
	node, _, _, _, server := metadata.SetupCluster(t)
	defer node.Shutdown()
	metadata.WaitLeader(t, node.Raft)

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	userID := "user-mem"
	user := metadata.User{
		ID:      userID,
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	metadata.CreateUser(t, node, user)

	tsMeta := httptest.NewServer(server)
	defer tsMeta.Close()

	c := client.NewClient(tsMeta.URL)
	c = c.WithIdentity(userID, dk)
	c = c.WithSignKey(userSignKey)

	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	if err := c.Mkdir(t.Context(), "/m1"); err != nil {
		t.Fatalf("First Mkdir failed: %v", err)
	}

	if server.SessionKeyCacheSize() != 1 {
		t.Errorf("Expected 1 session key in cache, got %d", server.SessionKeyCacheSize())
	}

	if err := c.Mkdir(t.Context(), "/m2"); err != nil {
		t.Fatalf("Second Mkdir failed: %v", err)
	}
}

func TestBatchAtomicity(t *testing.T) {
	node, _, _, _, server := metadata.SetupCluster(t)
	defer node.Shutdown()
	metadata.WaitLeader(t, node.Raft)

	// Create user
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	u1 := "user-atom"
	user := metadata.User{
		ID:      u1,
		SignKey: sk.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
		Quota:   metadata.UserQuota{MaxInodes: 1}, // Only allow 1 inode
	}
	metadata.CreateUser(t, node, user)

	// Prepare a batch:
	// 1. Create Inode 0000000000000000000000000000000f (Valid)
	// 2. Create Inode 0000000000000000000000000000002f (Should FAIL due to quota)

	i1 := metadata.Inode{ID: "0000000000000000000000000000000f", OwnerID: u1, Type: metadata.FileType}
	i1.SignInodeForTest(u1, sk)
	i1Bytes, _ := json.Marshal(i1)

	i2 := metadata.Inode{ID: "0000000000000000000000000000002f", OwnerID: u1, Type: metadata.FileType}
	i2.SignInodeForTest(u1, sk)
	i2Bytes, _ := json.Marshal(i2)

	batch := []metadata.LogCommand{
		{Type: metadata.CmdCreateInode, Data: i1Bytes},
		{Type: metadata.CmdCreateInode, Data: i2Bytes},
	}
	batchBytes, _ := json.Marshal(batch)

	// Apply batch
	res, err := server.ApplyRaftCommandInternal(metadata.CmdBatch, batchBytes)
	if err != nil {
		t.Fatalf("Raft apply failed: %v", err)
	}

	// 'res' should be []interface{} containing the results of the two commands.
	results, ok := res.([]interface{})
	if !ok {
		t.Fatalf("Expected []interface{}, got %T", res)
	}

	foundErr := false
	for _, r := range results {
		if e, ok := r.(error); ok && e != nil {
			foundErr = true
			break
		}
	}
	if !foundErr {
		t.Errorf("Expected at least one error in batch results, got %v", results)
	}

	// Verify 0000000000000000000000000000000f was NOT created (atomicity check)
	server.FSM().DB().View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		if b.Get([]byte("0000000000000000000000000000000f")) != nil {
			t.Errorf("Inode 0000000000000000000000000000000f was created despite batch failure")
		}
		if b.Get([]byte("0000000000000000000000000000002f")) != nil {
			t.Errorf("Inode 0000000000000000000000000000002f was created despite batch failure")
		}
		return nil
	})
}
