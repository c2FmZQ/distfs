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

			_, err := server.ApplyRaftCommand(metadata.CmdCreateUser, body)
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

	if err := c.Login(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if err := c.Mkdir("/m1"); err != nil {
		t.Fatalf("First Mkdir failed: %v", err)
	}

	if server.SessionKeyCacheSize() != 1 {
		t.Errorf("Expected 1 session key in cache, got %d", server.SessionKeyCacheSize())
	}

	if err := c.Mkdir("/m2"); err != nil {
		t.Fatalf("Second Mkdir failed: %v", err)
	}
}
