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

package metadata

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestRequestBatching(t *testing.T) {
	node, _, _, _, server := setupCluster(t)
	defer node.Shutdown()

	// Wait for leader
	leader := false
	for i := 0; i < 50; i++ {
		if node.Raft.State() == raft.Leader {
			leader = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !leader {
		t.Fatal("Node did not become leader")
	}

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
			user := User{
				ID:      fmt.Sprintf("user-%d", id),
				SignKey: sk.Public(),
				EncKey:  dk.EncapsulationKey().Bytes(),
			}
			body, _ := json.Marshal(user)

			// This should trigger the batching logic in applyRaftCommand
			// Instead of calling applyCommandRaw, we call applyRaftCommand directly to check internal batching
			// But applyCommandRaw is the one calling applyRaftCommand.
			// Let's call a public method that uses it, e.g. handleRegisterUser logic.
			// But we don't have a request object here.
			// Ideally we test applyRaftCommand directly.
			_, err := server.applyRaftCommand(CmdCreateUser, body)
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
		server.fsm.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("users"))
			v := b.Get([]byte(fmt.Sprintf("user-%d", i)))
			if v == nil {
				t.Errorf("User %d not found in FSM", i)
			}
			return nil
		})
	}
}
