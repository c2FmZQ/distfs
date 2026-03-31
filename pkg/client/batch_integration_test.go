//go:build !wasm

package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	bolt "go.etcd.io/bbolt"
)

func TestRequestBatching(t *testing.T) {
	tc := metadata.SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()

	// Wait for leader
	metadata.WaitLeader(t, tc.Node.Raft)

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

			metadata.CreateUser(t, tc.Node, user, sk, tc.AdminID, tc.AdminSK)
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
		tc.Server.FSM().DB().View(func(tx *bolt.Tx) error {
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
	tc := metadata.SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	metadata.WaitLeader(t, tc.Node.Raft)

	// Use Admin Client for testing memoization (Phase 69 compliance)
	c, err := NewClient(tc.TS.URL).WithRegistry("").
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithServerKeyBytes(tc.EpochEK)
	if err != nil {
		t.Fatal(err)
	}
	c = c.WithAdmin(true)

	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if err := c.BootstrapFileSystem(t.Context()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	if err := c.Mkdir(t.Context(), "/m1", 0755); err != nil {
		t.Fatalf("First Mkdir failed: %v", err)
	}

	if tc.Server.SessionKeyCacheSize() != 1 {
		t.Errorf("Expected 1 session key in cache, got %d", tc.Server.SessionKeyCacheSize())
	}

	if err := c.Mkdir(t.Context(), "/m2", 0755); err != nil {
		t.Fatalf("Second Mkdir failed: %v", err)
	}
}

func TestBatchAtomicity(t *testing.T) {
	tc := metadata.SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()

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
	metadata.CreateUser(t, tc.Node, user, sk, tc.AdminID, tc.AdminSK)

	// Prepare a batch:
	// 1. Create Inode 0000000000000000000000000000000f (Valid)
	// 2. Create Inode 00000000000000000000000000000002f (Should FAIL due to quota)

	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := metadata.GenerateInodeID(u1, nonce1)
	i1 := metadata.Inode{ID: id1, Nonce: nonce1, OwnerID: u1, Type: metadata.FileType, Mode: 0644}
	i1.SignInodeForTest(u1, sk)
	i1Bytes, _ := json.Marshal(i1)

	nonce2 := make([]byte, 16)
	rand.Read(nonce2)
	id2 := metadata.GenerateInodeID(u1, nonce2)
	i2 := metadata.Inode{ID: id2, Nonce: nonce2, OwnerID: u1, Type: metadata.FileType, Mode: 0644}
	i2.SignInodeForTest(u1, sk)
	i2Bytes, _ := json.Marshal(i2)

	batch := []metadata.LogCommand{
		{Type: metadata.CmdCreateInode, Data: i1Bytes},
		{Type: metadata.CmdCreateInode, Data: i2Bytes},
	}
	batchBytes, _ := json.Marshal(batch)

	// Apply batch - Atomic should be true for individual user batches
	_, err := tc.Server.ApplyRaftCommandInternal(context.Background(), metadata.CmdBatch, batchBytes, u1)
	if err != nil && !errors.Is(err, metadata.ErrAtomicRollback) {
		t.Fatalf("Raft apply failed: %v", err)
	}

	// Verify 0000000000000000000000000000000f was NOT created (atomicity check)
	tc.Server.FSM().DB().View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		if b.Get([]byte(id1)) != nil {
			t.Errorf("Inode 1 was created despite batch failure")
		}
		if b.Get([]byte(id2)) != nil {
			t.Errorf("Inode 2 was created despite batch failure")
		}
		return nil
	})
}
