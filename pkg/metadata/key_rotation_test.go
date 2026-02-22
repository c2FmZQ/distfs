// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestKeyRotation(t *testing.T) {
	tmpDir := t.TempDir()

	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(tmpDir, mk)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nodeKey := &NodeKey{Pub: pub, Priv: priv}

	// 1. Start Node
	node, err := NewRaftNode("node1", "127.0.0.1:0", "", tmpDir, st, nodeKey)
	if err != nil {
		t.Fatalf("NewRaftNode failed: %v", err)
	}
	defer node.Shutdown()

	node.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "node1", Address: node.Transport.LocalAddr()}},
	})

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

	// 2. Apply Log 1 (Gen 1)
	inode1 := Inode{ID: "inode-1", Type: FileType}
	data1, _ := json.Marshal(inode1)
	cmd1 := LogCommand{Type: CmdCreateInode, Data: data1}
	b1, _ := json.Marshal(cmd1)
	if err := node.Raft.Apply(b1, 5*time.Second).Error(); err != nil {
		t.Fatalf("Apply 1 failed: %v", err)
	}

	// 3. Snapshot -> Triggers Rotation to Gen 2
	if err := node.Raft.Snapshot().Error(); err != nil {
		t.Fatalf("Snapshot 1 failed: %v", err)
	}

	// Wait for snapshot to complete and rotation to happen
	time.Sleep(1 * time.Second)

	// 4. Apply Log 2 (Gen 2)
	inode2 := Inode{ID: "inode-2", Type: FileType}
	data2, _ := json.Marshal(inode2)
	cmd2 := LogCommand{Type: CmdCreateInode, Data: data2}
	b2, _ := json.Marshal(cmd2)
	if err := node.Raft.Apply(b2, 5*time.Second).Error(); err != nil {
		t.Fatalf("Apply 2 failed: %v", err)
	}

	// 5. Snapshot -> Triggers Rotation to Gen 3
	if err := node.Raft.Snapshot().Error(); err != nil {
		t.Fatalf("Snapshot 2 failed: %v", err)
	}
	time.Sleep(1 * time.Second)

	// 6. Apply Log 3 (Gen 3)
	inode3 := Inode{ID: "inode-3", Type: FileType}
	data3, _ := json.Marshal(inode3)
	cmd3 := LogCommand{Type: CmdCreateInode, Data: data3}
	b3, _ := json.Marshal(cmd3)
	if err := node.Raft.Apply(b3, 5*time.Second).Error(); err != nil {
		t.Fatalf("Apply 3 failed: %v", err)
	}

	// 7. Restart Node
	node.Shutdown()

	// 8. Recover
	// Reuse storage instance (simulating persistent storage)
	// Actually we should create a new storage instance with same master key if we want to simulate restart?
	// Storage object is in-memory handle.
	// But files are on disk.
	// We can reuse `st` if it wasn't closed (it doesn't have Close).
	// NewRaftNode takes `st`.

	node2, err := NewRaftNode("node1", string(node.Transport.LocalAddr()), "", tmpDir, st, nodeKey)
	if err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	defer node2.Shutdown()

	// Wait for restore
	time.Sleep(2 * time.Second)

	// 9. Verify State
	err = node2.FSM.db.View(func(tx *bolt.Tx) error { // bolt imported
		b := tx.Bucket([]byte("inodes"))
		if b.Get([]byte("inode-1")) == nil {
			return fmt.Errorf("inode-1 missing (lost during snapshot 1?)")
		}
		if b.Get([]byte("inode-2")) == nil {
			return fmt.Errorf("inode-2 missing (lost during snapshot 2?)")
		}
		if b.Get([]byte("inode-3")) == nil {
			return fmt.Errorf("inode-3 missing (failed to decrypt trailing log?)")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}
