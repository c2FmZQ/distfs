// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestKeyRotation(t *testing.T) {
	tmpDir := t.TempDir()
	key := make([]byte, 32) // Generation 1 key

	// 1. Start Node
	node, err := NewRaftNode("node1", "127.0.0.1:0", tmpDir, key)
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
	// The FSM.Snapshot() is called during the snapshot process.
	// We sleep to ensure persistence.
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
	// This verifies:
	// - Can load Snapshot (encrypted with old keys? No, snapshots are plain BoltDB backup? Wait.)
	//   FSM Snapshot is `MetadataSnapshot`, which writes raw BoltDB.
	//   The Snapshot FILE stored by Raft is encrypted by `EncryptedLogStore`?
	//   No, `EncryptedLogStore` only encrypts LOGS.
	//   `SnapshotStore` is standard `FileSnapshotStore`.
	//   Wait! If snapshots are plaintext, then key rotation only protects TRAILING logs.
	//   The Plan says "Implement Log Key Rotation on Snapshot".
	//   It doesn't explicitly say Snapshots must be encrypted (though `skorekeeper` might have).
	//   However, if I restart, I replay logs.
	//   The logs on disk are encrypted. I need to be able to decrypt them.
	//   Logs from BEFORE snapshot 1 are compacted.
	//   Logs AFTER snapshot 2 (Log 3) are present.
	//   Log 3 is encrypted with Gen 3 key.
	
	// We need to ensure the KeyRing was persisted.
	node.Shutdown()

	// 8. Recover
	node2, err := NewRaftNode("node1", string(node.Transport.LocalAddr()), tmpDir, key)
	if err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	defer node2.Shutdown()

	// Wait for restore
	time.Sleep(2 * time.Second)

	// 9. Verify State
	// We should see ALL inodes (1 from snap1, 2 from snap2, 3 from log replay)
	// Actually snapshots contain accumulated state.
	// Snap 2 contains inode-1 and inode-2.
	// Log replay adds inode-3.
	
	err = node2.FSM.db.View(func(tx *bolt.Tx) error { // bolt imported in test file? need import
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
