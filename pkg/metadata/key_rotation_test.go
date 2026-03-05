// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestFSMKeyRotation(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: "u1", UID: 1001, SignKey: sk.Public()})

	// 1. Create Inode (Gen 1)
	inode := Inode{ID: "0000000000000000000000000000000f", Type: FileType, OwnerID: "u1"}
	inode.SignInodeForTest("u1", sk)
	iBytes, _ := json.Marshal(inode)
	if _, err := server.ApplyRaftCommandInternal(CmdCreateInode, iBytes, "u1"); err != nil {
		t.Fatalf("Create Inode Gen 1 failed: %v", err)
	}

	// 2. Rotate FSM Key (To Gen 2)
	err := server.RotateFSMKey()
	if err != nil {
		t.Fatal(err)
	}

	// 3. Create Inode (Gen 2)
	inode2 := Inode{ID: "0000000000000000000000000000002f", Type: FileType, OwnerID: "u1"}
	inode2.SignInodeForTest("u1", sk)
	iBytes2, _ := json.Marshal(inode2)
	if _, err := server.ApplyRaftCommandInternal(CmdCreateInode, iBytes2, "u1"); err != nil {
		t.Fatalf("Create Inode Gen 2 failed: %v", err)
	}

	// 4. Verify decryption of both
	err = server.FSM().DB().View(func(tx *bolt.Tx) error {
		v1, _ := server.FSM().Get(tx, []byte("inodes"), []byte("0000000000000000000000000000000f"))
		if v1 == nil {
			t.Error("0000000000000000000000000000000f missing")
		}
		v2, _ := server.FSM().Get(tx, []byte("inodes"), []byte("0000000000000000000000000000002f"))
		if v2 == nil {
			t.Error("0000000000000000000000000000002f missing")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}

	// 5. Force Re-encryption
	server.keyWorker.reencryptSlowly()
	// Wait for async Raft apply
	time.Sleep(500 * time.Millisecond)

	// 6. Verify 0000000000000000000000000000000f is now Gen 2 in raw storage
	server.FSM().DB().View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v1 := b.Get([]byte("0000000000000000000000000000000f"))
		if binary.BigEndian.Uint32(v1[:4]) != 2 {
			t.Errorf("0000000000000000000000000000000f not re-encrypted: gen %d", binary.BigEndian.Uint32(v1[:4]))
		}
		return nil
	})
}

func TestFSMKeyRingSync(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// 1. Rotate a few times
	server.RotateFSMKey()
	server.RotateFSMKey()
	_, gen := server.FSM().KeyRing().Current()
	if gen < 3 {
		t.Errorf("Expected gen >= 3, got %d", gen)
	}

	// 2. Take Snapshot
	if err := node.Raft.Snapshot().Error(); err != nil {
		t.Fatal(err)
	}

	// 3. New Node Joins
	tmpDir2 := t.TempDir()
	mk2, _ := storage_crypto.CreateAESMasterKeyForTest()
	st2 := storage.New(tmpDir2, mk2)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	nodeKey2 := &NodeKey{Pub: pub2, Signer: priv2}
	nodeID2 := NodeIDFromKey(nodeKey2)

	node2, err := NewRaftNode(nodeID2, "127.0.0.1:0", "", tmpDir2, st2, nodeKey2, []byte("test-cluster-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer node2.Shutdown()

	// Add to cluster
	f := node.Raft.AddVoter(raft.ServerID(nodeID2), node2.Transport.LocalAddr(), 0, 0)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}

	// 4. Wait for Restore on node2
	time.Sleep(2 * time.Second)

	// 5. Verify node2 has matching KeyRing
	_, gen2 := node2.FSM.KeyRing().Current()
	if gen2 != gen {
		t.Errorf("Node 2 KeyRing generation mismatch: expected %d, got %d", gen, gen2)
	}

	// Verify it can decrypt data from gen 1
}

func TestKeyRotation(t *testing.T) {
	tmpDir := t.TempDir()

	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(tmpDir, mk)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nodeKey := &NodeKey{Pub: pub, Signer: priv}

	// 1. Start Node
	node, err := NewRaftNode("node1", "127.0.0.1:0", "", tmpDir, st, nodeKey, []byte("test-cluster-secret"))
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

	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: "u1", UID: 1001, SignKey: sk.Public()})

	// 2. Apply Log 1 (Gen 1)
	inode1 := Inode{ID: "inode-1", Type: FileType, OwnerID: "u1"}
	inode1.SignInodeForTest("u1", sk)
	data1, _ := json.Marshal(inode1)
	cmd1 := LogCommand{Type: CmdCreateInode, Data: data1, UserID: "u1"}
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
	inode2 := Inode{ID: "inode-2", Type: FileType, OwnerID: "u1"}
	inode2.SignInodeForTest("u1", sk)
	data2, _ := json.Marshal(inode2)
	cmd2 := LogCommand{Type: CmdCreateInode, Data: data2, UserID: "u1"}
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
	inode3 := Inode{ID: "inode-3", Type: FileType, OwnerID: "u1"}
	inode3.SignInodeForTest("u1", sk)
	data3, _ := json.Marshal(inode3)
	cmd3 := LogCommand{Type: CmdCreateInode, Data: data3, UserID: "u1"}
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

	node2, err := NewRaftNode("node1", string(node.Transport.LocalAddr()), "", tmpDir, st, nodeKey, []byte("test-cluster-secret"))
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
