// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func createTestFSM(t *testing.T) *MetadataFSM {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)
	fsm, err := NewMetadataFSM(filepath.Join(tmpDir, "fsm.bolt"), st)
	if err != nil {
		t.Fatal(err)
	}
	return fsm
}

func TestFSM_Quota(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	userID := "u1"
	sk, _ := crypto.GenerateIdentityKey()
	user := User{ID: userID, SignKey: sk.Public()}
	userBytes, _ := json.Marshal(user)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateUser, Data: userBytes}.Marshal()})

	// Set Quota
	maxInodes := int64(1)
	maxBytes := int64(100)
	req := SetUserQuotaRequest{
		UserID:    userID,
		MaxInodes: &maxInodes,
		MaxBytes:  &maxBytes,
	}
	quotaBytes, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdSetUserQuota, Data: quotaBytes}.Marshal()})

	// Verify Quota Set
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("users"), []byte(userID))
		if err != nil {
			return err
		}
		var u User
		json.Unmarshal(plain, &u)
		if u.Quota.MaxInodes != 1 || u.Quota.MaxBytes != 100 {
			return fmt.Errorf("quota not set correctly: %+v", u.Quota)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try creating 2nd inode (should fail quota)
	inode1 := Inode{ID: "i1", OwnerID: userID, Type: FileType, Size: 10}
	inode1.SignInodeForTest(userID, sk)
	inodeBytes1, _ := json.Marshal(inode1)
	resp := fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: inodeBytes1}.Marshal()})
	if err, ok := resp.(error); ok {
		t.Fatalf("First inode should succeed, got %v", err)
	}

	inode2 := Inode{ID: "i2", OwnerID: userID, Type: FileType, Size: 10}
	inode2.SignInodeForTest(userID, sk)
	inodeBytes2, _ := json.Marshal(inode2)
	resp = fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: inodeBytes2}.Marshal()})
	if _, ok := resp.(error); !ok {
		t.Fatal("Expected quota error for 2nd inode")
	}

	// Try creating large inode (should fail quota)
	inode3 := Inode{ID: "i3", OwnerID: userID, Type: FileType, Size: 200}
	inode3.SignInodeForTest(userID, sk)
	inodeBytes3, _ := json.Marshal(inode3)
	// We need to delete i1 first to have inode slot
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdDeleteInode, Data: []byte("i1")}.Marshal()})
	resp = fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: inodeBytes3}.Marshal()})
	if _, ok := resp.(error); !ok {
		t.Fatal("Expected quota error for large inode")
	}
}

func TestFSM_Replication(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	sk, _ := crypto.GenerateIdentityKey()
	userID := "u1"

	inode := Inode{
		ID:      "f1",
		Type:    FileType,
		OwnerID: userID,
		ChunkManifest: []ChunkEntry{
			{ID: "c1", Nodes: []string{"n1"}},
		},
	}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: inodeBytes}.Marshal()})

	// Add Replica
	req := AddReplicaRequest{
		InodeID: "f1",
		ChunkID: "c1",
		NodeIDs: []string{"n2"},
	}
	reqBytes, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAddChunkReplica, Data: reqBytes}.Marshal()})

	// Verify
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("inodes"), []byte("f1"))
		if err != nil {
			return err
		}
		var i Inode
		json.Unmarshal(plain, &i)
		// We need to load pages too if it was paginated, but here it's small.
		// Actually fsm.Apply(CmdCreateInode) calls saveInodeWithPages which might move it to pages if it's large.
		// For 1 chunk it stays in Inode.
		if len(i.ChunkManifest) != 1 || len(i.ChunkManifest[0].Nodes) != 2 {
			return fmt.Errorf("nodes not updated: %v", i.ChunkManifest[0].Nodes)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFSM_SetAttr(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	sk, _ := crypto.GenerateIdentityKey()
	userID := "u1"
	inode := Inode{ID: "f1", Type: FileType, Mode: 420, OwnerID: userID}
	inode.SignInodeForTest(userID, sk)
	b, _ := json.Marshal(inode)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: b}.Marshal()})

	mode := uint32(0777)
	size := uint64(1234)
	req := SetAttrRequest{
		InodeID: "f1",
		Mode:    &mode,
		Size:    &size,
	}
	reqBytes, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdSetAttr, Data: reqBytes}.Marshal()})
}

func TestFSM_InitSecret(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	secret := []byte("super-secret-cluster-key")
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdInitSecret, Data: secret}.Marshal()})

	// Verify
	s, err := fsm.GetClusterSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(s) != string(secret) {
		t.Errorf("Secret mismatch: got %s, want %s", s, secret)
	}

	// Try re-init (should fail)
	resp := fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdInitSecret, Data: []byte("new")}.Marshal()})
	if _, ok := resp.(error); !ok {
		t.Fatal("Expected error on re-init")
	}
}

func TestFSM_GCRemove(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Manually put something in GC bucket
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		return fsm.Put(tx, []byte("garbage_collection"), []byte("c1"), []byte(`["n1"]`))
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Remove it via command
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdGCRemove, Data: []byte("c1")}.Marshal()})

	// 3. Verify gone
	err = fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("garbage_collection"))
		if b.Get([]byte("c1")) != nil {
			return fmt.Errorf("c1 still in GC")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}
