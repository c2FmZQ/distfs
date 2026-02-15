// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

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
	user := User{ID: userID}
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
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(userID))
		var u User
		json.Unmarshal(v, &u)
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
	inodeBytes1, _ := json.Marshal(inode1)
	resp := fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: inodeBytes1}.Marshal()})
	if err, ok := resp.(error); ok {
		t.Fatalf("First inode should succeed, got %v", err)
	}

	inode2 := Inode{ID: "i2", OwnerID: userID, Type: FileType, Size: 10}
	inodeBytes2, _ := json.Marshal(inode2)
	resp = fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: inodeBytes2}.Marshal()})
	if _, ok := resp.(error); !ok {
		t.Fatal("Expected quota error for 2nd inode")
	}

	// Try creating large inode (should fail quota)
	inode3 := Inode{ID: "i3", OwnerID: userID, Type: FileType, Size: 200}
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

	inode := Inode{
		ID:   "f1",
		Type: FileType,
		ChunkManifest: []ChunkEntry{
			{ID: "c1", Nodes: []string{"n1"}},
		},
	}
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
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte("f1"))
		var i Inode
		json.Unmarshal(v, &i)
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

func TestFSM_Rename(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Create structure: /dir1, /dir1/f1
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: []byte(`{"id":"root","type":1,"children":{}}`)}.Marshal()})
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: []byte(`{"id":"d1","parent_id":"root","type":1,"children":{}}`)}.Marshal()})
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAddChild, Data: []byte(`{"parent_id":"root","name":"dir1","child_id":"d1"}`)}.Marshal()})

	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: []byte(`{"id":"f1","parent_id":"d1","type":0}`)}.Marshal()})
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAddChild, Data: []byte(`{"parent_id":"d1","name":"file1","child_id":"f1"}`)}.Marshal()})

	// 2. Rename /dir1/file1 to /file1-moved
	req := RenameRequest{
		OldParentID: "d1",
		OldName:     "file1",
		NewParentID: "root",
		NewName:     "file1-moved",
	}
	reqBytes, _ := json.Marshal(req)
	resp := fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdRename, Data: reqBytes}.Marshal()})
	if err, ok := resp.(error); ok {
		t.Fatalf("Rename failed: %v", err)
	}

	// 3. Verify
	err := fsm.db.View(func(tx *bolt.Tx) error {
		inodes := tx.Bucket([]byte("inodes"))
		// Old parent should not have it
		var d1 Inode
		json.Unmarshal(inodes.Get([]byte("d1")), &d1)
		if _, ok := d1.Children["file1"]; ok {
			return fmt.Errorf("file1 still in d1")
		}

		// New parent should have it
		var root Inode
		json.Unmarshal(inodes.Get([]byte("root")), &root)
		if id, ok := root.Children["file1-moved"]; !ok || id != "f1" {
			return fmt.Errorf("file1-moved not in root or wrong ID")
		}

		// Inode links should be updated

		var f1 Inode

		json.Unmarshal(inodes.Get([]byte("f1")), &f1)

		if f1.Links == nil || !f1.Links["root:file1-moved"] {

			return fmt.Errorf("f1 links not updated correctly: %+v", f1.Links)

		}

		return nil

	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_SetAttr(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: []byte(`{"id":"f1","type":0,"mode":420}`)}.Marshal()})

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

func TestFSM_Link(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Create file f1
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: []byte(`{"id":"f1","type":0,"nlink":1}`)}.Marshal()})

	// 2. Create link f1-link -> f1 in root
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: []byte(`{"id":"root","type":1,"children":{}}`)}.Marshal()})
	req := LinkRequest{
		ParentID: "root",
		Name:     "f1-link",
		TargetID: "f1",
	}
	reqBytes, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdLink, Data: reqBytes}.Marshal()})

	// 3. Verify
	err := fsm.db.View(func(tx *bolt.Tx) error {
		inodes := tx.Bucket([]byte("inodes"))
		// Target nlink should be 2
		var f1 Inode
		json.Unmarshal(inodes.Get([]byte("f1")), &f1)
		if f1.NLink != 2 {
			return fmt.Errorf("nlink not incremented: %d", f1.NLink)
		}

		// Parent should have child
		var root Inode
		json.Unmarshal(inodes.Get([]byte("root")), &root)
		if id, ok := root.Children["f1-link"]; !ok || id != "f1" {
			return fmt.Errorf("link not in parent")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
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
		b := tx.Bucket([]byte("garbage_collection"))
		return b.Put([]byte("c1"), []byte(`["n1"]`))
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
