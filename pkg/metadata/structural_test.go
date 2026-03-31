//go:build !wasm

package metadata

import (
	"encoding/json"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestStructuralInconsistency(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	sk, _ := crypto.GenerateIdentityKey()
	fsm.db.Update(func(tx *bolt.Tx) error {
		u := User{ID: "u1", UID: 1001, SignKey: sk.Public()}
		return fsm.Put(tx, []byte("users"), []byte("u1"), MustMarshalJSON(u))
	})

	p := Inode{ID: "p1", Type: DirType, Children: make(map[string]ChildEntry), OwnerID: "u1"}
	c := Inode{ID: "c1", Type: FileType, OwnerID: "u1"}
	p.SignInodeForTest("u1", sk)
	c.SignInodeForTest("u1", sk)
	pb, _ := json.Marshal(p)
	cb, _ := json.Marshal(c)

	pb1, _ := LogCommand{Type: CmdCreateInode, Data: pb, UserID: "u1"}.Marshal()
	fsm.Apply(&raft.Log{Data: pb1})
	cb1, _ := LogCommand{Type: CmdCreateInode, Data: cb, UserID: "u1"}.Marshal()
	fsm.Apply(&raft.Log{Data: cb1})

	// Add reciprocal link to c1 beforehand
	c.Links = map[string]bool{"p1:child_name": true}
	c.Version = 2
	c.SignInodeForTest("u1", sk)
	cb2, _ := json.Marshal(c)
	cb2b, _ := LogCommand{Type: CmdUpdateInode, Data: cb2, UserID: "u1"}.Marshal()
	fsm.Apply(&raft.Log{Data: cb2b})

	p.Children["child_name"] = ChildEntry{ID: "c1"}
	p.Version = 2
	p.NLink = 1
	p.SignInodeForTest("u1", sk)
	pb2, _ := json.Marshal(p)

	batch := []LogCommand{
		{
			Type:          CmdUpdateInode,
			Data:          pb2,
			LeaseBindings: map[string]string{"child_name": "path:p1:child_name"},
		},
	}
	batchBytes, _ := json.Marshal(batch)

	bb, _ := LogCommand{Type: CmdBatch, Data: batchBytes, Atomic: true, UserID: "u1"}.Marshal()
	res := fsm.Apply(&raft.Log{Data: bb})
	if !fsm.containsError(res) {
		t.Fatalf("expected batch to fail structural validation due to missing child update, but it succeeded")
	}
}
