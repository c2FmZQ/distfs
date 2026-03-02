package metadata

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/raft"
)

func TestFSM_StructuralValidation_ImplicitNLink(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	p := Inode{ID: "p1", Type: DirType, Children: make(map[string]string)}
	c := Inode{ID: "c1", Type: FileType}
	pb, _ := json.Marshal(p)
	cb, _ := json.Marshal(c)

	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: pb}.Marshal()})
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: cb}.Marshal()})

	// Add reciprocal link to c1 beforehand
	c.Links = map[string]bool{"p1:child_name": true}
	c.Version = 2
	cb2, _ := json.Marshal(c)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdUpdateInode, Data: cb2}.Marshal()})

	p.Children["child_name"] = "c1"
	p.Version = 2
	p.NLink = 1
	pb2, _ := json.Marshal(p)

	batch := []LogCommand{
		{
			Type: CmdUpdateInode, 
			Data: pb2,
			LeaseBindings: map[string]string{"child_name": "path:p1:child_name"},
		},
	}
	batchBytes, _ := json.Marshal(batch)

	res := fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdBatch, Data: batchBytes, Atomic: true}.Marshal()})
	if !fsm.containsError(res) {
		t.Fatalf("expected batch to fail structural validation due to missing child update, but it succeeded")
	}
}
