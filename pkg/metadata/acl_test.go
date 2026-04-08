//go:build !wasm

package metadata

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestEvaluatePOSIXAccess(t *testing.T) {
	tmpDir := t.TempDir()
	fsm, err := NewMetadataFSM("node1", filepath.Join(tmpDir, "test.db"), []byte("test-cluster-secret-32-bytes-!!"))
	if err != nil {
		t.Fatal(err)
	}
	defer fsm.db.Close()

	setGroup := func(g Group) {
		fsm.db.Update(func(tx *bolt.Tx) error {
			data, _ := json.Marshal(g)
			return fsm.Put(tx, []byte("groups"), []byte(g.ID), data)
		})
	}

	// Simple test to ensure evaluatePOSIXAccess is correctly wired
	inode := &Inode{
		OwnerID: "u1",
		GroupID: "g1",
		Mode:    0640,
	}

	// 1. Owner Write (Mode 0600 -> 0002)
	if !evaluatePOSIXAccess(fsm, inode, "u1", 0002) {
		t.Error("owner should have write access")
	}

	// 2. Owner Read (Mode 0600 -> 0004)
	if !evaluatePOSIXAccess(fsm, inode, "u1", 0004) {
		t.Error("owner should have read access")
	}

	// 3. Group Read (Mode 0040 -> 0004)
	setGroup(Group{
		ID:      "g1",
		SignKey: []byte("test-key"),
		Lockbox: map[string]crypto.LockboxEntry{
			ComputeMemberHMAC("g1", "u2"): {},
		},
	})
	if !evaluatePOSIXAccess(fsm, inode, "u2", 0004) {
		t.Error("group member should have read access")
	}

	// 4. Group Write (Mode 0040 -> no write)
	if evaluatePOSIXAccess(fsm, inode, "u2", 0002) {
		t.Error("group should NOT have write access")
	}

	// 5. Other Read (Mode 0000)
	if evaluatePOSIXAccess(fsm, inode, "u3", 0004) {
		t.Error("other should NOT have read access")
	}

	// 6. Named User Access
	inode.AccessACL = &POSIXAccess{
		Users: map[string]uint32{
			"u3": 0004,
		},
	}
	if !evaluatePOSIXAccess(fsm, inode, "u3", 0004) {
		t.Error("named user should have read access")
	}

	// 7. Named Group Access
	setGroup(Group{
		ID:      "g2",
		SignKey: []byte("test-key-2"),
		Lockbox: map[string]crypto.LockboxEntry{
			ComputeMemberHMAC("g2", "u4"): {},
		},
	})
	inode.AccessACL.Groups = map[string]uint32{
		"g2": 0004,
	}
	if !evaluatePOSIXAccess(fsm, inode, "u4", 0004) {
		t.Error("named group member should have read access")
	}
}
