//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestFSM_ZKPathLeaseEnforcement(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Setup: Create Parent and Child
	parentID := "000000000000000000000000000000a1"
	childID := "000000000000000000000000000000c1"
	childName := "file1"

	// Pre-calculate name HMAC (mocking client-side ZK)
	parentKey := []byte("parent-dir-key-32-bytes-long!!!!")
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(childName))
	nameHMAC := hex.EncodeToString(mac.Sum(nil))

	pathID := fmt.Sprintf("path:%s:%s", parentID, nameHMAC)

	sk, _ := crypto.GenerateIdentityKey()
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		u := User{ID: "u1", SignKey: sk.Public()}
		fsm.Put(tx, []byte("users"), []byte("u1"), MustMarshalJSON(u))

		p := Inode{
			ID:      parentID,
			Type:    DirType,
			Version: 1,
			OwnerID: "u1",
			NLink:   1,
			Links:   map[string]bool{"root:parent": true},
		}
		p.SignInodeForTest("u1", sk)
		pb, _ := json.Marshal(p)
		fsm.executeCreateInode(tx, pb, "u1", time.Now().UnixNano())

		c := Inode{ID: childID, Type: FileType, Version: 1, OwnerID: "u1", NLink: 1}
		c.SignInodeForTest("u1", sk)
		cb, _ := json.Marshal(c)
		fsm.executeCreateInode(tx, cb, "u1", time.Now().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Attempt to add child to parent WITHOUT path lease
	t.Run("AddChildNoLease", func(t *testing.T) {
		err := fsm.db.Update(func(tx *bolt.Tx) error {
			update := Inode{
				ID:       parentID,
				Type:     DirType,
				Version:  2,
				OwnerID:  "u1",
				Children: map[string]ChildEntry{nameHMAC: {ID: childID}},
			}
			update.SignInodeForTest("u1", sk)
			data, _ := json.Marshal(update)
			res := fsm.executeUpdateInode(tx, data, "u1", "session1", nil, time.Now().UnixNano())
			if err, ok := res.(error); !ok || err == nil {
				return fmt.Errorf("expected error for missing path lease, got %v", res)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})

	// 3. Attempt to add child to parent WITH path lease but WRONG session
	t.Run("AddChildWrongSession", func(t *testing.T) {
		err := fsm.db.Update(func(tx *bolt.Tx) error {
			// Acquire lease for session2
			lReq := LeaseRequest{
				InodeIDs:  []string{pathID},
				Duration:  int64(time.Hour),
				SessionID: "session2",
				Type:      LeaseExclusive,
			}
			lb, _ := json.Marshal(lReq)
			resL := fsm.executeAcquireLeases(tx, lb, "session2", "u1", time.Now().UnixNano())
			if err, ok := resL.(error); ok && err != nil {
				return err
			}

			// Update attempt for session1
			update := Inode{
				ID:       parentID,
				Type:     DirType,
				Version:  2,
				OwnerID:  "u1",
				Children: map[string]ChildEntry{nameHMAC: {ID: childID}},
			}
			update.SignInodeForTest("u1", sk)
			data, _ := json.Marshal(update)
			bindings := map[string]string{nameHMAC: pathID}
			res := fsm.executeUpdateInode(tx, data, "u1", "session1", bindings, time.Now().UnixNano())
			if err, ok := res.(error); !ok || err == nil {
				return fmt.Errorf("expected error for wrong session lease, got %v", res)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})

	// 4. Successful Add with correct lease and session
	t.Run("AddChildSuccess", func(t *testing.T) {
		err := fsm.db.Update(func(tx *bolt.Tx) error {
			// First, release session2's lease
			relReq := LeaseRequest{
				InodeIDs:  []string{pathID},
				SessionID: "session2",
			}
			relB, _ := json.Marshal(relReq)
			fsm.executeReleaseLeases(tx, relB, "session2", "u1", time.Now().UnixNano())

			// Acquire lease for session1
			lReq := LeaseRequest{
				InodeIDs:  []string{pathID},
				Duration:  int64(time.Hour),
				SessionID: "session1",
				UserID:    "u1",
				Type:      LeaseExclusive,
			}
			lb, _ := json.Marshal(lReq)
			fsm.executeAcquireLeases(tx, lb, "session1", "u1", time.Now().UnixNano())

			// Prepare Parent Update (adding child)
			pUpdate := Inode{
				ID:       parentID,
				OwnerID:  "u1",
				Type:     DirType,
				Version:  2,
				NLink:    1, // Keep parent link count
				Children: map[string]ChildEntry{nameHMAC: {ID: childID}},
			}
			pUpdate.SignInodeForTest("u1", sk)
			pData, _ := json.Marshal(pUpdate)

			// Prepare Child Update
			cUpdate := Inode{
				ID:      childID,
				Type:    FileType,
				OwnerID: "u1",
				Version: 2,
				NLink:   2,
				Links:   map[string]bool{parentID + ":" + nameHMAC: true},
			}
			cUpdate.SignInodeForTest("u1", sk)
			cData, _ := json.Marshal(cUpdate)

			cmds := []LogCommand{
				{Type: CmdUpdateInode, Data: cData, UserID: "u1", SessionNonce: "session1"},
				{Type: CmdUpdateInode, Data: pData, UserID: "u1", SessionNonce: "session1", LeaseBindings: map[string]string{nameHMAC: pathID}},
			}

			results := fsm.executeBatchCommands(tx, cmds, 0, true)
			if fsm.containsError(results) {
				return fmt.Errorf("batch failed: %v", results)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})

	// 5. Successful Removal with correct lease
	t.Run("RemoveChildSuccess", func(t *testing.T) {
		err := fsm.db.Update(func(tx *bolt.Tx) error {
			// Prepare Parent Update (removing child)
			pUpdate := Inode{
				ID:       parentID,
				OwnerID:  "u1",
				Type:     DirType,
				Version:  3,
				NLink:    1,
				Children: map[string]ChildEntry{},
			}
			pUpdate.SignInodeForTest("u1", sk)
			pData, _ := json.Marshal(pUpdate)

			// Prepare Child Update
			cUpdate := Inode{
				ID:      childID,
				Type:    FileType,
				OwnerID: "u1",
				Version: 3,
				NLink:   1,
				Links:   map[string]bool{},
			}
			cUpdate.SignInodeForTest("u1", sk)
			cData, _ := json.Marshal(cUpdate)

			cmds := []LogCommand{
				{Type: CmdUpdateInode, Data: cData, UserID: "u1", SessionNonce: "session1"},
				{Type: CmdUpdateInode, Data: pData, UserID: "u1", SessionNonce: "session1", LeaseBindings: map[string]string{nameHMAC: pathID}},
			}

			results := fsm.executeBatchCommands(tx, cmds, 0, true)
			if fsm.containsError(results) {
				return fmt.Errorf("batch failed: %v", results)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})
}

func TestFSM_MultiInodeLeases(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	ids := []string{
		"00000000000000000000000000000001",
		"00000000000000000000000000000002",
		"00000000000000000000000000000003",
	}
	sk, _ := crypto.GenerateIdentityKey()

	err := fsm.db.Update(func(tx *bolt.Tx) error {
		u := User{ID: "u1", SignKey: sk.Public()}
		fsm.Put(tx, []byte("users"), []byte("u1"), MustMarshalJSON(u))

		for _, id := range ids {
			inode := Inode{ID: id, Type: FileType, Version: 1, OwnerID: "u1", NLink: 1}
			inode.SignInodeForTest("u1", sk)
			ib, _ := json.Marshal(inode)
			fsm.executeCreateInode(tx, ib, "u1", time.Now().UnixNano())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Acquire multiple shared leases
	t.Run("MultiShared", func(t *testing.T) {
		err := fsm.db.Update(func(tx *bolt.Tx) error {
			req := LeaseRequest{
				InodeIDs:  ids,
				Duration:  int64(time.Hour),
				SessionID: "s1",
				Type:      LeaseShared,
				Nonce:     "n1",
			}
			data, _ := json.Marshal(req)
			res := fsm.executeAcquireLeases(tx, data, req.SessionID, "u1", time.Now().UnixNano())
			if err, ok := res.(error); ok && err != nil {
				return err
			}

			// Verify held
			for _, id := range ids {
				plain, _ := fsm.Get(tx, []byte("inodes"), []byte(id))
				var inode Inode
				json.Unmarshal(plain, &inode)
				if l, ok := inode.Leases["n1"]; !ok || l.Type != LeaseShared {
					return fmt.Errorf("shared lease not held for %s: %+v", id, inode.Leases)
				}
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})

	// 2. Conflict: Exclusive on one of them
	t.Run("ConflictExclusive", func(t *testing.T) {
		err := fsm.db.Update(func(tx *bolt.Tx) error {
			req := LeaseRequest{
				InodeIDs:  []string{ids[1]},
				Duration:  int64(time.Hour),
				SessionID: "s2",
				Type:      LeaseExclusive,
				Nonce:     "n2",
			}
			data, _ := json.Marshal(req)
			res := fsm.executeAcquireLeases(tx, data, req.SessionID, "u1", time.Now().UnixNano())
			if err, ok := res.(error); !ok || err == nil {
				return fmt.Errorf("expected conflict error, got %v", res)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})
}
