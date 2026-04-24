//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"encoding/json"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestFSM_OwnerDelegationSig_Enforcement(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	adminSK, _ := crypto.GenerateIdentityKey()
	ownerSK, _ := crypto.GenerateIdentityKey()
	signerSK, _ := crypto.GenerateIdentityKey()

	fsm.db.Update(func(tx *bolt.Tx) error {
		// Create admin
		u1 := User{ID: "admin", SignKey: adminSK.Public()}
		fsm.Put(tx, []byte("users"), []byte("admin"), MustMarshalJSON(u1))
		fsm.Put(tx, []byte("admins"), []byte("admin"), []byte("true"))

		// Create Owner
		u2 := User{ID: "owner", SignKey: ownerSK.Public()}
		fsm.Put(tx, []byte("users"), []byte("owner"), MustMarshalJSON(u2))

		// Create Signer (Group Member)
		u3 := User{ID: "signer", SignKey: signerSK.Public()}
		fsm.Put(tx, []byte("users"), []byte("signer"), MustMarshalJSON(u3))
		return nil
	})

	// 1. Create a group owned by the owner
	nonceG1 := GenerateNonce()
	groupSK, _ := crypto.GenerateIdentityKey()
	g1 := Group{
		ID:           "g1",
		GID:          6000,
		OwnerID:      "owner",
		Nonce:        nonceG1,
		Version:      1,
		QuotaEnabled: true,
		SignerID:     "owner",
		SignKey:      groupSK.Public(),
		Lockbox:      crypto.Lockbox{ComputeMemberHMAC("g1", "signer"): {}},
	}
	g1.Signature = ownerSK.Sign(g1.Hash())
	gb1, _ := json.Marshal(g1)
	cmd1, _ := LogCommand{Type: CmdCreateGroup, Data: gb1, UserID: "owner"}.Marshal()
	fsm.Apply(&raft.Log{Data: cmd1})

	// 2. Owner creates an Inode belonging to the group
	id1 := "00000000000000000000000000000001"
	inode := Inode{
		ID:      id1,
		Type:    FileType,
		OwnerID: "owner",
		GroupID: "g1",
		Mode:    0660, // Group Writable
		Version: 1,
	}
	inode.SignInodeForTest("owner", ownerSK)
	ib, _ := json.Marshal(inode)
	cmd2, _ := LogCommand{Type: CmdCreateInode, Data: ib, UserID: "owner"}.Marshal()
	fsm.Apply(&raft.Log{Data: cmd2})

	// 3. Signer (group member) attempts to update the inode WITHOUT OwnerDelegationSig
	// This should FAIL now.
	inode.Version = 2
	inode.Size = 1024
	inode.GroupSignerID = "g1"
	inode.GroupSig = groupSK.Sign(inode.ManifestHash()) // Provide valid GroupSig
	inode.SignInodeForTest("signer", signerSK)
	inode.OwnerDelegationSig = nil // Explicitly nil
	ib2, _ := json.Marshal(inode)
	cmd3, _ := LogCommand{Type: CmdUpdateInode, Data: ib2, UserID: "signer"}.Marshal()
	res := fsm.Apply(&raft.Log{Data: cmd3})
	if !fsm.containsError(res) {
		t.Error("Non-owner update without OwnerDelegationSig should have failed")
	}

	// 4. Signer attempts to update with INVALID OwnerDelegationSig
	inode.OwnerDelegationSig = []byte("invalid-sig")
	inode.SignInodeForTest("signer", signerSK) // Must re-sign because OwnerDelegationSig is in ManifestHash
	ib3, _ := json.Marshal(inode)
	cmd4, _ := LogCommand{Type: CmdUpdateInode, Data: ib3, UserID: "signer"}.Marshal()
	res = fsm.Apply(&raft.Log{Data: cmd4})
	if !fsm.containsError(res) {
		t.Error("Non-owner update with invalid OwnerDelegationSig should have failed")
	}

	// 5. Signer attempts to update with VALID OwnerDelegationSig
	// The Owner must sign the delegation hash
	inode.OwnerDelegationSig = ownerSK.Sign(inode.DelegationHash())
	inode.GroupSig = groupSK.Sign(inode.ManifestHash()) // Re-sign because OwnerDelegationSig changed
	inode.SignInodeForTest("signer", signerSK)          // Re-sign mutation
	ib4, _ := json.Marshal(inode)
	cmd5, _ := LogCommand{Type: CmdUpdateInode, Data: ib4, UserID: "signer"}.Marshal()
	res = fsm.Apply(&raft.Log{Data: cmd5})
	if fsm.containsError(res) {
		t.Errorf("Non-owner update with valid OwnerDelegationSig failed: %v", res)
	}
}
