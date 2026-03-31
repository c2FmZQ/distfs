//go:build !wasm

package client

import (
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestGroupMemberRegistry(t *testing.T) {
	// 1. Setup Alice (Owner) using setupTestClient
	clientAlice, node, _, _, adminID, adminSK := setupTestClient(t)

	// 2. Setup Bob (Member)
	bobSign, _ := crypto.GenerateIdentityKey()
	bobDK, _ := crypto.GenerateEncryptionKey()
	bobID := node.FSM.ComputeUserID("bob")
	bob := metadata.User{ID: bobID, SignKey: bobSign.Public(), EncKey: bobDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, bob, bobSign, adminID, adminSK)

	// Anchor Bob in registry
	if err := clientAlice.AnchorUserInRegistry(t.Context(), "bob", bob.ID, adminID); err != nil {
		t.Fatalf("AnchorUserInRegistry Bob failed: %v", err)
	}

	// 3. Alice creates a group and adds Bob
	group, err := clientAlice.createGroup(t.Context(), "registry-test", false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	err = clientAlice.AddUserToGroup(t.Context(), group.ID, bobID, "Bob the Builder", nil)
	if err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	// 4. Verify Registry Entry
	found := false
	members, err := clientAlice.AdminGetGroupMembersList(t.Context(), group.ID)
	if err != nil {
		t.Fatalf("GetGroupMembers failed: %v", err)
	}
	for _, m := range members {
		if m.UserID == bobID {
			found = true
			if m.Info != "Bob the Builder" {
				t.Errorf("Expected info 'Bob the Builder', got '%s'", m.Info)
			}
		}
	}

	if !found {
		t.Errorf("Bob not found in group member registry")
	}
}
