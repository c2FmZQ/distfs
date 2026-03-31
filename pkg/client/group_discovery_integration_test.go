//go:build !wasm

package client

import (
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestGroupDiscovery(t *testing.T) {
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

	// Login Bob
	serverPK, _ := clientAlice.getServerKey(t.Context())
	clientBob := NewClient(clientAlice.serverURL()).
		withIdentity(bobID, bobDK).
		withSignKey(bobSign).
		withServerKey(serverPK).
		WithRegistry("/registry")

	if err := clientBob.Login(t.Context()); err != nil {
		t.Fatalf("Bob login failed: %v", err)
	}

	// 3. Alice creates a group and adds Bob
	group, err := clientAlice.createGroup(t.Context(), "discovery-test", false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	err = clientAlice.AddUserToGroup(t.Context(), group.ID, bobID, "Bob", nil)
	if err != nil {
		t.Fatalf("AddUserToGroup Bob failed: %v", err)
	}

	// 4. Bob discovers his groups
	found := false
	for entry, err := range clientBob.ListGroups(t.Context()) {
		if err != nil {
			t.Fatalf("ListGroups failed: %v", err)
		}
		if entry.ID == group.ID {
			found = true
		}
	}

	if !found {
		t.Errorf("Group %s not found in Bob's list", group.ID)
	}
}
