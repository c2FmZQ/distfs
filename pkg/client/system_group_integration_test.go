//go:build !wasm

package client

import (
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestSystemGroups(t *testing.T) {
	// 1. Setup Admin Client (Alice) using setupTestClient
	clientAdmin, node, _, _, adminID, adminSK := setupTestClient(t)

	// 2. Setup Non-Admin Client (Eve)
	eveSign, _ := crypto.GenerateIdentityKey()
	eveDK, _ := crypto.GenerateEncryptionKey()
	eveID := "eve"
	eve := metadata.User{ID: eveID, SignKey: eveSign.Public(), EncKey: eveDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, eve, eveSign, adminID, adminSK)

	// Anchor Eve in registry
	if err := clientAdmin.AnchorUserInRegistry(t.Context(), "eve", eve.ID, adminID); err != nil {
		t.Fatalf("AnchorUserInRegistry Eve failed: %v", err)
	}

	serverPK, err := clientAdmin.getServerKey(t.Context())
	if err != nil {
		t.Fatalf("Failed to get server key: %v", err)
	}
	clientEve := NewClient(clientAdmin.serverURL()).
		withIdentity(eveID, eveDK).
		withSignKey(eveSign).
		withServerKey(serverPK).
		WithRegistry("/registry")

	if err := clientEve.Login(t.Context()); err != nil {
		t.Fatalf("Eve login failed: %v", err)
	}

	// 3. Eve (non-admin) should NOT be able to create a system group
	if _, err := clientEve.createSystemGroup(t.Context(), "sys-eve", true); err == nil {
		t.Error("Eve (non-admin) should NOT be able to create a system group")
	}

	// 4. Alice (admin) should be able to create a system group
	group, err := clientAdmin.createSystemGroup(t.Context(), "sys-alice", true)
	if err != nil {
		t.Fatalf("Alice (admin) failed to create system group: %v", err)
	}

	if !group.IsSystem {
		t.Error("Expected group to be marked as system")
	}
}
