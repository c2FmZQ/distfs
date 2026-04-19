//go:build !wasm

package client

import (
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestNestedGroupAccess(t *testing.T) {
	// Setup Alice (Owner) using setupTestClient
	clientAlice, node, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()
	defer node.Shutdown()

	ctx := t.Context()

	// 1. Create Parent Group (owned by Alice)
	parentGroup, err := clientAlice.createGroup(ctx, "parent-group", false)
	if err != nil {
		t.Fatalf("Create parent group failed: %v", err)
	}

	// 2. Create Child Group (owned by Parent Group)
	childGroup, err := clientAlice.CreateGroupWithOptions(ctx, "child-group", false, parentGroup.ID)
	if err != nil {
		t.Fatalf("Create child group failed: %v", err)
	}

	// 3. Setup Bob and add to the Parent Group
	bobSign, _ := crypto.GenerateIdentityKey()
	bobDK, _ := crypto.GenerateEncryptionKey()
	bobID := node.FSM.ComputeUserID("bob-nested")
	bob := metadata.User{ID: bobID, SignKey: bobSign.Public(), EncKey: bobDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, bob, bobSign, clientAlice.userID, clientAlice.signKey)

	err = clientAlice.AddUserToGroup(ctx, parentGroup.ID, bobID, "Bob", nil)
	if err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	clientBob := NewClient(clientAlice.serverURL()).
		withIdentity(bobID, bobDK).
		withSignKey(bobSign).
		withServerKey(clientAlice.serverKey)

	err = clientBob.Login(ctx)
	if err != nil {
		t.Fatalf("Bob login failed: %v", err)
	}

	// 4. Verify Bob can extract the child group's epoch seed using his membership in the parent group.
	// clientBob will call getGroupEpochSeedFromGroup internally
	cg, err := clientBob.getGroupUnverifiedCached(ctx, childGroup.ID)
	if err != nil {
		t.Fatalf("Bob failed to fetch child group: %v", err)
	}

	seed, err := clientBob.getGroupEpochSeedFromGroup(ctx, cg)
	if err != nil {
		t.Fatalf("Bob failed to get epoch seed via nested group: %v", err)
	}
	if len(seed) != 64 {
		t.Fatalf("Bob seed has invalid length: %d", len(seed))
	}
}

func TestGroupKeyCaching(t *testing.T) {
	// Setup Alice
	clientAlice, node, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()
	defer node.Shutdown()

	ctx := t.Context()

	// Create Group
	group, err := clientAlice.createGroup(ctx, "test-cache-group", false)
	if err != nil {
		t.Fatalf("Create group failed: %v", err)
	}

	// Check if keys are cached with the proper epoch suffix
	cacheKey := groupKeyCacheID{id: group.ID, epoch: 0} // epoch is 0 initially
	clientAlice.keyMu.RLock()
	_, encOk := clientAlice.groupKeys[cacheKey]
	_, signOk := clientAlice.groupSignKeys[cacheKey]
	clientAlice.keyMu.RUnlock()

	if !encOk || !signOk {
		t.Fatalf("Group keys were not cached correctly with epoch suffix. EncKey ok: %v, SignKey ok: %v", encOk, signOk)
	}

	// 3. Test RevokeGroupMember caching
	bobSign, _ := crypto.GenerateIdentityKey()
	bobDK, _ := crypto.GenerateEncryptionKey()
	bobID := node.FSM.ComputeUserID("bob-cache")
	bob := metadata.User{ID: bobID, SignKey: bobSign.Public(), EncKey: bobDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, bob, bobSign, adminID, adminSK)

	err = clientAlice.AddUserToGroup(ctx, group.ID, bobID, "Bob", nil)
	if err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	err = clientAlice.RevokeGroupMember(ctx, group.ID, bobID, nil)
	if err != nil {
		t.Fatalf("RevokeGroupMember failed: %v", err)
	}

	cacheKeyEpoch1 := groupKeyCacheID{id: group.ID, epoch: 1} // epoch is now 1
	clientAlice.keyMu.RLock()
	_, encOk1 := clientAlice.groupKeys[cacheKeyEpoch1]
	_, signOk1 := clientAlice.groupSignKeys[cacheKeyEpoch1]
	clientAlice.keyMu.RUnlock()

	if !encOk1 || !signOk1 {
		t.Fatalf("Group keys were not cached correctly after revocation with epoch suffix. EncKey ok: %v, SignKey ok: %v", encOk1, signOk1)
	}
}
