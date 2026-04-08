//go:build !wasm

package client

import (
	"sync"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestGroupUpdateConcurrency(t *testing.T) {
	tc := metadata.SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Setup Alice (using existing Admin from SetupCluster)
	clientAlice, err := NewClient(tc.TS.URL).
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithServerKeyBytes(tc.EpochEK)
	if err != nil {
		t.Fatal(err)
	}
	clientAlice = clientAlice.WithAdmin(true).
		WithRegistry("") // Disable registry for pure metadata test

	if err := clientAlice.Login(t.Context()); err != nil {
		t.Fatalf("Alice login failed: %v", err)
	}

	// Prepare dummy users for adding
	for _, id := range []string{"user1", "user2"} {
		sk, _ := crypto.GenerateIdentityKey()
		dk, _ := crypto.GenerateEncryptionKey()
		u := metadata.User{ID: id, SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes()}
		metadata.CreateUser(t, tc.Node, u, sk, tc.AdminID, tc.AdminSK)
	}

	// 2. Alice creates a group
	group, err := clientAlice.createGroup(t.Context(), "race-test", false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// 3. Attempt concurrent additions
	var wg sync.WaitGroup
	wg.Add(2)

	err1Ch := make(chan error, 1)
	err2Ch := make(chan error, 1)

	go func() {
		defer wg.Done()
		err1Ch <- clientAlice.AddUserToGroup(t.Context(), group.ID, "user1", "User 1 Info", nil)
	}()

	go func() {
		defer wg.Done()
		err2Ch <- clientAlice.AddUserToGroup(t.Context(), group.ID, "user2", "User 2 Info", nil)
	}()

	wg.Wait()

	if err := <-err1Ch; err != nil {
		t.Errorf("Add user1 failed: %v", err)
	}
	if err := <-err2Ch; err != nil {
		t.Errorf("Add user2 failed: %v", err)
	}

	// 4. Verify BOTH users are present
	finalGroup, err := clientAlice.getGroup(t.Context(), group.ID)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}

	target1 := clientAlice.computeMemberHMAC(finalGroup.ID, "user1")
	if _, ok := finalGroup.Lockbox[target1]; !ok {
		t.Errorf("user1 missing from group members")
	}
	target2 := clientAlice.computeMemberHMAC(finalGroup.ID, "user2")
	if _, ok := finalGroup.Lockbox[target2]; !ok {
		t.Errorf("user2 missing from group members")
	}

	// Verify Registry (Fix #2 ensures merge)
	found1, found2 := false, false
	members, err := clientAlice.AdminGetGroupMembersList(t.Context(), group.ID)
	if err != nil {
		t.Fatalf("GetGroupMembers failed: %v", err)
	}
	for _, m := range members {
		if m.UserID == "user1" {
			found1 = true
		}
		if m.UserID == "user2" {
			found2 = true
		}
	}
	if !found1 {
		t.Errorf("user1 missing from registry")
	}
	if !found2 {
		t.Errorf("user2 missing from registry")
	}
}
