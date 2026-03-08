package metadata_test

import (
	"testing"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestGroupMemberRegistry(t *testing.T) {
	node, ts, _, serverEK, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setup Alice (Owner) and Bob (Member)
	uAliceSign, _ := crypto.GenerateIdentityKey()
	uAliceDK, _ := crypto.GenerateEncryptionKey()
	uAlice := metadata.User{ID: "alice", SignKey: uAliceSign.Public(), EncKey: uAliceDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uAlice)

	uBobSign, _ := crypto.GenerateIdentityKey()
	uBobDK, _ := crypto.GenerateEncryptionKey()
	uBob := metadata.User{ID: "bob", SignKey: uBobSign.Public(), EncKey: uBobDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uBob)

	// 2. Alice creates Group A
	clientAlice := client.NewClient(ts.URL)
	serverPK, _ := crypto.UnmarshalEncapsulationKey(serverEK)
	clientAlice = clientAlice.WithIdentity("alice", uAliceDK).WithSignKey(uAliceSign).WithServerKey(serverPK)

	if err := clientAlice.Login(t.Context()); err != nil {
		t.Fatalf("Alice login failed: %v", err)
	}

	group, err := clientAlice.CreateGroup(t.Context(), "test-registry", false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	groupID := group.ID

	// 3. Alice adds Bob with info
	err = clientAlice.AddUserToGroup(t.Context(), groupID, "bob", "bob@example.com (Staff)", nil)
	if err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	// 4. Alice (Owner) views members - should see Bob's info
	foundBob := false
	for m, err := range clientAlice.GetGroupMembers(t.Context(), groupID) {
		if err != nil {
			t.Fatalf("GetGroupMembers Alice failed: %v", err)
		}
		if m.UserID == "bob" {
			if m.Info != "bob@example.com (Staff)" {
				t.Errorf("Alice saw wrong info for Bob: %s", m.Info)
			}
			foundBob = true
		}
	}
	if !foundBob {
		t.Error("Alice didn't find Bob in registry")
	}

	// 5. Bob (Member) views members - should NOT see info
	clientBob := client.NewClient(ts.URL)
	clientBob = clientBob.WithIdentity("bob", uBobDK).WithSignKey(uBobSign).WithServerKey(serverPK)

	if err := clientBob.Login(t.Context()); err != nil {
		t.Fatalf("Login Bob failed: %v", err)
	}

	// Unlock Bob
	if err := clientAlice.AdminSetUserLock(t.Context(), "bob", false); err != nil {
		t.Fatalf("Unlock Bob failed: %v", err)
	}

	for m, err := range clientBob.GetGroupMembers(t.Context(), groupID) {
		if err != nil {
			t.Fatalf("GetGroupMembers Bob failed: %v", err)
		}
		if m.Info != "[HIDDEN]" && m.UserID != "alice" {
			t.Errorf("Bob saw info for %s: %s", m.UserID, m.Info)
		}
	}
}
