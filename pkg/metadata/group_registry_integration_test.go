package metadata_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestGroupMemberRegistry(t *testing.T) {
	node, ts, _, serverEK, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Initialize Cluster Secret
	secret := make([]byte, 32)
	rand.Read(secret)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdInitSecret, Data: secret}.Marshal(), 5*time.Second)

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

	if err := clientAlice.Login(); err != nil {
		t.Fatalf("Alice login failed: %v", err)
	}

	group, err := clientAlice.CreateGroup("test-registry")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	groupID := group.ID

	// 3. Alice adds Bob with email
	err = clientAlice.AddUserToGroup(groupID, "bob", "bob@example.com")
	if err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	// 4. Alice (Owner) views members - should see Bob's email
	members, err := clientAlice.GetGroupMembers(groupID)
	if err != nil {
		t.Fatalf("GetGroupMembers Alice failed: %v", err)
	}

	foundBob := false
	for _, m := range members {
		if m.UserID == "bob" {
			if m.Email != "bob@example.com" {
				t.Errorf("Alice saw wrong email for Bob: %s", m.Email)
			}
			foundBob = true
		}
	}
	if !foundBob {
		t.Error("Alice didn't find Bob in registry")
	}

	// 5. Bob (Member) views members - should NOT see emails
	clientBob := client.NewClient(ts.URL)
	clientBob = clientBob.WithIdentity("bob", uBobDK).WithSignKey(uBobSign).WithServerKey(serverPK)

	if err := clientBob.Login(); err != nil {
		t.Fatalf("Bob login failed: %v", err)
	}

	membersBob, err := clientBob.GetGroupMembers(groupID)
	if err != nil {
		t.Fatalf("GetGroupMembers Bob failed: %v", err)
	}

	for _, m := range membersBob {
		if m.Email != "[HIDDEN]" && m.UserID != "alice" { // Alice's email might be hidden too if she didn't set it
			t.Errorf("Bob saw email for %s: %s", m.UserID, m.Email)
		}
	}
}
