package metadata_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestGroupDiscovery(t *testing.T) {
	node, ts, _, serverEK, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Initialize Cluster Secret
	secret := make([]byte, 32)
	rand.Read(secret)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdInitSecret, Data: secret}.Marshal(), 5*time.Second)

	// 1. Setup Alice and Bob
	uAliceSign, _ := crypto.GenerateIdentityKey()
	uAliceDK, _ := crypto.GenerateEncryptionKey()
	uAlice := metadata.User{ID: "alice", SignKey: uAliceSign.Public(), EncKey: uAliceDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uAlice)

	uBobSign, _ := crypto.GenerateIdentityKey()
	uBobDK, _ := crypto.GenerateEncryptionKey()
	uBob := metadata.User{ID: "bob", SignKey: uBobSign.Public(), EncKey: uBobDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uBob)

	clientAlice := client.NewClient(ts.URL)
	serverPK, _ := crypto.UnmarshalEncapsulationKey(serverEK)
	clientAlice = clientAlice.WithIdentity("alice", uAliceDK).WithSignKey(uAliceSign).WithServerKey(serverPK)
	if err := clientAlice.Login(t.Context()); err != nil {
		t.Fatalf("Alice login failed: %v", err)
	}

	clientBob := client.NewClient(ts.URL)
	clientBob = clientBob.WithIdentity("bob", uBobDK).WithSignKey(uBobSign).WithServerKey(serverPK)
	if err := clientBob.Login(t.Context()); err != nil {
		t.Fatalf("Bob login failed: %v", err)
	}

	// 2. Alice creates Group A (Direct Owner)
	groupA, err := clientAlice.CreateGroup(t.Context(), "group-a")
	if err != nil {
		t.Fatalf("CreateGroup A failed: %v", err)
	}

	// 3. Alice adds Bob to Group A (Bob is Member)
	err = clientAlice.AddUserToGroup(t.Context(), groupA.ID, "bob", "Bob info", nil)
	if err != nil {
		t.Fatalf("AddUserToGroup Bob failed: %v", err)
	}

	// 4. Alice creates Group B owned by Group A (Alice is Manager)
	groupB, err := clientAlice.CreateGroup(t.Context(), "group-b")
	if err != nil {
		t.Fatalf("CreateGroup B failed: %v", err)
	}
	err = clientAlice.GroupChown(t.Context(), groupB.ID, groupA.ID)
	if err != nil {
		t.Fatalf("GroupChown B failed: %v", err)
	}

	// 5. Verify Alice's Discovery
	var groupsA []metadata.GroupListEntry
	for g, err := range clientAlice.ListGroups(t.Context()) {
		if err != nil {
			t.Fatalf("ListGroups Alice failed: %v", err)
		}
		groupsA = append(groupsA, g)
	}

	if len(groupsA) != 2 {
		t.Errorf("Alice should see 2 groups, got %d", len(groupsA))
	}

	rolesAlice := make(map[string]metadata.GroupRole)
	for _, g := range groupsA {
		rolesAlice[g.ID] = g.Role
	}

	if rolesAlice[groupA.ID] != metadata.RoleOwner {
		t.Errorf("Alice role for A: got %s, want owner", rolesAlice[groupA.ID])
	}
	if rolesAlice[groupB.ID] != metadata.RoleManager {
		t.Errorf("Alice role for B: got %s, want manager", rolesAlice[groupB.ID])
	}

	// 6. Verify Bob's Discovery
	var groupsB []metadata.GroupListEntry
	for g, err := range clientBob.ListGroups(t.Context()) {
		if err != nil {
			t.Fatalf("ListGroups Bob failed: %v", err)
		}
		groupsB = append(groupsB, g)
	}

	if len(groupsB) != 2 {
		t.Errorf("Bob should see 2 groups, got %d", len(groupsB))
	}

	rolesBob := make(map[string]metadata.GroupRole)
	for _, g := range groupsB {
		rolesBob[g.ID] = g.Role
	}

	if rolesBob[groupA.ID] != metadata.RoleMember {
		t.Errorf("Bob role for A: got %s, want member", rolesBob[groupA.ID])
	}
	if rolesBob[groupB.ID] != metadata.RoleManager {
		t.Errorf("Bob role for B: got %s, want manager", rolesBob[groupB.ID])
	}

	// 7. Verify Delegated Registry Access (Fix #1)
	// Bob is a member of A, and A owns B. Bob should be able to see B's members (PII).
	foundAlice := false
	for m, err := range clientBob.GetGroupMembers(t.Context(), groupB.ID) {
		if err != nil {
			t.Fatalf("Bob GetGroupMembers B failed: %v", err)
		}
		if m.UserID == "alice" && m.Info != "[HIDDEN]" {
			foundAlice = true
		}
	}
	if !foundAlice {
		t.Errorf("Bob should see Alice in B's registry via delegated management")
	}

	// 8. Verify Cryptographic Authorization Transfer (Fix #3)
	// Bob: Create Group C.
	groupC, err := clientBob.CreateGroup(t.Context(), "group-c")
	if err != nil {
		t.Fatalf("Bob CreateGroup C failed: %v", err)
	}

	// Bob: Transfer Group C to Alice.
	err = clientBob.GroupChown(t.Context(), groupC.ID, "alice")
	if err != nil {
		t.Fatalf("Bob GroupChown C to Alice failed: %v", err)
	}

	// Alice: Should now be able to manage C (e.g., fetch its private signing key)
	_, err = clientAlice.GetGroupSignKey(t.Context(), groupC.ID)
	if err != nil {
		t.Errorf("Alice failed to fetch sign key for group C after transfer: %v", err)
	}
}
