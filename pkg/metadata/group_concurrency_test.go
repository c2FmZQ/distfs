package metadata_test

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestGroupUpdateConcurrency(t *testing.T) {
	node, ts, _, serverEK, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Initialize Cluster Secret
	secret := make([]byte, 32)
	rand.Read(secret)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdInitSecret, Data: secret}.Marshal(), 5*time.Second)

	// 1. Setup Alice (Owner) and two members to add
	uAliceSign, _ := crypto.GenerateIdentityKey()
	uAliceDK, _ := crypto.GenerateEncryptionKey()
	uAlice := metadata.User{ID: "alice", SignKey: uAliceSign.Public(), EncKey: uAliceDK.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uAlice)

	serverPK, _ := crypto.UnmarshalEncapsulationKey(serverEK)
	clientAlice := client.NewClient(ts.URL).WithIdentity("alice", uAliceDK).WithSignKey(uAliceSign).WithServerKey(serverPK)
	if err := clientAlice.Login(t.Context()); err != nil {
		t.Fatalf("Alice login failed: %v", err)
	}

	// Prepare dummy users for adding
	for _, id := range []string{"user1", "user2"} {
		sk, _ := crypto.GenerateIdentityKey()
		dk, _ := crypto.GenerateEncryptionKey()
		u := metadata.User{ID: id, SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes()}
		metadata.CreateUser(t, node, u)
	}

	// 2. Alice creates a group
	group, err := clientAlice.CreateGroup(t.Context(), "race-test")
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
	finalGroup, err := clientAlice.GetGroup(t.Context(), group.ID)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}

	if !finalGroup.Members["user1"] {
		t.Errorf("user1 missing from group members")
	}
	if !finalGroup.Members["user2"] {
		t.Errorf("user2 missing from group members")
	}

	// Verify Registry (Fix #2 ensures merge)
	found1, found2 := false, false
	for m, err := range clientAlice.GetGroupMembers(t.Context(), group.ID) {
		if err != nil {
			t.Fatalf("GetGroupMembers failed: %v", err)
		}
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
