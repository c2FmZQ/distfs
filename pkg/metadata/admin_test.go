// Copyright 2026 TTBT Enterprises LLC
package metadata_test

import (
	"bytes"
	"crypto/mlkem"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/client"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	bolt "go.etcd.io/bbolt"
)

func TestAdminCUI(t *testing.T) {
	node, ts, _, _, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create First User (Should be Admin)
	user1ID := "admin-user"
	dk1, _ := crypto.GenerateEncryptionKey()
	sk1, _ := crypto.GenerateIdentityKey()
	u1 := metadata.User{ID: user1ID, UID: 1001, SignKey: sk1.Public(), EncKey: dk1.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, u1)

	// 2. Create Second User (Should NOT be Admin)
	user2ID := "normal-user"
	dk2, _ := crypto.GenerateEncryptionKey()
	sk2, _ := crypto.GenerateIdentityKey()
	u2 := metadata.User{ID: user2ID, UID: 1002, SignKey: sk2.Public(), EncKey: dk2.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, u2)

	// 3. Verify Admin Status
	if !node.FSM.IsAdmin(user1ID) {
		t.Error("User 1 should be admin")
	}
	if node.FSM.IsAdmin(user2ID) {
		t.Error("User 2 should NOT be admin")
	}

	// Helper to make sealed admin request
	callAdmin := func(sk *crypto.IdentityKey, dk *mlkem.DecapsulationKey768, userID string, path string) int {
		c := client.NewClient(ts.URL)
		c = c.WithIdentity(userID, dk).WithSignKey(sk)
		// We need server key for sealing
		ekBytes, _ := c.GetServerSignKey(t.Context())
		ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
		c = c.WithServerKey(ek)

		if err := c.Login(t.Context()); err != nil {
			t.Logf("login failed: %v", err)
			return 500
		}

		if path == "users" {
			found := false
			for _, err := range c.AdminListUsers(t.Context()) {
				if err != nil {
					if apiErr, ok := err.(*client.APIError); ok {
						return apiErr.StatusCode
					}
					return 500
				}
				found = true
			}
			if found {
				return 200
			}
			return 200 // Even if empty
		}
		return 0
	}

	// 4. Verify Access Control
	code1 := callAdmin(sk1, dk1, user1ID, "users")
	if code1 != 200 {
		t.Errorf("Admin user failed to access admin API: %d", code1)
	}

	code2 := callAdmin(sk2, dk2, user2ID, "users")
	if code2 != 403 {
		t.Errorf("Normal user should be forbidden (403), got %d", code2)
	}

	// 5. Promote User 2
	c1 := client.NewClient(ts.URL)
	c1 = c1.WithIdentity(user1ID, dk1).WithSignKey(sk1)
	ekBytes, _ := c1.GetServerSignKey(t.Context())
	ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
	c1 = c1.WithServerKey(ek)
	if err := c1.Login(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := c1.AdminPromote(t.Context(), user2ID); err != nil {
		t.Fatalf("Promotion failed: %v", err)
	}

	// 6. Verify User 2 is now Admin
	if !node.FSM.IsAdmin(user2ID) {
		t.Error("User 2 should now be admin")
	}
	code2After := callAdmin(sk2, dk2, user2ID, "users")
	if code2After != 200 {
		t.Errorf("Newly promoted user failed to access admin API: %d", code2After)
	}
}

func TestAdminAPI(t *testing.T) {
	node, ts, _, _, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create First User (Admin)
	userID := "admin-user"
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	u := metadata.User{ID: userID, UID: 1001, SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, u)

	// 2. Setup Admin Client
	c := client.NewClient(ts.URL)
	c = c.WithIdentity(userID, dk).WithSignKey(sk)
	ekBytes, _ := c.GetServerSignKey(t.Context())
	ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
	c = c.WithServerKey(ek)
	if err := c.Login(t.Context()); err != nil {
		t.Fatal(err)
	}

	// 3. Fetch Users
	var users []*metadata.User
	for u, err := range c.AdminListUsers(t.Context()) {
		if err != nil {
			t.Fatalf("AdminListUsers failed: %v", err)
		}
		users = append(users, u)
	}
	if len(users) != 1 || users[0].ID != userID {
		t.Errorf("Unexpected users list: %v", users)
	}

	// 4. Register Node (Internal Heartbeat still exists)
	n := metadata.Node{ID: "node1", Status: metadata.NodeStatusActive, Address: "1.2.3.4"}
	nodeBytes, _ := json.Marshal(n)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/node", bytes.NewReader(nodeBytes))
	req.Header.Set("X-Raft-Secret", "testsecret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/node status %d", resp.StatusCode)
	}

	// 5. Fetch Nodes via Admin API
	var nodes []*metadata.Node
	for n := range c.AdminListNodes(t.Context()) {
		nodes = append(nodes, n)
	}
	if len(nodes) < 1 {
		t.Error("No nodes returned")
	}

	// 6. Test Lookup
	id, err := c.AdminLookup(t.Context(), "alice@example.com", "Test Lookup")
	if err != nil {
		t.Fatalf("AdminLookup failed: %v", err)
	}
	if id == "" {
		t.Error("Lookup returned empty ID")
	}
}

func TestAdminMkdirOwner(t *testing.T) {
	node, ts, _, _, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create Admin
	adminID := "admin"
	dkA, _ := crypto.GenerateEncryptionKey()
	skA, _ := crypto.GenerateIdentityKey()
	uA := metadata.User{ID: adminID, UID: 1001, SignKey: skA.Public(), EncKey: dkA.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uA)

	// 2. Create User B
	userBID := "userB"
	dkB, _ := crypto.GenerateEncryptionKey()
	skB, _ := crypto.GenerateIdentityKey()
	uB := metadata.User{ID: userBID, UID: 1002, SignKey: skB.Public(), EncKey: dkB.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uB)

	// 3. Admin Setup
	c := client.NewClient(ts.URL)
	c = c.WithIdentity(adminID, dkA).WithSignKey(skA)
	ekBytes, _ := c.GetServerSignKey(t.Context())
	ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
	c = c.WithServerKey(ek).WithAdmin(true)
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 3.5 Initialize Root
	if err := c.EnsureRoot(t.Context()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// 4. Admin creates directory for User B
	dirPath := "/userB-home"
	err := c.MkdirExtended(t.Context(), dirPath, 0700, client.MkdirOptions{OwnerID: userBID})
	if err != nil {
		t.Fatalf("Admin MkdirExtended failed: %v", err)
	}

	// 5. Verify Metadata
	inode, _, err := c.ResolvePath(t.Context(), dirPath)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}
	if inode.OwnerID != userBID {
		t.Errorf("Expected owner %s, got %s", userBID, inode.OwnerID)
	}
	if inode.SignerID != adminID {
		t.Errorf("Expected signer %s, got %s", adminID, inode.SignerID)
	}

	// 6. Verify User B Quota
	var uBUpdated metadata.User
	node.FSM.DB().View(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("users"), []byte(userBID))
		if err != nil {
			return err
		}
		return json.Unmarshal(plain, &uBUpdated)
	})
	if uBUpdated.Usage.InodeCount != 1 {
		t.Errorf("Expected User B inode count 1, got %d", uBUpdated.Usage.InodeCount)
	}
}

func TestOwnerImmutability(t *testing.T) {
	node, ts, _, _, server := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create User
	uID := "user1"
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	user := metadata.User{ID: uID, UID: 1001, SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, user)

	// 2. Create Inode
	inode := metadata.Inode{ID: "file1", OwnerID: uID, Version: 1, Type: metadata.FileType}
	inode.SignInodeForTest(uID, sk)
	ib, _ := json.Marshal(inode)
	server.ApplyRaftCommandInternal(metadata.CmdCreateInode, ib, uID)

	// 3. Attempt to change owner via Update
	inode.Version = 2
	inode.OwnerID = "victim"
	inode.SignInodeForTest(uID, sk)
	ub, _ := json.Marshal(inode)

	res, err := server.ApplyRaftCommandInternal(metadata.CmdUpdateInode, ub, uID)
	if err == nil {
		if !isFSMError(res) {
			t.Error("FSM should have rejected OwnerID change")
		}
	}
}

func TestFSM_GroupAuthorization(t *testing.T) {
	node, ts, _, _, server := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create User and Group
	u1ID := "user1"
	sk1, _ := crypto.GenerateIdentityKey()
	u1 := metadata.User{ID: u1ID, UID: 1001, SignKey: sk1.Public()}
	metadata.CreateUser(t, node, u1)

	gID := "group1"
	group := metadata.Group{ID: gID, OwnerID: "some-other-user", Members: map[string]bool{"somebody": true}}
	fsm := node.FSM
	fsm.DB().Update(func(tx *bolt.Tx) error {
		return fsm.Put(tx, []byte("groups"), []byte(gID), metadata.MustMarshalJSON(group))
	})

	// 2. Create Inode owned by u1
	inode := metadata.Inode{ID: "file1", OwnerID: u1ID, Version: 1, Type: metadata.FileType}
	inode.SignInodeForTest(u1ID, sk1)
	ib, _ := json.Marshal(inode)
	server.ApplyRaftCommandInternal(metadata.CmdCreateInode, ib, u1ID)

	// 3. Attempt to assign to group1 (u1 is not a member)
	inode.Version = 2
	inode.GroupID = gID
	inode.SignInodeForTest(u1ID, sk1)
	ub, _ := json.Marshal(inode)

	res, err := server.ApplyRaftCommandInternal(metadata.CmdUpdateInode, ub, u1ID)
	if err == nil {
		if !isFSMError(res) {
			t.Error("FSM should have rejected GroupID assignment for non-member")
		}
	}

	// 4. Add u1 to group and try again
	fsm.DB().Update(func(tx *bolt.Tx) error {
		group.Members[u1ID] = true
		return fsm.Put(tx, []byte("groups"), []byte(gID), metadata.MustMarshalJSON(group))
	})

	res, err = server.ApplyRaftCommandInternal(metadata.CmdUpdateInode, ub, u1ID)
	if err != nil || isFSMError(res) {
		t.Errorf("FSM should have allowed GroupID assignment for member: %v", res)
	}
}

func isFSMError(res interface{}) bool {
	if res == nil {
		return false
	}
	if _, ok := res.(error); ok {
		return true
	}
	if b, ok := res.([]byte); ok {
		// Try to see if it's an APIErrorResponse
		var er metadata.APIErrorResponse
		if err := json.Unmarshal(b, &er); err == nil && er.Code != "" {
			return true
		}
	}
	return false
}

func TestFSM_AdminCreation(t *testing.T) {
	node, ts, _, _, server := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create Admin and Normal User
	adminID := "admin"
	skA, _ := crypto.GenerateIdentityKey()
	metadata.CreateUser(t, node, metadata.User{ID: adminID, UID: 1001, SignKey: skA.Public()})

	user1ID := "user1"
	sk1, _ := crypto.GenerateIdentityKey()
	metadata.CreateUser(t, node, metadata.User{ID: user1ID, UID: 1002, SignKey: sk1.Public()})

	// 2. Admin creates inode for user1 (SUCCESS)
	inodeA := metadata.Inode{ID: "dirA", OwnerID: user1ID, Version: 1, Type: metadata.DirType}
	inodeA.SignInodeForTest(adminID, skA)
	ibA, _ := json.Marshal(inodeA)
	res, err := server.ApplyRaftCommandInternal(metadata.CmdCreateInode, ibA, adminID)
	if err != nil || isFSMError(res) {
		t.Errorf("Admin should be allowed to create inode for another user: %v", res)
	}

	// 3. Normal user creates inode for admin (FAIL)
	inode1 := metadata.Inode{ID: "dir1", OwnerID: adminID, Version: 1, Type: metadata.DirType}
	inode1.SignInodeForTest(user1ID, sk1)
	ib1, _ := json.Marshal(inode1)
	res, err = server.ApplyRaftCommandInternal(metadata.CmdCreateInode, ib1, user1ID)
	if err == nil {
		if !isFSMError(res) {
			t.Error("Normal user should be forbidden from creating inode for another user")
		}
	}
}
