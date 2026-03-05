// Copyright 2026 TTBT Enterprises LLC
package metadata_test

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

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

func TestAdminOverrides(t *testing.T) {
	node, ts, _, _, server := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create Admin
	adminID := "admin"
	dkA, _ := crypto.GenerateEncryptionKey()
	skA, _ := crypto.GenerateIdentityKey()
	uA := metadata.User{ID: adminID, UID: 1001, SignKey: skA.Public(), EncKey: dkA.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uA)
	// Promote user to admin
	if _, err := server.ApplyRaftCommandInternal(metadata.CmdPromoteAdmin, metadata.MustMarshalJSON(uA.ID), "bootstrap"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	// 2. Create User B
	userID := "userB"
	dkB, _ := crypto.GenerateEncryptionKey()
	skB, _ := crypto.GenerateIdentityKey()
	uB := metadata.User{ID: userID, UID: 1002, SignKey: skB.Public(), EncKey: dkB.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, node, uB)

	// 3. Create a File owned by Admin
	inode := metadata.Inode{ID: "file1", OwnerID: adminID, Size: 100, Mode: 0600, NLink: 1, Version: 1, Lockbox: make(crypto.Lockbox)}
	// Add Admin to lockbox so they can unlock it for re-sealing
	fileKey := make([]byte, 32)
	rand.Read(fileKey)
	inode.Lockbox.AddRecipient(adminID, dkA.EncapsulationKey(), fileKey)

	// Encrypt ClientBlob (VerifyInode now checks this)
	blob := metadata.InodeClientBlob{
		SignerID:          adminID,
		AuthorizedSigners: []string{adminID},
	}
	plainBlob, _ := json.Marshal(blob)
	encBlob, _ := crypto.EncryptDEM(fileKey, plainBlob)
	inode.ClientBlob = encBlob

	// IMPORTANT: These must be set so they are included in ManifestHash correctly
	// AND matches what's in the ClientBlob.
	inode.SetSignerID(adminID)
	inode.SetAuthorizedSigners([]string{adminID})

	inode.SignInodeForTest(adminID, skA)

	iBytes, _ := json.Marshal(inode)
	if _, err := server.ApplyRaftCommandInternal(metadata.CmdCreateInode, iBytes, adminID); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	// Setup Client
	c := client.NewClient(ts.URL)
	c = c.WithIdentity(adminID, dkA).WithSignKey(skA)
	ekBytes, _ := c.GetServerSignKey(t.Context())
	ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
	c = c.WithServerKey(ek).WithAdmin(true)
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 4. Admin Chown to User B
	req := metadata.AdminChownRequest{OwnerID: &userID}
	if err := c.AdminChown(t.Context(), "file1", req); err != nil {
		t.Fatalf("AdminChown failed: %v", err)
	}

	// 5. Verify Metadata
	var updated metadata.Inode
	node.FSM.DB().View(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("inodes"), []byte("file1"))
		if err != nil {
			return err
		}
		return json.Unmarshal(plain, &updated)
	})
	if updated.OwnerID != userID {
		t.Errorf("Expected owner %s, got %s", userID, updated.OwnerID)
	}

	// 6. Verify Quota accounting
	var uBUpdated metadata.User
	node.FSM.DB().View(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("users"), []byte(userID))
		if err != nil {
			return err
		}
		return json.Unmarshal(plain, &uBUpdated)
	})
	if uBUpdated.Usage.TotalBytes != 100 {
		t.Errorf("Expected User B usage 100, got %d", uBUpdated.Usage.TotalBytes)
	}
	if uBUpdated.Usage.InodeCount != 1 {
		t.Errorf("Expected User B inode count 1, got %d", uBUpdated.Usage.InodeCount)
	}

	// 7. Admin Chmod (World-write 0002 should be stripped to 0775)
	if err := c.AdminChmod(t.Context(), "file1", 0777); err != nil {
		t.Fatalf("AdminChmod failed: %v", err)
	}
	node.FSM.DB().View(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("inodes"), []byte("file1"))
		if err != nil {
			return err
		}
		return json.Unmarshal(plain, &updated)
	})
	if updated.Mode != 0775 {
		t.Errorf("Expected mode 0775, got %04o", updated.Mode)
	}
}
