// Copyright 2026 TTBT Enterprises LLC
package metadata_test

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestAdminCUI(t *testing.T) {
	node, ts, _, _, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create First User (Should be Admin)
	user1ID := "admin-user"
	dk1, _ := crypto.GenerateEncryptionKey()
	sk1, _ := crypto.GenerateIdentityKey()
	u1 := metadata.User{ID: user1ID, SignKey: sk1.Public(), EncKey: dk1.EncapsulationKey().Bytes()}
	u1Bytes, _ := json.Marshal(u1)
	if err := node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: u1Bytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	// 2. Create Second User (Should NOT be Admin)
	user2ID := "normal-user"
	dk2, _ := crypto.GenerateEncryptionKey()
	sk2, _ := crypto.GenerateIdentityKey()
	u2 := metadata.User{ID: user2ID, SignKey: sk2.Public(), EncKey: dk2.EncapsulationKey().Bytes()}
	u2Bytes, _ := json.Marshal(u2)
	if err := node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: u2Bytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

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
		ekBytes, _ := c.GetServerSignKey()
		ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
		c = c.WithServerKey(ek)

		if err := c.Login(); err != nil {
			t.Logf("login failed: %v", err)
			return 500
		}

		ctx := context.Background()
		if path == "users" {
			_, err := c.AdminListUsers(ctx)
			if err != nil {
				if apiErr, ok := err.(*client.APIError); ok {
					return apiErr.StatusCode
				}
				return 500
			}
			return 200
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
	ekBytes, _ := c1.GetServerSignKey()
	ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
	c1 = c1.WithServerKey(ek)
	if err := c1.Login(); err != nil {
		t.Fatal(err)
	}

	if err := c1.AdminPromote(context.Background(), user2ID); err != nil {
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
	u := metadata.User{ID: userID, SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes()}
	uBytes, _ := json.Marshal(u)
	if err := node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: uBytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	// 2. Setup Admin Client
	c := client.NewClient(ts.URL)
	c = c.WithIdentity(userID, dk).WithSignKey(sk)
	ekBytes, _ := c.GetServerSignKey()
	ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
	c = c.WithServerKey(ek)
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	// 3. Fetch Users
	users, err := c.AdminListUsers(context.Background())
	if err != nil {
		t.Fatalf("AdminListUsers failed: %v", err)
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
	nodes, err := c.AdminListNodes(context.Background())
	if err != nil {
		t.Fatalf("AdminListNodes failed: %v", err)
	}
	if len(nodes) < 1 {
		t.Error("No nodes returned")
	}

	// 6. Test Lookup
	secret := make([]byte, 32)
	if err := node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdInitSecret, Data: secret}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	id, err := c.AdminLookup(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("AdminLookup failed: %v", err)
	}
	if id == "" {
		t.Error("Lookup returned empty ID")
	}
}
