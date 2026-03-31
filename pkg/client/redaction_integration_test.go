//go:build !wasm

package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestAdminRedaction(t *testing.T) {
	tc := metadata.SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Create Admin
	adminID := "admin"
	dkA, _ := crypto.GenerateEncryptionKey()
	skA, _ := crypto.GenerateIdentityKey()
	uA := metadata.User{ID: adminID, UID: 1001, SignKey: skA.Public(), EncKey: dkA.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, tc.Node, uA, skA, tc.AdminID, tc.AdminSK)
	uAIDBytes, _ := json.Marshal(uA.ID)
	uAIDCmd, err := metadata.LogCommand{Type: metadata.CmdPromoteAdmin, Data: uAIDBytes, UserID: "bootstrap"}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.Node.Raft.Apply(uAIDCmd, 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	// 2. Setup Admin Client
	c := NewClient(tc.TS.URL).withIdentity(adminID, dkA).withSignKey(skA)
	ekBytes, err := c.GetServerKeyBytes(t.Context())
	if err != nil {
		t.Fatalf("Failed to get server encryption key: %v", err)
	}
	c, err = c.WithServerKeyBytes(ekBytes)
	if err != nil {
		t.Fatalf("WithServerKeyBytes failed: %v", err)
	}
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 3. Register Node
	n := metadata.Node{ID: "node1", Status: metadata.NodeStatusActive, Address: "1.2.3.4", PublicKey: []byte("node-pk"), SignKey: []byte("node-sk")}
	nodeBytes, _ := json.Marshal(n)
	req, _ := http.NewRequest("POST", tc.TS.URL+"/v1/node", bytes.NewReader(nodeBytes))
	req.Header.Set("X-Raft-Secret", "testsecret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to register node: %d", resp.StatusCode)
	}

	// 4. Create Group
	group, err := c.createGroup(t.Context(), "test-group", false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// 5. Verify Redaction in ListUsers
	var users []*metadata.User
	for u, err := range c.AdminListUsers(t.Context()) {
		if err != nil {
			t.Fatalf("AdminListUsers failed: %v", err)
		}
		users = append(users, u)
	}
	if len(users) == 0 {
		t.Fatal("No users returned")
	}
	for _, u := range users {
		if len(u.SignKey) > 0 || len(u.EncKey) > 0 {
			t.Errorf("User %s keys not redacted in bulk response", u.ID)
		}
	}

	// 6. Verify Redaction in ListNodes
	var nodes []*metadata.Node
	for n := range c.AdminListNodes(t.Context()) {
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		t.Fatal("No nodes returned")
	}
	for _, node := range nodes {
		if len(node.PublicKey) > 0 || len(node.SignKey) > 0 {
			t.Errorf("Node %s keys not redacted in bulk response", node.ID)
		}
	}

	// 7. Verify Redaction in ListGroups
	var groups []*metadata.Group
	for g, err := range c.AdminListGroups(t.Context()) {
		if err != nil {
			t.Fatalf("AdminListGroups failed: %v", err)
		}
		groups = append(groups, g)
	}
	if len(groups) == 0 {
		t.Fatal("No groups returned")
	}
	for _, g := range groups {
		if len(g.EncKey) > 0 || len(g.SignKey) > 0 || len(g.Lockbox) > 0 || len(g.RegistryLockbox) > 0 || len(g.EncryptedRegistry) > 0 {
			t.Errorf("Group %s sensitive fields not redacted in bulk response. EncKey: %d, SignKey: %d, Lockbox: %d", g.ID, len(g.EncKey), len(g.SignKey), len(g.Lockbox))
		}
	}

	// 8. Verify FULL metadata is still available via getGroup (for authorized users/admins)
	fetched, err := c.getGroup(t.Context(), group.ID)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if len(fetched.EncKey) == 0 || len(fetched.SignKey) == 0 || len(fetched.Lockbox) == 0 {
		t.Error("Group metadata improperly redacted in single-object GET response")
	}
}
