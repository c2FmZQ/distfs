//go:build !wasm

package client

import (
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestAdminMethods(t *testing.T) {
	tc := metadata.SetupCluster(t)
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Create a few users
	user1ID := tc.Node.FSM.ComputeUserID("user1")
	dk1, _ := crypto.GenerateEncryptionKey()
	sk1, _ := crypto.GenerateIdentityKey()
	u1 := metadata.User{ID: user1ID, UID: 1001, SignKey: sk1.Public(), EncKey: dk1.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, tc.Node, u1, sk1, tc.AdminID, tc.AdminSK)

	user2ID := tc.Node.FSM.ComputeUserID("user2")
	dk2, _ := crypto.GenerateEncryptionKey()
	sk2, _ := crypto.GenerateIdentityKey()
	u2 := metadata.User{ID: user2ID, UID: 1002, SignKey: sk2.Public(), EncKey: dk2.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, tc.Node, u2, sk2, tc.AdminID, tc.AdminSK)

	// 2. Setup Clients
	c1, err := NewClient(tc.TS.URL).
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithServerKeyBytes(tc.EpochEK)
	if err != nil {
		t.Fatal(err)
	}
	c1 = c1.WithAdmin(true)
	if err := c1.Login(t.Context()); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}

	// 3. Admin: List Users
	users := make(map[string]bool)
	for user, err := range c1.AdminListUsers(t.Context()) {
		if err != nil {
			t.Fatalf("AdminListUsers failed: %v", err)
		}
		users[user.ID] = true
	}
	if !users[user1ID] || !users[user2ID] {
		t.Errorf("Expected users %s and %s in list, got: %v", user1ID, user2ID, users)
	}

	// 4. Admin: Perform Audit
	count := 0
	if err := c1.AdminAudit(t.Context(), func(record metadata.AuditRecord) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("AdminAudit failed: %v", err)
	}
	if count == 0 {
		t.Error("Expected audit records, got 0")
	}

	// 5. Admin: Promote user
	if tc.Node.FSM.IsAdmin(user2ID) {
		t.Fatalf("User 2 should NOT be admin yet")
	}

	if err := c1.AdminPromote(t.Context(), user2ID); err != nil {
		t.Fatalf("Admin promotion failed: %v", err)
	}

	// 6. Verify Promotion
	if !tc.Node.FSM.IsAdmin(user2ID) {
		t.Error("User 2 should now be admin")
	}
}

func TestAdminMkdirOwner(t *testing.T) {
	tc := metadata.SetupCluster(t) // Stable setup with backbone foundations
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 2. Create User B
	userBID := tc.Node.FSM.ComputeUserID("userB")
	dkB, _ := crypto.GenerateEncryptionKey()
	skB, _ := crypto.GenerateIdentityKey()
	uB := metadata.User{ID: userBID, UID: 1002, SignKey: skB.Public(), EncKey: dkB.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, tc.Node, uB, skB, tc.AdminID, tc.AdminSK)

	// 3. Admin Setup (using default admin)
	// IMPORTANT: Disable registry to avoid circularity issues in pure metadata tests
	c, err := NewClient(tc.TS.URL).WithRegistry("").
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithServerKeyBytes(tc.EpochEK)
	if err != nil {
		t.Fatal(err)
	}
	c = c.WithAdmin(true)
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 3.5. Bootstrap Client-Side Foundations (signed root)
	if err := c.BootstrapFileSystem(t.Context()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// 4. Admin creates directory for User B
	dirPath := "/userB-home"
	if err := c.MkdirExtended(t.Context(), dirPath, 0700, MkdirOptions{OwnerID: userBID}); err != nil {
		t.Fatalf("Admin MkdirExtended failed: %v", err)
	}

	// 5. Verify Metadata
	inode, _, err := c.resolvePath(t.Context(), dirPath)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}
	if inode.OwnerID != userBID {
		t.Errorf("Expected owner %s, got %s", userBID, inode.OwnerID)
	}
	if inode.SignerID != tc.AdminID {
		t.Errorf("Expected signer %s, got %s", tc.AdminID, inode.SignerID)
	}
}
