// Copyright 2026 TTBT Enterprises LLC
package metadata_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestSystemGroups(t *testing.T) {
	node, ts, _, _, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create Admin and Normal User
	adminID := "admin"
	uASign, _ := crypto.GenerateIdentityKey()
	uADK, _ := crypto.GenerateEncryptionKey()
	uA := metadata.User{ID: adminID, SignKey: uASign.Public(), EncKey: uADK.EncapsulationKey().Bytes()}
	uABytes, _ := json.Marshal(uA)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: uABytes}.Marshal(), 5*time.Second)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdPromoteAdmin, Data: []byte(adminID)}.Marshal(), 5*time.Second)

	userID := "alice"
	uUSign, _ := crypto.GenerateIdentityKey()
	uUDK, _ := crypto.GenerateEncryptionKey()
	uU := metadata.User{ID: userID, SignKey: uUSign.Public(), EncKey: uUDK.EncapsulationKey().Bytes()}
	uUBytes, _ := json.Marshal(uU)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: uUBytes}.Marshal(), 5*time.Second)

	time.Sleep(200 * time.Millisecond)

	// 2. Alice tries to create a system group (should fail)
	cAlice := client.NewClient(ts.URL).WithIdentity(userID, uUDK).WithSignKey(uUSign)
	// We need server key for sealing/authentication
	ekBytes, _ := cAlice.GetServerSignKey()
	ek, _ := crypto.UnmarshalEncapsulationKey(ekBytes)
	cAlice = cAlice.WithServerKey(ek)

	if err := cAlice.Login(); err != nil {
		t.Fatalf("Alice login failed: %v", err)
	}

	_, err := cAlice.CreateSystemGroup("alice-sys-group")
	if err == nil {
		t.Error("Alice (non-admin) should NOT be able to create a system group")
	} else {
		t.Logf("Caught expected error for non-admin system group creation: %v", err)
	}

	// 3. Admin creates a system group (should succeed)
	cAdmin := client.NewClient(ts.URL).WithIdentity(adminID, uADK).WithSignKey(uASign).WithServerKey(ek)
	if err := cAdmin.Login(); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}

	sysGroup, err := cAdmin.CreateSystemGroup("cluster-admin-group")
	if err != nil {
		t.Fatalf("Admin failed to create system group: %v", err)
	}
	if !sysGroup.IsSystem {
		t.Error("Created group should have IsSystem=true")
	}

	// 4. Verify labeling in list
	groups, err := cAdmin.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}

	found := false
	for _, g := range groups {
		if g.ID == sysGroup.ID {
			found = true
			if !g.IsSystem {
				t.Error("Group in list should have IsSystem=true")
			}
		}
	}
	if !found {
		t.Fatal("System group not found in list")
	}
}
