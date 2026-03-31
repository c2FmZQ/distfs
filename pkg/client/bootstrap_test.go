//go:build !wasm

package client

import (
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestBootstrapFileSystem(t *testing.T) {
	tc := metadata.SetupRawCluster(t)
	defer tc.Node.Shutdown()
	defer tc.Server.Shutdown()
	defer tc.TS.Close()

	ctx := t.Context()
	svKey, _ := crypto.UnmarshalEncapsulationKey(tc.EpochEK)

	// 1. Setup Admin Client
	c := NewClient(tc.TS.URL).
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithAdmin(true).
		withServerKey(svKey)

	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 1.5 Setup Data Node (Required for registry attestation files)
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, tc.NodeSK.Public(), tc.Node.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	registerNode(t, tc.TS.URL, "testsecret", metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	})

	// 2. Run Bootstrap
	if err := c.BootstrapFileSystem(ctx); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// 3. Verify Backbone
	dirs := []string{"/", "/registry", "/users"}
	for _, d := range dirs {
		inode, _, err := c.resolvePath(ctx, d)
		if err != nil {
			t.Errorf("Failed to resolve %s: %v", d, err)
			continue
		}

		group, err := c.getGroup(ctx, inode.GroupID)
		if err != nil {
			t.Errorf("Failed to get group %s for %s: %v", inode.GroupID, d, err)
			continue
		}
		groupName, _ := c.getGroupName(ctx, group)

		if d == "/" {
			if groupName != "users" && inode.GroupID != "users" {
				t.Errorf("Root group should be users, got %s (ID %s)", groupName, inode.GroupID)
			}
			if inode.Mode != 0755 {
				t.Errorf("Root mode should be 0755, got %o", inode.Mode)
			}
		} else if d == "/users" {
			if groupName != "users" && inode.GroupID != "users" {
				t.Errorf("/users group should be users, got %s (ID %s)", groupName, inode.GroupID)
			}
			if inode.Mode != 0750 {
				t.Errorf("/users mode should be 0750, got %o", inode.Mode)
			}
		} else if d == "/registry" {
			if groupName != "registry" && inode.GroupID != "registry" {
				t.Errorf("/registry group should be registry, got %s (ID %s)", groupName, inode.GroupID)
			}
			if inode.Mode != 0750 {
				t.Errorf("/registry mode should be 0750, got %o", inode.Mode)
			}
		}
	}

	// 4. Verify Anchors
	// We expect anchors for:
	// - alice.user (admin)
	// - users.group
	// - registry.group
	// - <usersGID>.group-id
	// - <registryGID>.group-id

	// We'll find the GIDs first
	usersInode, _, _ := c.resolvePath(ctx, "/users")
	usersGID := usersInode.GroupID
	regInodeDir, _, _ := c.resolvePath(ctx, "/registry")
	registryGID := regInodeDir.GroupID

	anchors := []string{
		"/registry/admin.user",
		"/registry/" + tc.AdminID + ".user-id",
		"/registry/users.group",
		"/registry/registry.group",
		"/registry/" + usersGID + ".group-id",
		"/registry/" + registryGID + ".group-id",
	}
	for _, a := range anchors {
		_, _, err := c.resolvePath(ctx, a)
		if err != nil {
			t.Errorf("Failed to resolve anchor %s: %v", a, err)
		}
	}

	// 5. Verify ACL on /registry
	if regInodeDir.AccessACL.Groups[usersGID] != 0005 {
		t.Errorf("Expected read+execute access for users group (%s) on /registry, got %o", usersGID, regInodeDir.AccessACL.Groups[usersGID])
	}
}
