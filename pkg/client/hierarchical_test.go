//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	"crypto/mlkem"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func TestAccessControls_Comprehensive(t *testing.T) {
	ctx := t.Context()

	// 1. Setup Raw Cluster (No backbone)
	tc := metadata.SetupRawCluster(t)
	defer tc.Node.Shutdown()

	// 2. Setup Data Node
	dataDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	dataSt := storage.New(dataDir, mk)
	dataStore, _ := data.NewDiskStore(dataSt)
	csk := metadata.GetClusterSignKey(tc.Node.FSM)
	dataServer := data.NewServer(dataStore, csk.Public, tc.Node.FSM, data.NoopValidator{}, true, true)
	dataTS := httptest.NewServer(dataServer)
	defer dataTS.Close()

	registerNode(t, tc.TS.URL, "testsecret", metadata.Node{
		ID:      "data1",
		Address: dataTS.URL,
		Status:  metadata.NodeStatusActive,
	})

	// 3. Admin Client Setup
	svKey, _ := crypto.UnmarshalEncapsulationKey(tc.EpochEK)
	adminClient := NewClient(tc.TS.URL).
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithAdmin(true).
		withServerKey(svKey).
		WithRegistry("/registry")

	if err := adminClient.Login(ctx); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}

	// 4. Bootstrap Backbone
	if err := adminClient.BootstrapFileSystem(ctx); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// 5. Create Users: Bob, Charlie, Eve
	usersGID, _, _ := adminClient.ResolveGroupName(ctx, "users")

	setupUser := func(name string) (string, *crypto.IdentityKey, *mlkem.DecapsulationKey768, *Client) {
		id := tc.Node.FSM.ComputeUserID(name)
		dk, _ := crypto.GenerateEncryptionKey()
		sk, _ := crypto.GenerateIdentityKey()
		u := metadata.User{ID: id, SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes()}
		createUser(t, tc.Node, u, sk, tc.AdminID, tc.AdminSK)
		if err := adminClient.AnchorUserInRegistry(ctx, name, u.ID, tc.AdminID); err != nil {
			t.Fatalf("AnchorUserInRegistry failed for %s: %v", name, err)
		}
		// Add to 'users' group so they can access registry
		if err := adminClient.AddUserToGroup(ctx, usersGID, id, name, nil); err != nil {
			t.Fatalf("AddUserToGroup failed for %s: %v", name, err)
		}

		c := NewClient(tc.TS.URL).
			withIdentity(id, dk).
			withSignKey(sk).
			withServerKey(svKey).
			WithRegistry("/registry")
		if err := c.Login(ctx); err != nil {
			t.Fatalf("Login failed for %s: %v", name, err)
		}
		return id, sk, dk, c
	}

	bobID, _, _, bobClient := setupUser("bob")
	charlieID, _, _, charlieClient := setupUser("charlie")
	eveID, _, _, eveClient := setupUser("eve")

	// Helper to check if an error is a permission error
	assertForbidden := func(err error, desc string) {
		t.Helper()
		if err == nil {
			t.Fatalf("Expected permission denied for %s, but got success", desc)
		}
		if isNotFound(err) {
			t.Fatalf("Expected permission denied for %s, but got not found: %v", desc, err)
		}
	}

	getFile := func(c *Client, path string) ([]byte, error) {
		rc, err := c.OpenBlobRead(ctx, path)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}

	// ========================================================================
	// Scenario 1: Admin creates a directory for another user (Bob)
	// ========================================================================
	err := adminClient.MkdirExtended(ctx, "/bob-home", 0750, MkdirOptions{
		OwnerID: bobID,
	})
	if err != nil {
		t.Fatalf("Admin failed to provision home dir for Bob: %v", err)
	}
	// Bob (the Owner) assigns the directory to the 'users' group so others can traverse it.
	if err := bobClient.Chgrp(ctx, "/bob-home", usersGID); err != nil {
		t.Fatalf("Bob failed to assign his home dir to group: %v", err)
	}
	// Bob should be able to create a file inside
	err = bobClient.CreateFile(ctx, "/bob-home/private.txt", bytes.NewReader([]byte("secret")), 6)
	if err != nil {
		t.Fatalf("Bob failed to write to his own home dir: %v", err)
	}
	// Charlie should NOT be able to read it
	_, err = getFile(charlieClient, "/bob-home/private.txt")
	assertForbidden(err, "Charlie reading Bob's private file")

	// ========================================================================
	// Scenario 2: Group read/write permission & Self-Owned Groups
	// ========================================================================
	// Bob creates a self-owned group 'project-b'
	groupB, err := bobClient.createGroupWithOptions(ctx, "project-b", false, metadata.SelfOwnedGroup)
	if err != nil {
		t.Fatalf("Bob failed to create project-b group: %v", err)
	}
	if err := adminClient.AnchorGroupInRegistry(ctx, "project-b", groupB.ID); err != nil {
		t.Fatalf("Admin failed to anchor project-b: %v", err)
	}

	// Bob creates a shared directory and assigns it to 'project-b'
	err = bobClient.MkdirExtended(ctx, "/bob-home/shared", 0770, MkdirOptions{
		GroupID: groupB.ID,
	})
	if err != nil {
		t.Fatalf("Bob failed to create shared dir: %v", err)
	}

	// Bob adds Charlie to 'project-b'
	t.Logf("DEBUG: Adding Charlie (%s) to project-b (%s)", charlieID, groupB.ID)
	err = bobClient.AddUserToGroup(ctx, groupB.ID, charlieID, "Charlie", nil)
	if err != nil {
		t.Fatalf("Bob failed to add Charlie to group: %v", err)
	}

	// Verify Charlie is in group project-b
	inGroup, err := tc.Node.FSM.IsUserInGroup(charlieID, groupB.ID)
	if err != nil || !inGroup {
		t.Fatalf("FSM verification failed: Charlie is not in project-b (err: %v)", err)
	}

	// Charlie should be able to write a file in the shared dir
	err = charlieClient.CreateFileExtended(ctx, "/bob-home/shared/charlie.txt", bytes.NewReader([]byte("charlie was here")), 16, MkdirOptions{
		Mode: ptr(uint32(0660)), // rw-rw----
	})
	if err != nil {
		t.Fatalf("Charlie failed to write to shared dir: %v", err)
	}

	// Bob should be able to read Charlie's file
	content, err := getFile(bobClient, "/bob-home/shared/charlie.txt")
	if err != nil {
		t.Fatalf("Bob failed to read Charlie's shared file: %v", err)
	}
	if string(content) != "charlie was here" {
		t.Fatalf("Unexpected content: %s", string(content))
	}

	// Eve should NOT be able to read or write
	_, err = getFile(eveClient, "/bob-home/shared/charlie.txt")
	assertForbidden(err, "Eve reading shared file")
	err = eveClient.CreateFile(ctx, "/bob-home/shared/eve.txt", bytes.NewReader([]byte("evil")), 4)
	assertForbidden(err, "Eve writing to shared dir")

	// Charlie can rename his file
	err = charlieClient.Rename(ctx, "/bob-home/shared/charlie.txt", "/bob-home/shared/charlie-renamed.txt")
	if err != nil {
		t.Fatalf("Charlie failed to rename file in shared dir: %v", err)
	}

	// ========================================================================
	// Scenario 3: World read permission
	// ========================================================================
	err = bobClient.CreateFileExtended(ctx, "/bob-home/public.txt", bytes.NewReader([]byte("public info")), 11, MkdirOptions{
		Mode: ptr(uint32(0644)), // rw-r--r--
	})
	if err != nil {
		t.Fatalf("Bob failed to create public file: %v", err)
	}

	// Eve can read it
	content, err = getFile(eveClient, "/bob-home/public.txt")
	if err != nil {
		t.Fatalf("Eve failed to read public file: %v", err)
	}
	if string(content) != "public info" {
		t.Fatalf("Unexpected public content: %s", string(content))
	}

	// Eve cannot write to it
	err = eveClient.CreateFile(ctx, "/bob-home/public.txt", bytes.NewReader([]byte("hacked")), 6)
	assertForbidden(err, "Eve overwriting public file")

	// Eve cannot delete it
	err = eveClient.Remove(ctx, "/bob-home/public.txt")
	assertForbidden(err, "Eve deleting public file")

	// ========================================================================
	// Scenario 4: ACL read and write permission
	// ========================================================================
	err = bobClient.CreateFileExtended(ctx, "/bob-home/acl-test.txt", bytes.NewReader([]byte("acl data")), 8, MkdirOptions{
		Mode: ptr(uint32(0600)),
	})
	if err != nil {
		t.Fatalf("Bob failed to create acl test file: %v", err)
	}

	// Charlie cannot read
	_, err = getFile(charlieClient, "/bob-home/acl-test.txt")
	assertForbidden(err, "Charlie reading private file before ACL")

	// Bob grants Charlie rw access (0006)
	err = bobClient.Setfacl(ctx, "/bob-home/acl-test.txt", ACL{
		Users: map[string]uint32{charlieID: 0006},
	})
	if err != nil {
		t.Fatalf("Bob failed to setfacl: %v", err)
	}

	// Charlie can now read and overwrite
	_, err = getFile(charlieClient, "/bob-home/acl-test.txt")
	if err != nil {
		t.Fatalf("Charlie failed to read after ACL grant: %v", err)
	}
	err = charlieClient.CreateFile(ctx, "/bob-home/acl-test.txt", bytes.NewReader([]byte("charlie edit")), 12)
	if err != nil {
		t.Fatalf("Charlie failed to write after ACL grant: %v", err)
	}

	// Eve still cannot read
	_, err = getFile(eveClient, "/bob-home/acl-test.txt")
	assertForbidden(err, "Eve reading ACL file")

	// Bob grants Eve read-only access (0004)
	err = bobClient.Setfacl(ctx, "/bob-home/acl-test.txt", ACL{
		Users: map[string]uint32{charlieID: 0006, eveID: 0004},
	})
	if err != nil {
		t.Fatalf("Bob failed to setfacl for Eve: %v", err)
	}

	// Eve can read
	_, err = getFile(eveClient, "/bob-home/acl-test.txt")
	if err != nil {
		t.Fatalf("Eve failed to read after ACL grant: %v", err)
	}
	// Eve cannot write
	err = eveClient.CreateFile(ctx, "/bob-home/acl-test.txt", bytes.NewReader([]byte("eve edit")), 8)
	assertForbidden(err, "Eve writing to read-only ACL file")

	// ========================================================================
	// Scenario 5: Default ACL permission
	// ========================================================================
	acl := ACL{Users: map[string]uint32{eveID: 0006}} // Grant Eve rw for children
	err = bobClient.MkdirExtended(ctx, "/bob-home/default-acl-dir", 0750, MkdirOptions{
		DefaultACL: &acl,
		AccessACL:  &ACL{Users: map[string]uint32{eveID: 0005}}, // Grant Eve r-x for dir
	})
	if err != nil {
		t.Fatalf("Bob failed to create dir with DefaultACL: %v", err)
	}

	// Bob creates a file inside
	err = bobClient.CreateFile(ctx, "/bob-home/default-acl-dir/inherited.txt", bytes.NewReader([]byte("inherited")), 9)
	if err != nil {
		t.Fatalf("Bob failed to create file in default ACL dir: %v", err)
	}

	// Eve should be able to read and write it
	_, err = getFile(eveClient, "/bob-home/default-acl-dir/inherited.txt")
	if err != nil {
		t.Fatalf("Eve failed to read inherited file: %v", err)
	}
	err = eveClient.CreateFile(ctx, "/bob-home/default-acl-dir/inherited.txt", bytes.NewReader([]byte("eve update")), 10)
	if err != nil {
		t.Fatalf("Eve failed to overwrite inherited file: %v", err)
	}

	// Charlie should NOT be able to read it
	_, err = getFile(charlieClient, "/bob-home/default-acl-dir/inherited.txt")
	assertForbidden(err, "Charlie reading Eve's inherited file")

	// ========================================================================
	// Scenario 6: Group remove member (Transitive access removed)
	// ========================================================================
	// Bob removes Charlie from project-b
	err = bobClient.RemoveUserFromGroup(ctx, groupB.ID, charlieID)
	if err != nil {
		t.Fatalf("Bob failed to remove Charlie from group: %v", err)
	}

	// Ensure Charlie fetches fresh state
	charlieClient.ClearNodeCache()
	charlieClient.ClearMetadataCache()

	// Charlie should no longer be able to write to the shared dir
	err = charlieClient.CreateFile(ctx, "/bob-home/shared/charlie-2.txt", bytes.NewReader([]byte("rejected")), 8)
	assertForbidden(err, "Charlie writing to shared dir after removal")

	// Charlie should no longer be able to overwrite his own old file in the shared dir
	// because the group permission check in the FSM will reject him.
	err = charlieClient.CreateFile(ctx, "/bob-home/shared/charlie-renamed.txt", bytes.NewReader([]byte("rejected")), 8)
	assertForbidden(err, "Charlie overwriting group file after removal")

	// ========================================================================
	// Scenario 7: Group add member (Transitive access added)
	// ========================================================================
	// Bob adds Eve to project-b
	err = bobClient.AddUserToGroup(ctx, groupB.ID, eveID, "Eve", nil)
	if err != nil {
		t.Fatalf("Bob failed to add Eve to group: %v", err)
	}

	// Eve should now be able to read Charlie's old file
	content, err = getFile(eveClient, "/bob-home/shared/charlie-renamed.txt")
	if err != nil {
		t.Fatalf("Eve failed to read group file after being added: %v", err)
	}
	if string(content) != "charlie was here" {
		t.Fatalf("Unexpected content read by Eve: %s", string(content))
	}

	// Eve should be able to create a new file
	err = eveClient.CreateFile(ctx, "/bob-home/shared/eve-new.txt", bytes.NewReader([]byte("eve is here")), 11)
	if err != nil {
		t.Fatalf("Eve failed to write to shared dir after being added: %v", err)
	}

	// ========================================================================
	// Scenario 8: Hierarchical Group Access (Transitive)
	// ========================================================================
	// Alice (Admin) creates a group 'project-admin' owned by the 'admin' group.
	adminGID, _, _ := adminClient.ResolveGroupName(ctx, "admin")
	groupAdmin, err := adminClient.createGroupWithOptions(ctx, "project-admin", false, adminGID)
	if err != nil {
		t.Fatalf("Admin failed to create hierarchical group: %v", err)
	}
	if err := adminClient.AnchorGroupInRegistry(ctx, "project-admin", groupAdmin.ID); err != nil {
		t.Fatalf("Admin failed to anchor project-admin: %v", err)
	}

	// Bob creates a file in his home and assigns it to 'project-admin'
	// (Bob can do this if he is a member of project-admin, or if it's his file)
	// Actually, Bob needs to be in project-admin first.
	if err := adminClient.AddUserToGroup(ctx, groupAdmin.ID, bobID, "Bob", nil); err != nil {
		t.Fatalf("Admin failed to add Bob to project-admin: %v", err)
	}

	// Alice adds herself to project-admin so she can access the files
	if err := adminClient.AddUserToGroup(ctx, groupAdmin.ID, tc.AdminID, "Alice", nil); err != nil {
		t.Fatalf("Admin failed to add herself to project-admin: %v", err)
	}

	err = bobClient.CreateFileExtended(ctx, "/bob-home/admin-shared.txt", bytes.NewReader([]byte("admin eyes only")), 15, MkdirOptions{
		GroupID: groupAdmin.ID,
		Mode:    ptr(uint32(0660)),
	})
	if err != nil {
		t.Fatalf("Bob failed to create file for project-admin: %v", err)
	}

	// Bob grants project-admin group rwx access to his home dir so they can move files
	err = bobClient.Setfacl(ctx, "/bob-home", ACL{
		Groups: map[string]uint32{groupAdmin.ID: 0007},
	})
	if err != nil {
		t.Fatalf("Bob failed to setfacl for project-admin: %v", err)
	}

	// Now the Admin (Alice) should be able to read project-admin files,
	// even though she is not a direct member of project-admin.
	// She is a member of 'admin', which owns 'project-admin'.
	content, err = getFile(adminClient, "/bob-home/admin-shared.txt")
	if err != nil {
		t.Fatalf("Admin failed to read project-admin file via hierarchy: %v", err)
	}
	if string(content) != "admin eyes only" {
		t.Fatalf("Admin read wrong content via hierarchy: %s", string(content))
	}

	// Alice should also be able to rename/move files in project-admin shared dir
	err = adminClient.Rename(ctx, "/bob-home/admin-shared.txt", "/bob-home/admin-shared-moved.txt")
	if err != nil {
		t.Fatalf("Admin failed to rename file in hierarchical group: %v", err)
	}

	// Verify the move
	_, err = adminClient.OpenBlobRead(ctx, "/bob-home/admin-shared-moved.txt")
	if err != nil {
		t.Fatalf("Admin failed to read moved file: %v", err)
	}
}
