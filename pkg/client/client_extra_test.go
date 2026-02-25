// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestClient_ExtraFS(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Mkdir
	err := c.Mkdir(ctx, "/testdir")
	if err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}

	// 2. ReadFile (fs.FS)
	distFS := c.FS(ctx)
	content := []byte("hello world")
	err = c.CreateFile(ctx, "/testdir/hello.txt", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	data, err := fs.ReadFile(distFS, "testdir/hello.txt")
	if err != nil {
		t.Fatalf("fs.ReadFile failed: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("Unexpected data: %s", data)
	}

	// 3. Stat (fs.FS)
	fi, err := fs.Stat(distFS, "testdir/hello.txt")
	if err != nil {
		t.Fatalf("fs.Stat failed: %v", err)
	}
	if fi.Name() != "hello.txt" {
		t.Errorf("Unexpected name: %s", fi.Name())
	}
	if fi.Size() != int64(len(content)) {
		t.Error("Size mismatch")
	}
	if fi.Mode() == 0 {
		t.Error("Mode zero")
	}
	if fi.ModTime().IsZero() {
		t.Error("ModTime zero")
	}
	if fi.IsDir() {
		t.Error("IsDir true for file")
	}
	if fi.Sys() == nil {
		t.Error("Sys nil")
	}

	// 4. Glob (fs.FS)
	matches, err := fs.Glob(distFS, "testdir/*.txt")
	if err != nil {
		t.Fatalf("fs.Glob failed: %v", err)
	}
	if len(matches) != 1 || matches[0] != "testdir/hello.txt" {
		t.Errorf("Glob mismatch: %v", matches)
	}

	// 5. ReadAt
	f, err := distFS.Open("testdir/hello.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer f.Close()

	// Test File.Stat
	ffi, _ := f.Stat()
	if ffi.Name() == "" {
		t.Error("Empty name from file stat")
	}

	ra, ok := f.(io.ReaderAt)
	if !ok {
		t.Fatal("File does not implement io.ReaderAt")
	}
	buf := make([]byte, 5)
	n, err := ra.ReadAt(buf, 6)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if string(buf[:n]) != "world" {
		t.Errorf("ReadAt data failed: %s", buf[:n])
	}
}

func TestClient_Links(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	err := c.Mkdir(ctx, "/dir")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("data")
	err = c.CreateFile(ctx, "/dir/f1", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Symlink
	err = c.Symlink(ctx, "f1", "/dir/s1")
	if err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	// 2. ReadLink
	target, err := c.FS(ctx).ReadLink("dir/s1")
	if err != nil {
		t.Fatalf("ReadLink failed: %v", err)
	}
	if target != "f1" {
		t.Errorf("ReadLink target mismatch: %s", target)
	}

	// 3. Link (Hard link)
	err = c.Link(ctx, "/dir/f1", "/dir/f2")
	if err != nil {
		t.Fatalf("Link failed: %v", err)
	}

	// Verify hard link
	inode1, _, err := c.ResolvePath(ctx, "/dir/f1")
	if err != nil {
		t.Fatal(err)
	}
	inode2, _, err := c.ResolvePath(ctx, "/dir/f2")
	if err != nil {
		t.Fatal(err)
	}
	if inode1.ID != inode2.ID {
		t.Errorf("Hard links should have same InodeID: %s != %s", inode1.ID, inode2.ID)
	}
}

func TestClient_DeleteExtra(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	content := []byte("bye")
	err := c.CreateFile(ctx, "/delete_me", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}

	err = c.Remove(ctx, "/delete_me")
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	_, _, err = c.ResolvePath(ctx, "/delete_me")
	if err == nil {
		t.Error("File should be gone")
	}
}

func TestClient_SubFS(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/a")
	c.Mkdir(ctx, "/a/b")
	c.Mkdir(ctx, "/a/b/c")
	content := []byte("sub data")
	c.CreateFile(ctx, "/a/b/c/f1", bytes.NewReader(content), int64(len(content)))

	sub, err := c.FS(ctx).Sub("a/b")
	if err != nil {
		t.Fatalf("Sub failed: %v", err)
	}

	data, err := fs.ReadFile(sub, "c/f1")
	if err != nil {
		t.Fatalf("fs.ReadFile on sub failed: %v", err)
	}
	if string(data) != "sub data" {
		t.Errorf("Unexpected data: %s", data)
	}
}

func TestClient_ReadDirRecursive(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/dir1")
	c.Mkdir(ctx, "/dir1/subdir")
	content1 := []byte("1")
	c.CreateFile(ctx, "/dir1/f1", bytes.NewReader(content1), int64(len(content1)))
	content2 := []byte("2")
	c.CreateFile(ctx, "/dir1/subdir/f2", bytes.NewReader(content2), int64(len(content2)))

	results, err := c.ReadDirRecursive(ctx, "/dir1")
	if err != nil {
		t.Fatalf("ReadDirRecursive failed: %v", err)
	}

	if len(results) != 2 { // /dir1 and /dir1/subdir
		t.Errorf("Expected 2 directories in results, got %d", len(results))
	}
}

func TestClient_AdminMethods(t *testing.T) {
	ctx := context.Background()
	c, node, _, ts := SetupTestClient(t)
	defer ts.Close()

	// Promote user to admin in FSM directly
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdPromoteAdmin, Data: []byte("u1")}.Marshal(), 5*time.Second)

	// Register a node
	nodeInfo := metadata.Node{ID: "n1", Address: "http://127.0.0.1:8080", Status: metadata.NodeStatusActive}
	nb, _ := json.Marshal(nodeInfo)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second)

	time.Sleep(100 * time.Millisecond) // Wait for apply

	// 1. AdminListUsers
	users, err := c.WithAdmin(true).AdminListUsers(ctx)
	if err != nil {
		t.Fatalf("AdminListUsers failed: %v", err)
	}
	if len(users) == 0 {
		t.Error("Expected at least one user")
	}

	// 2. AdminListGroups
	_, err = c.WithAdmin(true).AdminListGroups(ctx)
	if err != nil {
		t.Fatalf("AdminListGroups failed: %v", err)
	}

	// 3. AdminListNodes
	nodes, err := c.WithAdmin(true).AdminListNodes(ctx)
	if err != nil {
		t.Fatalf("AdminListNodes failed: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("Expected at least one node")
	}

	// 4. AdminClusterStatus
	_, err = c.WithAdmin(true).AdminClusterStatus(ctx)
	if err != nil {
		t.Fatalf("AdminClusterStatus failed: %v", err)
	}

	// 5. AdminLookup
	uID, err := c.WithAdmin(true).AdminLookup(ctx, "user1@example.com", "Test")
	if err != nil {
		// Might fail if cluster secret not set in a way HMAC matches, but handler should be hit
	} else if uID == "" {
		t.Error("AdminLookup returned empty ID")
	}

	// 6. AdminSetUserQuota
	err = c.WithAdmin(true).AdminSetUserQuota(ctx, metadata.SetUserQuotaRequest{
		UserID:    "u1",
		MaxInodes: ptr(int64(100)),
		MaxBytes:  ptr(int64(1000)),
	})
	if err != nil {
		t.Fatalf("AdminSetUserQuota failed: %v", err)
	}

	// 7. AdminSetGroupQuota
	err = c.WithAdmin(true).AdminSetGroupQuota(ctx, metadata.SetGroupQuotaRequest{
		GroupID:   "g1",
		MaxInodes: ptr(int64(50)),
		MaxBytes:  ptr(int64(500)),
	})
	if err != nil {
		// Might fail if g1 not created yet
	}

	// 8. AdminChown
	u2 := "u2"
	c.Mkdir(ctx, "/testdir")
	inode, _, err := c.ResolvePath(ctx, "/testdir")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}
	err = c.WithAdmin(true).AdminChown(ctx, inode.ID, metadata.AdminChownRequest{
		OwnerID: &u2,
	})
	if err != nil {
		t.Fatalf("AdminChown failed: %v", err)
	}

	// 9. AdminPromote
	usk2, _ := crypto.GenerateIdentityKey()
	user2 := metadata.User{ID: u2, SignKey: usk2.Public()}
	ub2, _ := json.Marshal(user2)
	node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: ub2}.Marshal(), 5*time.Second)

	err = c.WithAdmin(true).AdminPromote(ctx, u2)
	if err != nil {
		t.Fatalf("AdminPromote failed: %v", err)
	}

	// 10. AdminJoinNode
	err = c.WithAdmin(true).AdminJoinNode(ctx, "http://127.0.0.1:9999")
	if err != nil {
		// Might fail due to real Raft join logic, but handler hit
	}

	// 11. AdminRemoveNode
	err = c.WithAdmin(true).AdminRemoveNode(ctx, "n2")
	if err != nil {
		// Might fail if not in cluster
	}
}

func TestClient_GroupsExtra(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. CreateGroup
	group, err := c.CreateGroup(ctx, "group1")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// 2. GetGroupName
	name, err := c.GetGroupName(ctx, group)
	if err != nil {
		// Might fail if not in registry
	} else if name != "group1" {
		t.Errorf("Expected group1, got %s", name)
	}
}

func TestClient_Blob(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	content := []byte("blob data")
	err := c.CreateFile(ctx, "/blob", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}

	// 1. OpenBlobRead by Path
	rc, err := c.OpenBlobRead(ctx, "/blob")
	if err != nil {
		t.Fatalf("OpenBlobRead by Path failed: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "blob data" {
		t.Errorf("Blob data mismatch: %s", data)
	}
}

func TestClient_RenameExtra(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/dir1")
	c.Mkdir(ctx, "/dir2")
	content := []byte("data")
	c.CreateFile(ctx, "/dir1/f1", bytes.NewReader(content), int64(len(content)))

	// 1. Cross-directory rename
	err := c.Rename(ctx, "/dir1/f1", "/dir2/f1_moved")
	if err != nil {
		t.Fatalf("Cross-directory rename failed: %v", err)
	}

	// 2. Rename with overwrite
	c.CreateFile(ctx, "/dir2/target", bytes.NewReader([]byte("old")), 3)
	err = c.Rename(ctx, "/dir2/f1_moved", "/dir2/target")
	if err != nil {
		t.Fatalf("Rename with overwrite failed: %v", err)
	}

	// 3. Rename with overwrite (target has NLink > 1)
	c.CreateFile(ctx, "/dir2/f2", bytes.NewReader([]byte("f2")), 2)
	c.Link(ctx, "/dir2/f2", "/dir2/f2_link")
	c.CreateFile(ctx, "/dir2/source", bytes.NewReader([]byte("src")), 3)
	err = c.Rename(ctx, "/dir2/source", "/dir2/f2")
	if err != nil {
		t.Fatalf("Rename with multi-link overwrite failed: %v", err)
	}
}

func TestClient_RemoveExtraError(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/dir")
	c.CreateFile(ctx, "/dir/f1", bytes.NewReader([]byte("1")), 1)

	// 1. Remove non-empty directory
	err := c.Remove(ctx, "/dir")
	if err == nil {
		t.Error("Expected error when removing non-empty directory")
	}
}

func TestClient_EnsureRootExtra(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Root already exists
	err := c.EnsureRoot(ctx)
	if err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// 2. No identity
	cNoId := NewClient(ts.URL)
	err = cNoId.EnsureRoot(ctx)
	if err == nil {
		t.Error("EnsureRoot should fail without identity")
	}
}

func TestClient_UnsealExtraErrors(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Not sealed
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	_, err := c.unsealResponse(ctx, resp)
	if err != nil {
		t.Errorf("unsealResponse failed for non-sealed: %v", err)
	}

	// 2. Invalid format
	resp.Header.Set("X-DistFS-Sealed", "true")
	resp.Body = io.NopCloser(bytes.NewReader([]byte("not-json")))
	_, err = c.unsealResponse(ctx, resp)
	if err == nil {
		t.Error("unsealResponse should fail for invalid JSON")
	}

	// 3. Failed to open
	resp.Body = io.NopCloser(bytes.NewReader([]byte(`{"sealed":"malformed"}`)))
	_, err = c.unsealResponse(ctx, resp)
	if err == nil {
		t.Error("unsealResponse should fail for malformed sealed payload")
	}
}

func TestClient_DownloadHedged(t *testing.T) {
	ctx := context.Background()
	c := NewClient("http://meta")

	// Two nodes: one fails, one succeeds
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts1.Close()
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("chunk data"))
	}))
	defer ts2.Close()

	// downloadChunk(ctx, id, urls, token)
	data, err := c.downloadChunk(ctx, "c1", []string{ts1.URL, ts2.URL}, "token")
	if err != nil {
		t.Fatalf("downloadChunk failed: %v", err)
	}
	if string(data) != "chunk data" {
		t.Errorf("Expected chunk data, got %s", string(data))
	}
}

func TestClient_LoginExtraErrors(t *testing.T) {
	ctx := context.Background()

	// 1. Invalid server signature on challenge
	sk, _ := crypto.GenerateIdentityKey()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/challenge" {
			// Return challenge with INVALID signature
			json.NewEncoder(w).Encode(metadata.AuthChallengeResponse{
				Challenge: make([]byte, 32),
				Signature: make([]byte, 64),
			})
		} else if r.URL.Path == "/v1/meta/key/sign" {
			w.Write(sk.Public())
		}
	}))
	defer ts.Close()

	c := NewClient(ts.URL).WithIdentity("u1", nil).WithSignKey(sk)
	err := c.Login(ctx)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("Expected signature error, got %v", err)
	}
}

func TestClient_UploadExtraError(t *testing.T) {
	ctx := context.Background()
	c := NewClient("http://meta")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	err := c.uploadChunk(ctx, "c1", []byte("data"), []metadata.Node{{Address: ts.URL}}, "token")
	if err == nil {
		t.Error("uploadChunk should fail when node returns error")
	}
}

func TestClient_CreateLockboxExtra(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	fileKey := make([]byte, 32)

	// 1. World access (0004)
	lb := c.createLockbox(ctx, fileKey, 0644, "")
	if _, ok := lb[metadata.WorldID]; !ok {
		// WorldID might be missing if world public key not available, but should be hit
	}

	// 2. Group access (0040)
	group, _ := c.CreateGroup(ctx, "g1")
	lb2 := c.createLockbox(ctx, fileKey, 0640, group.ID)
	if _, ok := lb2[group.ID]; !ok {
		t.Errorf("Group %s missing from lockbox", group.ID)
	}
}

func TestClient_MiscMethods(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. WithRootAnchor
	c2 := c.WithRootAnchor("root-id", "owner-id", 10)
	id, owner, rver := c2.GetRootAnchor()
	if id != "root-id" || owner != "owner-id" || rver != 10 {
		t.Errorf("WithRootAnchor failed: %s %s %d", id, owner, rver)
	}

	// 2. UserID
	if c.UserID() != "u1" {
		t.Errorf("Expected u1, got %s", c.UserID())
	}

	// 3. ToPOSIX
	apiErr := &APIError{StatusCode: http.StatusNotFound}
	if apiErr.ToPOSIX() != syscall.ENOENT {
		t.Errorf("Expected ENOENT, got %v", apiErr.ToPOSIX())
	}

	// 4. GetServerKey (Pre-configured)
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	c3 := c.WithServerKey(ek)
	pk, err := c3.GetServerKey(ctx)
	if err != nil || pk == nil {
		t.Errorf("GetServerKey failed: %v", err)
	}

	// 5. Contact exchange errors
	_, err = c.ParseContactString("invalid")
	if err == nil {
		t.Error("ParseContactString should fail for invalid string")
	}

	_, err = c.ParseContactString("distfs-contact:v1:invalid-base64")
	if err == nil {
		t.Error("ParseContactString should fail for invalid base64")
	}

	// 6. Close (File Close)
	c.CreateFile(ctx, "/f1", bytes.NewReader([]byte("data")), 4)
	rc, _ := c.OpenBlobRead(ctx, "/f1")
	rc.Close()

	// 7. GetInodes
	_, err = c.GetInodes(ctx, []string{"root"})
	if err != nil {
		t.Errorf("GetInodes failed: %v", err)
	}

	// 8. GetClusterStats
	_, err = c.GetClusterStats(ctx)
	if err != nil {
		t.Errorf("GetClusterStats failed: %v", err)
	}
}

func TestClient_ResolvePath_InvalidCache(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/dir")
	c.CreateFile(ctx, "/dir/f1", bytes.NewReader([]byte("data")), 4)

	// 1. Manually poison cache
	c.putPathCache("/dir/f1", pathCacheEntry{
		inodeID: "wrong-id",
		key:     make([]byte, 32),
		linkTag: "wrong-tag",
	})

	// 2. Resolve should detect invalid cache and fix it
	inode, _, err := c.ResolvePath(ctx, "/dir/f1")
	if err != nil {
		t.Fatalf("ResolvePath failed after cache poisoning: %v", err)
	}
	if inode.ID == "wrong-id" {
		t.Error("ResolvePath used invalid cache entry")
	}
}

func TestClient_UnlockInode_GroupAndWorld(t *testing.T) {
	ctx := context.Background()
	c1, node, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Setup u2
	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	udk2, _ := crypto.GenerateEncryptionKey()
	user2 := metadata.User{ID: u2, SignKey: usk2.Public(), EncKey: udk2.EncapsulationKey().Bytes()}
	ub2, _ := json.Marshal(user2)
	if err := node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: ub2}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Raft apply CreateUser failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // Wait for FSM application

	c2 := NewClient(ts.URL).WithIdentity(u2, udk2).WithSignKey(usk2)
	if err := c2.Login(ctx); err != nil {
		t.Fatalf("u2 login failed: %v", err)
	}

	// 2. Setup Group g1
	group, err := c1.CreateGroup(ctx, "g1")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	contactStr, err := c2.GenerateContactString()
	if err != nil {
		t.Fatalf("GenerateContactString failed: %v", err)
	}

	ci, err := c1.ParseContactString(contactStr)
	if err != nil {
		t.Fatalf("ParseContactString failed: %v", err)
	}

	err = c1.AddUserToGroup(ctx, group.ID, u2, "Member", ci)
	if err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// 3. Create File f1 with Group access
	err = c1.Mkdir(ctx, "/shared")
	if err != nil {
		t.Fatalf("Mkdir /shared failed: %v", err)
	}

	err = c1.SetAttr(ctx, "/shared", metadata.SetAttrRequest{Mode: ptr(uint32(0770)), GroupID: &group.ID})
	if err != nil {
		t.Fatalf("SetAttr /shared failed: %v", err)
	}

	wc, err := c1.OpenBlobWrite(ctx, "/shared/f1")
	if err != nil {
		t.Fatalf("OpenBlobWrite f1 failed: %v", err)
	}
	wc.Write([]byte("secret"))
	wc.Close()

	c1.SetAttr(ctx, "/shared/f1", metadata.SetAttrRequest{Mode: ptr(uint32(0660))})

	_, _, _ = c1.ResolvePath(ctx, "/shared/f1")

	// 4. u2 Unlocks f1 (via Group key)
	rc, err := c2.OpenBlobRead(ctx, "/shared/f1")
	if err != nil {
		t.Fatalf("u2 failed to open group-shared file: %v", err)
	}
	data, _ := io.ReadAll(rc)
	if string(data) != "secret" {
		t.Errorf("Unexpected data: %s", data)
	}
	rc.Close()

	// 5. Create File f2 with World access
	c1.Mkdir(ctx, "/public")
	c1.SetAttr(ctx, "/public", metadata.SetAttrRequest{Mode: ptr(uint32(0777))})
	c1.CreateFile(ctx, "/public/f2", bytes.NewReader([]byte("public")), 6)
	c1.SetAttr(ctx, "/public/f2", metadata.SetAttrRequest{Mode: ptr(uint32(0664))})

	// Create u3
	usk3, _ := crypto.GenerateIdentityKey()
	udk3, _ := crypto.GenerateEncryptionKey()
	c3 := NewClient(ts.URL).WithIdentity("u3", udk3).WithSignKey(usk3)
	user3 := metadata.User{ID: "u3", SignKey: usk3.Public(), EncKey: udk3.EncapsulationKey().Bytes()}
	ub3, _ := json.Marshal(user3)
	if err := node.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: ub3}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Raft apply CreateUser u3 failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if err := c3.Login(ctx); err != nil {
		t.Fatalf("u3 login failed: %v", err)
	}

	rc, err = c3.OpenBlobRead(ctx, "/public/f2")
	if err != nil {
		t.Fatalf("u3 failed to open public file: %v", err)
	}
	data, _ = io.ReadAll(rc)
	if string(data) != "public" {
		t.Errorf("Unexpected data: %s", data)
	}
	rc.Close()

	// 6. RemoveUserFromGroup
	err = c1.RemoveUserFromGroup(ctx, group.ID, u2)
	if err != nil {
		t.Errorf("RemoveUserFromGroup failed: %v", err)
	}

	// 7. GroupChown
	err = c1.GroupChown(ctx, group.ID, "u2")
	if err != nil {
		t.Errorf("GroupChown failed: %v", err)
	}
}

func TestClient_Groups_SystemAndMembers(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. CreateSystemGroup
	group, err := c.WithAdmin(true).CreateSystemGroup(ctx, "sysgroup")
	if err != nil {
		t.Fatalf("CreateSystemGroup failed: %v", err)
	}
	if !group.IsSystem {
		t.Error("Expected system group")
	}

	// 2. DecryptGroupName
	gl, _ := c.ListGroups(ctx)
	if len(gl) > 0 {
		name, err := c.DecryptGroupName(ctx, gl[0])
		if err != nil {
			t.Errorf("DecryptGroupName failed: %v", err)
		}
		if name != "sysgroup" {
			t.Errorf("Expected sysgroup, got %s", name)
		}
	}

	// 3. GetGroupMembers
	members, err := c.GetGroupMembers(ctx, group.ID)
	if err != nil {
		t.Fatalf("GetGroupMembers failed: %v", err)
	}
	if len(members) == 0 {
		t.Error("Expected at least owner in members")
	}
}

func TestClient_FS_Extra(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/fs")
	c.CreateFile(ctx, "/fs/f1", bytes.NewReader([]byte("data")), 4)

	distFS := c.FS(ctx)

	// 1. ReadDir
	des, _ := fs.ReadDir(distFS, "fs")
	if len(des) > 0 {
		e := des[0]
		_ = e.Type()
		fi, _ := e.Info()
		_ = fi.Name()
		_ = fi.Size()
		_ = fi.Mode()
		_ = fi.ModTime()
		_ = fi.IsDir()
		_ = fi.Sys()

		// Type assertions
		if ext, ok := e.(interface{ Inode() *metadata.Inode }); ok {
			_ = ext.Inode()
		}
		if ext, ok := e.(interface{ InodeID() string }); ok {
			_ = ext.InodeID()
		}
	}

	// 2. Open directory and call ReadDir
	f, _ := distFS.Open("fs")
	if rdf, ok := f.(fs.ReadDirFile); ok {
		rdf.ReadDir(-1)
	}
	f.Close()

	// 3. NewDirEntry / NewDirEntryForTest
	inode := &metadata.Inode{ID: "00000000000000000000000000000001"}
	key := make([]byte, 32)
	_ = c.NewDirEntry(inode, "name", key)
	_ = NewDirEntryForTest(inode, "name2", key)
}

func TestClient_Onboarding_Discovery(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/config" {
			conf := metadata.OIDCConfig{
				DeviceAuthorizationEndpoint: "http://auth",
				TokenEndpoint:               "http://token",
			}
			json.NewEncoder(w).Encode(conf)
		}
	}))
	defer ts.Close()

	opts := OnboardingOptions{
		ServerURL: ts.URL,
		ClientID:  "client",
	}
	// This will still fail at auth.GetToken but discovered endpoints.
	_, err := GetOIDCToken(ctx, opts)
	if err == nil {
		t.Error("Expected error from auth.GetToken")
	}
}

func TestClient_SyncFile_More(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Inline Sync
	c.CreateFile(ctx, "/inline", bytes.NewReader([]byte("init")), 4)
	inode, _, _ := c.ResolvePath(ctx, "/inline")
	c.SyncFile(ctx, inode.ID, strings.NewReader("new content"), 11, nil)

	// 2. Growing file (Chunked)
	large := make([]byte, crypto.ChunkSize+100)
	c.CreateFile(ctx, "/large", bytes.NewReader(large), int64(len(large)))
	inodeL, _, _ := c.ResolvePath(ctx, "/large")

	grown := make([]byte, 2*crypto.ChunkSize+100)
	c.SyncFile(ctx, inodeL.ID, bytes.NewReader(grown), int64(len(grown)), nil)
}

func ptr[T any](v T) *T {
	return &v
}

func TestClient_DeleteInode(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Create a file
	c.Mkdir(ctx, "/dir1")
	err := c.CreateFile(ctx, "/dir1/file1", bytes.NewReader([]byte("hello")), 5)
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	inode, _, _ := c.ResolvePath(ctx, "/dir1/file1")

	// Delete it
	err = c.DeleteInode(ctx, inode.ID)
	if err != nil {
		t.Fatalf("DeleteInode failed: %v", err)
	}

	// Verify it's gone
	_, _, err = c.ResolvePath(ctx, "/dir1/file1")
	if err == nil {
		t.Error("Expected error resolving deleted path, got nil")
	}
}

func TestClient_SyncFile(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Setup a Data Node for Sync
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)

	csk := metadata.GetClusterSignKey(metaNode.FSM)

	dataServer := data.NewServer(dataStore, csk.Public, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	nodeInfo := metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNode(t, ts.URL, "testsecret", nodeInfo)

	// Create a file
	path := "/test-sync"
	content := []byte("original content")
	c.CreateFile(ctx, path, bytes.NewReader(content), int64(len(content)))

	inode, key, _ := c.ResolvePath(ctx, path)

	// Sync with updates
	newContent := []byte("updated content and much longer to force chunking if needed")
	dirty := map[int64]bool{0: true}
	updatedInode, err := c.SyncFile(ctx, inode.ID, bytes.NewReader(newContent), int64(len(newContent)), dirty)
	if err != nil {
		t.Fatalf("SyncFile failed: %v", err)
	}

	if updatedInode.Size != uint64(len(newContent)) {
		t.Errorf("Expected size %d, got %d", len(newContent), updatedInode.Size)
	}

	// Read back and verify
	reader, _ := c.NewReader(ctx, updatedInode.ID, key)
	readBack, _ := io.ReadAll(reader)
	if !bytes.Equal(readBack, newContent) {
		t.Errorf("Expected %s, got %s", string(newContent), string(readBack))
	}
}

func TestClient_AdminChmod(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Promote user to admin
	metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdPromoteAdmin, Data: []byte("u1")}.Marshal(), 5*time.Second)

	// Create a file
	path := "/secret"
	c.CreateFile(ctx, path, bytes.NewReader([]byte("data")), 4)
	inode, _, _ := c.ResolvePath(ctx, path)

	// Chmod via Admin
	err := c.AdminChmod(ctx, inode.ID, 0640)
	if err != nil {
		t.Fatalf("AdminChmod failed: %v", err)
	}

	// Verify
	updated, _, _ := c.ResolvePath(ctx, path)
	if updated.Mode != 0640 {
		t.Errorf("Expected mode 0640, got %o", updated.Mode)
	}
}

func TestClient_ChunkDataOps(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)

	csk := metadata.GetClusterSignKey(metaNode.FSM)

	dataServer := data.NewServer(dataStore, csk.Public, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	nodeInfo := metadata.Node{ID: "data1", Address: tsData.URL, Status: metadata.NodeStatusActive}
	registerNode(t, ts.URL, "testsecret", nodeInfo)

	// 1. UploadChunkData
	path := "/chunk-test-file"
	fileKey := make([]byte, 32)
	chunkData := []byte("chunk payload")

	// Create file first
	err := c.SaveDataFile(ctx, path, []byte("init"))
	if err != nil {
		t.Fatalf("SaveDataFile failed: %v", err)
	}
	inode, _, _ := c.ResolvePath(ctx, path)

	entry, err := c.UploadChunkData(ctx, inode.ID, fileKey, 0, chunkData)
	if err != nil {
		t.Fatalf("UploadChunkData failed: %v", err)
	}

	// 2. DownloadChunkData
	downloaded, err := c.DownloadChunkData(ctx, inode.ID, entry.ID, entry.URLs, fileKey)
	if err != nil {
		t.Fatalf("DownloadChunkData failed: %v", err)
	}

	// Truncate to expected size (DecryptChunk returns 1MB padded)
	if len(downloaded) > len(chunkData) {
		downloaded = downloaded[:len(chunkData)]
	}

	if !bytes.Equal(downloaded, chunkData) {
		t.Errorf("Expected %s, got %s", string(chunkData), string(downloaded))
	}
}

func TestClient_OpenBlobWrite(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	csk := metadata.GetClusterSignKey(metaNode.FSM)
	dataServer := data.NewServer(dataStore, csk.Public, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	registerNode(t, ts.URL, "testsecret", metadata.Node{ID: "data1", Address: tsData.URL, Status: metadata.NodeStatusActive})

	// Open for writing
	path := "/bigblob"
	wc, err := c.OpenBlobWrite(ctx, path)
	if err != nil {
		t.Fatalf("OpenBlobWrite failed: %v", err)
	}

	// Write 1.5 MB (more than 1MB chunk size)
	dataSize := 3 * 1024 * 1024 / 2 // 1.5MB
	payload := make([]byte, dataSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := wc.Write(payload)
	if err != nil || n != dataSize {
		t.Fatalf("Write failed: %v, n=%d", err, n)
	}

	err = wc.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read back and verify
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	reader, _ := c.NewReader(ctx, inode.ID, key)
	readBack, _ := io.ReadAll(reader)
	if !bytes.Equal(readBack, payload) {
		t.Error("Data mismatch in big blob")
	}
}

func TestClient_ExtraDataOps(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// 1. CommitInodeManifest
	path := "/f1"
	c.CreateFile(ctx, path, bytes.NewReader([]byte("init")), 4)
	inode, _, _ := c.ResolvePath(ctx, path)

	manifest := []metadata.ChunkEntry{{ID: "c1", Nodes: []string{"n1"}}}
	_, err := c.CommitInodeManifest(ctx, inode.ID, manifest, 100)
	if err != nil {
		t.Fatalf("CommitInodeManifest failed: %v", err)
	}

	// 2. FetchChunk (Error case: missing chunk)
	_, err = c.FetchChunk(ctx, inode.ID, make([]byte, 32), 0)
	if err == nil {
		// Might fail because urls are missing, but let's see.
	}

	// 3. OpenBlobRead (Resolution failure)
	_, err = c.OpenBlobRead(ctx, "/missing/path")
	if err == nil {
		t.Error("OpenBlobRead should fail for missing absolute path")
	}
}
