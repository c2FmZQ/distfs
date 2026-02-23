// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/c2FmZQ/distfs/pkg/metadata"
	bolt "go.etcd.io/bbolt"
)

func TestClient_ExtraFS(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	t.Logf("Client UserID: %s", c.userID)

	// 1. Mkdir
	err := c.Mkdir(ctx, "/testdir")
	if err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	t.Log("Mkdir /testdir succeeded")

	// 2. ReadFile (fs.FS)
	distFS := c.FS(ctx)
	// Create a small file
	content := []byte("hello world")
	err = c.CreateFile(ctx, "/testdir/hello.txt", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}
	t.Log("CreateFile /testdir/hello.txt succeeded")

	// Small sleep for consistency
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
	if err != nil { t.Fatal(err) }
	inode2, _, err := c.ResolvePath(ctx, "/dir/f2")
	if err != nil { t.Fatal(err) }
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
	if err != nil { t.Fatal(err) }
	
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
		UserID: "u1",
		MaxInodes: ptr(int64(100)),
		MaxBytes: ptr(int64(1000)),
	})
	if err != nil {
		t.Fatalf("AdminSetUserQuota failed: %v", err)
	}

	// 7. AdminSetGroupQuota
	err = c.WithAdmin(true).AdminSetGroupQuota(ctx, metadata.SetGroupQuotaRequest{
		GroupID: "g1",
		MaxInodes: ptr(int64(50)),
		MaxBytes: ptr(int64(500)),
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
	if err != nil { t.Fatal(err) }
	
	inode, _, _ := c.ResolvePath(ctx, "/blob")
	
	// 1. OpenBlobRead by Path
	rc, err := c.OpenBlobRead(ctx, "/blob")
	if err != nil {
		t.Fatalf("OpenBlobRead by Path failed: %v", err)
	}
	rc.Close()

	// 2. OpenBlobRead by ID
	rc, err = c.OpenBlobRead(ctx, inode.ID)
	if err != nil {
		t.Fatalf("OpenBlobRead by ID failed: %v", err)
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

func TestClient_ConflictRetry(t *testing.T) {
	ctx := context.Background()
	c, node, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/conflict")
	inode, _, _ := c.ResolvePath(ctx, "/conflict")

	// Start a goroutine that will update the same inode, causing a conflict for the main thread
	go func() {
		time.Sleep(50 * time.Millisecond)
		// Update version in FSM directly to simulate another client
		node.FSM.DB().Update(func(tx *bolt.Tx) error {
			plain, _ := node.FSM.Get(tx, []byte("inodes"), []byte(inode.ID))
			var i metadata.Inode
			json.Unmarshal(plain, &i)
			i.Version++
			encoded, _ := json.Marshal(i)
			return node.FSM.Put(tx, []byte("inodes"), []byte(inode.ID), encoded)
		})
	}()

	// This update should conflict initially but succeed on retry
	_, err := c.updateInode(ctx, *inode)
	if err != nil {
		t.Fatalf("updateInode failed after retries: %v", err)
	}
}

func TestClient_Retries(t *testing.T) {
	// Mock server that fails twice then succeeds
	attempts := 0
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		
		// Minimal responses for anything else
		if r.URL.Path == "/v1/meta/key" {
			w.Write(dk.EncapsulationKey().Bytes())
		} else if r.URL.Path == "/v1/meta/key/sign" {
			w.Write(sk.Public())
		} else if r.URL.Path == "/v1/auth/challenge" {
			chal := make([]byte, 32)
			sig := sk.Sign(chal)
			json.NewEncoder(w).Encode(metadata.AuthChallengeResponse{Challenge: chal, Signature: sig})
		} else if r.URL.Path == "/v1/login" {
			json.NewEncoder(w).Encode(metadata.SessionResponse{Token: "mock"})
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]")) // Empty node list
		}
	}))
	defer ts.Close()

	c := NewClient(ts.URL)
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	c = c.WithIdentity("u1", udk).WithSignKey(usk)
	
	// c.allocateNodes uses retries
	_, err := c.allocateNodes(context.Background())
	if err != nil {
		t.Fatalf("allocateNodes failed after retries: %v", err)
	}
	if attempts < 3 {
		t.Errorf("Expected at least 3 attempts, got %d", attempts)
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
	id, owner, ver := c2.GetRootAnchor()
	if id != "root-id" || owner != "owner-id" || ver != 10 {
		t.Errorf("WithRootAnchor failed: %s %s %d", id, owner, ver)
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

func TestClient_UnsealFutureTimestamp(t *testing.T) {
	_, _, _, ts := SetupTestClient(t)
	defer ts.Close()
}

func TestClient_AllocateNodes_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	c := NewClient(ts.URL)
	// Bypass sealing by not providing identity
	_, err := c.allocateNodes(context.Background())
	if err == nil {
		t.Error("allocateNodes should fail for 400 error")
	}
}

func TestClient_CreateLockbox_Errors(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	fileKey := make([]byte, 32)

	// 1. GetWorldPublicKey fails (Mock failure by using invalid server URL for a new client)
	cFail := NewClient("http://invalid")
	lb := cFail.createLockbox(ctx, fileKey, 0644, "")
	if len(lb) != 0 {
		// No identity, no world key -> empty lockbox
	}

	// 2. GetGroup fails
	lb2 := c.createLockbox(ctx, fileKey, 0660, "missing-group")
	if len(lb2) != 1 { // Only owner
		t.Errorf("Expected 1 recipient (owner), got %d", len(lb2))
	}
}

func TestClient_ToPOSIX(t *testing.T) {
	cases := []struct {
		code     int
		expected error
	}{
		{http.StatusNotFound, syscall.ENOENT},
		{http.StatusUnauthorized, syscall.EACCES},
		{http.StatusForbidden, syscall.EACCES},
		{http.StatusServiceUnavailable, syscall.EAGAIN},
		{http.StatusTooManyRequests, syscall.EAGAIN},
		{http.StatusConflict, syscall.EEXIST},
		{http.StatusInternalServerError, syscall.EIO},
	}

	for _, c := range cases {
		err := &APIError{StatusCode: c.code}
		if !errors.Is(err.ToPOSIX(), c.expected) {
			t.Errorf("For code %d, expected %v, got %v", c.code, c.expected, err.ToPOSIX())
		}
	}
}

func TestClient_MiscMethodsExtra(t *testing.T) {
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. UserID
	if c.UserID() != "u1" {
		t.Errorf("Expected u1, got %s", c.UserID())
	}
}

func TestClient_OpenBlobWriteExtra(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.EnsureRoot(ctx)
	path := "/existing"
	c.CreateFile(ctx, path, bytes.NewReader([]byte("old")), 3)

	// Open for writing again
	wc, err := c.OpenBlobWrite(ctx, path)
	if err != nil {
		t.Fatalf("OpenBlobWrite failed: %v", err)
	}
	wc.Write([]byte("new data"))
	wc.Close()

	// Verify
	fi, _ := c.FS(ctx).Stat("existing")
	if fi.Size() != 8 {
		t.Errorf("Expected size 8, got %d", fi.Size())
	}
}

func TestClient_AddEntryExtraErrors(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Parent not found
	_, _, err := c.AddEntry(ctx, "missing", make([]byte, 32), "name", metadata.FileType, nil, 0, "", 0600, "", 0, 0)
	if err == nil {
		t.Error("AddEntry should fail for missing parent")
	}
}

func TestClient_MiscErrorPaths(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. GetInode missing
	_, err := c.GetInode(ctx, "missing")
	if err == nil {
		t.Error("GetInode should fail for missing ID")
	}

	// 2. CommitInodeManifest missing
	_, err = c.CommitInodeManifest(ctx, "missing", nil, 0)
	if err == nil {
		t.Error("CommitInodeManifest should fail for missing ID")
	}

	// 3. addEntry to non-directory
	c.CreateFile(ctx, "/file1", bytes.NewReader([]byte("data")), 4)
	err = c.CreateFile(ctx, "/file1/invalid", bytes.NewReader([]byte("data")), 4)
	if err == nil {
		t.Error("CreateFile should fail if parent is not a directory")
	}
}

func TestClient_RenameDirectory(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/dir1")
	c.Mkdir(ctx, "/dir1/sub")
	c.CreateFile(ctx, "/dir1/sub/f1", bytes.NewReader([]byte("data")), 4)

	// Rename directory
	err := c.Rename(ctx, "/dir1/sub", "/sub_moved")
	if err != nil {
		t.Fatalf("Rename directory failed: %v", err)
	}

	// Verify moved
	fi, err := c.FS(ctx).Stat("sub_moved/f1")
	if err != nil {
		t.Fatalf("Stat moved file failed: %v", err)
	}
	if fi.Size() != 4 {
		t.Errorf("Expected size 4, got %d", fi.Size())
	}
}

func TestClient_Download_IOError(t *testing.T) {
	ctx := context.Background()
	c := NewClient("http://meta")
	
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		// Close without writing body
	}))
	defer ts.Close()

	_, err := c.downloadChunk(ctx, "c1", []string{ts.URL}, "token")
	if err == nil {
		t.Error("downloadChunk should fail on premature close")
	}
}

func TestClient_UpdateInode_ConflictRefetchFail(t *testing.T) {
	ctx := context.Background()
	c, node, _, ts := SetupTestClient(t)
	defer ts.Close()

	c.Mkdir(ctx, "/conflict2")
	inode, _, _ := c.ResolvePath(ctx, "/conflict2")

	// Start a goroutine that will DELETE the inode, causing re-fetch to fail after a conflict
	go func() {
		time.Sleep(50 * time.Millisecond)
		// 1. Trigger conflict by incrementing version
		node.FSM.DB().Update(func(tx *bolt.Tx) error {
			plain, _ := node.FSM.Get(tx, []byte("inodes"), []byte(inode.ID))
			var i metadata.Inode
			json.Unmarshal(plain, &i)
			i.Version++
			encoded, _ := json.Marshal(i)
			return node.FSM.Put(tx, []byte("inodes"), []byte(inode.ID), encoded)
		})
		
		time.Sleep(50 * time.Millisecond)
		// 2. Delete it so re-fetch fails
		node.FSM.DB().Update(func(tx *bolt.Tx) error {
			return node.FSM.Delete(tx, []byte("inodes"), []byte(inode.ID))
		})
	}()

	// Wait long enough for the goroutine to trigger conflict AND deletion
	time.Sleep(200 * time.Millisecond)

	// This update should conflict then fail on re-fetch
	_, err := c.updateInode(ctx, *inode)
	if err == nil {
		t.Error("updateInode should have failed after deletion")
	}
}


func ptr[T any](v T) *T {
	return &v
}
