package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

// TestSecurity_ExpiredSessionKeyCacheEntry verifies that an expired cached
// session key falls back to the KEM path instead of crashing the server
// (previously a double RUnlock caused a fatal, unrecoverable error).
func TestSecurity_ExpiredSessionKeyCacheEntry(t *testing.T) {
	tc := SetupCluster(t)

	token, sessionKey := LoginSessionForTestWithSecret(t, tc.TS, tc.AdminID, tc.AdminSK)
	st, err := tc.Server.parseSessionToken(token)
	if err != nil {
		t.Fatalf("parseSessionToken: %v", err)
	}

	tc.Server.sessionKeyMu.Lock()
	entry, ok := tc.Server.sessionKeyCache[st.Nonce]
	if !ok {
		tc.Server.sessionKeyMu.Unlock()
		t.Fatal("session key not cached after login")
	}
	entry.expiry = time.Now().Add(-time.Minute).Unix()
	tc.Server.sessionKeyCache[st.Nonce] = entry
	tc.Server.sessionKeyMu.Unlock()

	req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetUser, GetUserRequest{ID: tc.AdminID}, tc.AdminID, tc.AdminSK, sessionKey)
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected expired cached session key to be rejected, got 200")
	}

	// The server must still be alive and serving.
	resp, err = http.Get(tc.TS.URL + "/v1/health")
	if err != nil {
		t.Fatalf("server not responding after expired session request: %v", err)
	}
	resp.Body.Close()
}

// TestSecurity_LoginRequiresDomainSeparatedSignature verifies that a raw
// signature over the challenge is rejected. Otherwise the login flow would be a
// signing oracle for arbitrary 32-byte hashes (e.g. inode ManifestHash).
func TestSecurity_LoginRequiresDomainSeparatedSignature(t *testing.T) {
	tc := SetupCluster(t)

	login := func(sign func(challenge []byte) []byte) int {
		b, _ := json.Marshal(AuthChallengeRequest{UserID: tc.AdminID})
		resp, err := http.Post(tc.TS.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		var cres AuthChallengeResponse
		json.NewDecoder(resp.Body).Decode(&cres)
		resp.Body.Close()

		sessionDK, _ := crypto.GenerateEncryptionKey()
		b, _ = json.Marshal(AuthChallengeSolve{
			UserID:    tc.AdminID,
			Challenge: cres.Challenge,
			Signature: sign(cres.Challenge),
			EncKey:    sessionDK.EncapsulationKey().Bytes(),
		})
		resp, err = http.Post(tc.TS.URL+"/v1/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := login(func(c []byte) []byte { return tc.AdminSK.Sign(c) }); code == http.StatusOK {
		t.Fatal("login accepted a raw (non domain-separated) challenge signature")
	}
	if code := login(func(c []byte) []byte { return tc.AdminSK.Sign(LoginChallengeMessage(c)) }); code != http.StatusOK {
		t.Fatalf("login with domain-separated signature failed: %d", code)
	}
}

// TestSecurity_IssueTokenModes verifies that capability tokens cannot be
// minted for chunks outside the inode's manifest or with escalated modes.
func TestSecurity_IssueTokenModes(t *testing.T) {
	tc := SetupCluster(t)

	u1 := "u1"
	usk1, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk1.Public()}, usk1, tc.AdminID, tc.AdminSK)
	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u2, UID: 1002, SignKey: usk2.Public()}, usk2, tc.AdminID, tc.AdminSK)
	token2, secret2 := LoginSessionForTestWithSecret(t, tc.TS, u2, usk2)

	readable := strings.Repeat("a", 64)
	victim := strings.Repeat("b", 64)

	// u1's world-readable file and u1's private file.
	for _, in := range []Inode{
		{ID: "world", OwnerID: u1, Type: FileType, Mode: 0644, ChunkManifest: []ChunkEntry{{ID: readable}}},
		{ID: "private", OwnerID: u1, Type: FileType, Mode: 0600, ChunkManifest: []ChunkEntry{{ID: victim}}},
	} {
		in.SignInodeForTest(u1, usk1)
		b, _ := json.Marshal(in)
		if _, err := tc.Server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, b, u1); err != nil {
			t.Fatal(err)
		}
	}

	issue := func(inodeID, mode string, chunks ...string) int {
		req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionIssueToken, map[string]any{
			"inode_id": inodeID, "mode": mode, "chunks": chunks,
		}, u2, usk2, secret2)
		req.Header.Set("Session-Token", token2)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	tests := []struct {
		name   string
		inode  string
		mode   string
		chunks []string
		ok     bool
	}{
		{"read own manifest chunk", "world", "R", []string{readable}, true},
		{"read manifest (implicit)", "world", "R", nil, true},
		{"read foreign chunk via readable inode", "world", "R", []string{victim}, false},
		{"delete via read-only inode", "world", "D", []string{victim}, false},
		{"combined mode RW", "world", "RW", []string{victim}, false},
		{"combined mode RWD", "world", "RWD", []string{victim}, false},
		{"delete without explicit chunks", "world", "D", nil, false},
		{"unknown mode", "world", "X", []string{readable}, false},
		{"delete for new inode (upload cleanup)", "new-inode", "D", []string{victim}, true},
		{"read nonexistent inode", "new-inode", "R", []string{victim}, false},
	}
	for _, tt := range tests {
		code := issue(tt.inode, tt.mode, tt.chunks...)
		if tt.ok && code != http.StatusOK {
			t.Errorf("%s: got %d, want 200", tt.name, code)
		}
		if !tt.ok && code == http.StatusOK {
			t.Errorf("%s: token issued, want rejection", tt.name)
		}
	}
}

// TestSecurity_CreateGroupCannotOverwrite verifies that CreateGroup cannot be
// used to replace an existing group (owner, keys and membership).
func TestSecurity_CreateGroupCannotOverwrite(t *testing.T) {
	tc := SetupCluster(t)

	mallory := "mallory"
	msk, _ := crypto.GenerateIdentityKey()
	mdk, _ := crypto.GenerateEncryptionKey()
	CreateUser(t, tc.Node, User{ID: mallory, UID: 1666, SignKey: msk.Public(), EncKey: mdk.EncapsulationKey().Bytes()}, msk, tc.AdminID, tc.AdminSK)

	victim, err := tc.Node.FSM.GetGroup("users")
	if err != nil {
		t.Fatalf("GetGroup(users): %v", err)
	}

	lb := crypto.NewLockbox()
	lb.AddRecipient(ComputeMemberHMAC(victim.ID, mallory), mdk.EncapsulationKey(), make([]byte, 32), 0)
	forged := Group{
		ID:       victim.ID,
		GID:      victim.GID,
		OwnerID:  SelfOwnedGroup,
		Nonce:    GenerateNonce(),
		Version:  1,
		EncKey:   mdk.EncapsulationKey().Bytes(),
		SignKey:  msk.Public(),
		SignerID: mallory,
		Lockbox:  lb,
	}
	forged.Signature = msk.Sign(forged.Hash())
	b, _ := json.Marshal(forged)
	batch, _ := json.Marshal([]LogCommand{{Type: CmdCreateGroup, Data: b, UserID: mallory}})

	if _, err := tc.Server.ApplyRaftCommandInternal(context.Background(), CmdBatch, batch, mallory); err == nil {
		t.Fatal("CreateGroup overwrote an existing group")
	}

	after, err := tc.Node.FSM.GetGroup("users")
	if err != nil {
		t.Fatal(err)
	}
	if after.SignerID != victim.SignerID || !bytes.Equal(after.SignKey, victim.SignKey) {
		t.Fatal("existing group was modified")
	}
}

// TestSecurity_ChunkPagesBoundToInode verifies that an inode cannot reference
// (and thereby delete or garbage-collect) another inode's chunk pages.
func TestSecurity_ChunkPagesBoundToInode(t *testing.T) {
	tc := SetupCluster(t)
	ctx := context.Background()

	victimID, mallory := "victim", "mallory"
	vsk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: victimID, UID: 1001, SignKey: vsk.Public()}, vsk, tc.AdminID, tc.AdminSK)
	msk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: mallory, UID: 1666, SignKey: msk.Public()}, msk, tc.AdminID, tc.AdminSK)

	// Victim file large enough to be paged.
	var manifest []ChunkEntry
	for i := 0; i < MaxChunksPerPage+1; i++ {
		manifest = append(manifest, ChunkEntry{ID: fmt.Sprintf("%064x", i)})
	}
	victimFile := Inode{ID: "victim-file", OwnerID: victimID, Type: FileType, Mode: 0600, Version: 1, ChunkManifest: manifest}
	victimFile.SignInodeForTest(victimID, vsk)
	b, _ := json.Marshal(victimFile)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdCreateInode, b, victimID); err != nil {
		t.Fatal(err)
	}
	victimPage := "victim-file:p0"

	pageExists := func() bool {
		var ok bool
		tc.Node.FSM.DB().View(func(tx *bolt.Tx) error {
			v, _ := tc.Node.FSM.Get(tx, []byte("chunk_pages"), []byte(victimPage))
			ok = v != nil
			return nil
		})
		return ok
	}
	if !pageExists() {
		t.Fatal("victim file was not paged")
	}

	// Creating an inode that references the victim's page is rejected.
	hijack := Inode{ID: "mallory-hijack", OwnerID: mallory, Type: FileType, Mode: 0600, Version: 1, ChunkPages: []string{victimPage}}
	hijack.SignInodeForTest(mallory, msk)
	b, _ = json.Marshal(hijack)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdCreateInode, b, mallory); err == nil {
		t.Error("created inode referencing another inode's chunk page")
	}

	// Updating an own inode to reference the victim's page is rejected.
	own := Inode{ID: "mallory-file", OwnerID: mallory, Type: FileType, Mode: 0600, Version: 1}
	own.SignInodeForTest(mallory, msk)
	b, _ = json.Marshal(own)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdCreateInode, b, mallory); err != nil {
		t.Fatal(err)
	}
	own.Version = 2
	own.ChunkPages = []string{victimPage}
	own.SignInodeForTest(mallory, msk)
	b, _ = json.Marshal(own)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdUpdateInode, b, mallory); err == nil {
		t.Error("updated inode to reference another inode's chunk page")
	}

	if !pageExists() {
		t.Fatal("victim chunk page was deleted")
	}
}

// TestSecurity_ChunkOwnership verifies that a user cannot list another inode's
// chunks in their own manifest (which would let GC delete them), and that the
// ownership index is rebuilt for existing data.
func TestSecurity_ChunkOwnership(t *testing.T) {
	tc := SetupCluster(t)
	ctx := context.Background()
	fsm := tc.Node.FSM

	victimID, mallory := "victim", "mallory"
	vsk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: victimID, UID: 1001, SignKey: vsk.Public()}, vsk, tc.AdminID, tc.AdminSK)
	msk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: mallory, UID: 1666, SignKey: msk.Public()}, msk, tc.AdminID, tc.AdminSK)

	victimChunk := strings.Repeat("c", 64)
	victimFile := Inode{ID: "victim-file", OwnerID: victimID, Type: FileType, Mode: 0600, Version: 1,
		ChunkManifest: []ChunkEntry{{ID: victimChunk, Nodes: []string{"n1"}}}}
	victimFile.SignInodeForTest(victimID, vsk)
	b, _ := json.Marshal(victimFile)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdCreateInode, b, victimID); err != nil {
		t.Fatal(err)
	}

	// Create with a foreign chunk is rejected.
	steal := Inode{ID: "mallory-steal", OwnerID: mallory, Type: FileType, Mode: 0600, Version: 1,
		ChunkManifest: []ChunkEntry{{ID: victimChunk, Nodes: []string{"n1"}}}}
	steal.SignInodeForTest(mallory, msk)
	b, _ = json.Marshal(steal)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdCreateInode, b, mallory); err == nil {
		t.Error("created inode with another inode's chunk")
	}

	// Update of own inode with a foreign chunk is rejected.
	own := Inode{ID: "mallory-file", OwnerID: mallory, Type: FileType, Mode: 0600, Version: 1}
	own.SignInodeForTest(mallory, msk)
	b, _ = json.Marshal(own)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdCreateInode, b, mallory); err != nil {
		t.Fatal(err)
	}
	own.Version = 2
	own.ChunkManifest = []ChunkEntry{{ID: victimChunk, Nodes: []string{"n1"}}}
	own.SignInodeForTest(mallory, msk)
	b, _ = json.Marshal(own)
	if _, err := tc.Server.ApplyRaftCommandInternal(ctx, CmdUpdateInode, b, mallory); err == nil {
		t.Error("updated inode to include another inode's chunk")
	}

	// GC never enqueues chunks the inode does not own, even if (e.g. legacy
	// data) its manifest lists them.
	fsm.DB().Update(func(tx *bolt.Tx) error {
		in := Inode{ID: "mallory-file", ChunkManifest: []ChunkEntry{{ID: victimChunk, Nodes: []string{"n1"}}}}
		fsm.enqueueGC(tx, &in)
		return nil
	})
	gcQueued := func(id string) bool {
		var ok bool
		fsm.DB().View(func(tx *bolt.Tx) error {
			v := tx.Bucket([]byte("garbage_collection")).Get([]byte(id))
			ok = v != nil
			return nil
		})
		return ok
	}
	if gcQueued(victimChunk) {
		t.Fatal("GC enqueued a chunk owned by another inode")
	}

	// The index is rebuilt from existing inodes when missing.
	fsm.DB().Update(func(tx *bolt.Tx) error {
		tx.DeleteBucket([]byte("chunk_owners"))
		return tx.Bucket([]byte("system")).Delete([]byte(chunkOwnerIndexMarker))
	})
	if err := fsm.ensureChunkOwnerIndex(); err != nil {
		t.Fatal(err)
	}
	fsm.DB().View(func(tx *bolt.Tx) error {
		owner, _ := fsm.Get(tx, []byte("chunk_owners"), []byte(victimChunk))
		if string(owner) != "victim-file" {
			t.Errorf("rebuilt owner = %q, want victim-file", owner)
		}
		return nil
	})

	// The owner's own GC still collects its chunks.
	fsm.DB().Update(func(tx *bolt.Tx) error {
		in := victimFile
		fsm.enqueueGC(tx, &in)
		return nil
	})
	if !gcQueued(victimChunk) {
		t.Fatal("GC did not enqueue a chunk owned by the inode")
	}
}
