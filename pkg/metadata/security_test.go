package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
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
