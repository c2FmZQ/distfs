package metadata

import (
	"bytes"
	"encoding/json"
	"net/http"
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
