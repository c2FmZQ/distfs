package metadata

import (
	"net/http"
	"testing"
	"time"
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
