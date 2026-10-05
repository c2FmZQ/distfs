package data

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
)

func testSessionToken(t *testing.T, sk *crypto.IdentityKey, nonce string) (string, []byte) {
	t.Helper()
	tok := metadata.SessionToken{UserID: "u", Expiry: time.Now().Add(time.Hour).Unix(), Nonce: nonce}
	payload, _ := json.Marshal(tok)
	b, _ := json.Marshal(metadata.SignedSessionToken{Token: tok, Signature: sk.Sign(payload)})
	h := sha256.Sum256([]byte(nonce))
	return base64.StdEncoding.EncodeToString(b), h[:]
}

func testCapability(t *testing.T, sk *crypto.IdentityKey, mode string, binding []byte, chunks ...string) string {
	t.Helper()
	capB, _ := json.Marshal(metadata.CapabilityToken{
		Chunks:         chunks,
		Mode:           mode,
		Exp:            time.Now().Add(time.Hour).Unix(),
		SessionBinding: binding,
	})
	b, _ := json.Marshal(metadata.SignedAuthToken{Payload: capB, Signature: sk.Sign(capB)})
	return "Bearer " + base64.StdEncoding.EncodeToString(b)
}

// TestSecurity_SessionDeleteOnlyOwnUploads verifies that a client (session-bound)
// delete capability can only remove chunks the same session created on this node.
func TestSecurity_SessionDeleteOnlyOwnUploads(t *testing.T) {
	sk, _ := crypto.GenerateIdentityKey()
	store, _ := NewDiskStore(storage.New(t.TempDir(), nil))
	srv := httptest.NewServer(NewServer(store, sk.Public(), nil, NoopValidator{}, true, true))
	defer srv.Close()

	sessA, bindA := testSessionToken(t, sk, "session-a")
	sessB, bindB := testSessionToken(t, sk, "session-b")

	do := func(method, id, auth, sess string, body []byte) int {
		req, _ := http.NewRequest(method, srv.URL+"/v1/data/"+id, bytes.NewReader(body))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Session-Token", sess)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// A victim chunk that already exists on the node.
	victimData := []byte("victim")
	vh := sha256.Sum256(victimData)
	victim := hex.EncodeToString(vh[:])
	if err := store.WriteChunk(victim, bytes.NewReader(victimData)); err != nil {
		t.Fatal(err)
	}

	if code := do("DELETE", victim, testCapability(t, sk, "D", bindA, victim), sessA, nil); code != http.StatusUnauthorized {
		t.Fatalf("session delete of a chunk it did not create: got %d, want 401", code)
	}
	// Re-uploading an existing chunk must not make the session its creator.
	if code := do("PUT", victim, testCapability(t, sk, "W", bindA, victim), sessA, victimData); code != http.StatusCreated {
		t.Fatalf("PUT existing chunk: got %d", code)
	}
	if code := do("DELETE", victim, testCapability(t, sk, "D", bindA, victim), sessA, nil); code != http.StatusUnauthorized {
		t.Fatalf("session delete after re-upload of existing chunk: got %d, want 401", code)
	}
	if ok, _ := store.HasChunk(victim); !ok {
		t.Fatal("victim chunk was deleted")
	}

	// A chunk uploaded by session A can be cleaned up by A but not by B.
	ownData := []byte("own upload")
	oh := sha256.Sum256(ownData)
	own := hex.EncodeToString(oh[:])
	if code := do("PUT", own, testCapability(t, sk, "W", bindA, own), sessA, ownData); code != http.StatusCreated {
		t.Fatalf("PUT new chunk: got %d", code)
	}
	if code := do("DELETE", own, testCapability(t, sk, "D", bindB, own), sessB, nil); code != http.StatusUnauthorized {
		t.Fatalf("delete by another session: got %d, want 401", code)
	}

	// Creator-only reads follow the same rule.
	creatorRead := func(binding []byte, id string) string {
		capB, _ := json.Marshal(metadata.CapabilityToken{
			Chunks: []string{id}, Mode: "R", Exp: time.Now().Add(time.Hour).Unix(),
			SessionBinding: binding, CreatorOnly: true,
		})
		b, _ := json.Marshal(metadata.SignedAuthToken{Payload: capB, Signature: sk.Sign(capB)})
		return "Bearer " + base64.StdEncoding.EncodeToString(b)
	}
	if code := do("GET", own, creatorRead(bindA, own), sessA, nil); code != http.StatusOK {
		t.Fatalf("creator-only read by creating session: got %d, want 200", code)
	}
	if code := do("GET", own, creatorRead(bindB, own), sessB, nil); code != http.StatusUnauthorized {
		t.Fatalf("creator-only read by another session: got %d, want 401", code)
	}
	if code := do("GET", victim, creatorRead(bindA, victim), sessA, nil); code != http.StatusUnauthorized {
		t.Fatalf("creator-only read of a chunk the session did not create: got %d, want 401", code)
	}
	if code := do("DELETE", own, testCapability(t, sk, "D", bindA, own), sessA, nil); code != http.StatusOK {
		t.Fatalf("delete by creating session: got %d, want 200", code)
	}

	// Cluster-issued (unbound) delete capabilities, used by GC, still work.
	if code := do("DELETE", victim, testCapability(t, sk, "D", nil, victim), "", nil); code != http.StatusOK {
		t.Fatalf("cluster delete: got %d, want 200", code)
	}
}
