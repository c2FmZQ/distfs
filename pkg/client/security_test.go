package client

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// TestSecurity_DeferredVerificationUsesObservedKeys verifies that deferred
// registry verification confirms exactly the keys that were used during the
// optimistic phase, so a malicious server cannot hand out substitute keys and
// then answer the confirmation fetch honestly.
func TestSecurity_DeferredVerificationUsesObservedKeys(t *testing.T) {
	c, node, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()
	ctx := t.Context()

	provisionUser(t, ts, node, c, adminID, adminSK, "bob")
	attackerSK, _ := crypto.GenerateIdentityKey()

	real, err := c.getUserRaw(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	forged := *real
	forged.SignKey = attackerSK.Public()

	// 1. Substitute keys for a not-yet-verified user are rejected, even though
	//    a fresh fetch would return the genuine record.
	c.invalidateUserCache("bob")
	vctx, state, _ := withVerificationState(ctx)
	if err := state.observeUser(&forged); err != nil {
		t.Fatal(err)
	}
	if err := c.processVerificationQueue(vctx, state); err == nil {
		t.Fatal("deferred verification accepted substituted keys")
	}
	c.cacheMu.RLock()
	_, cached := c.userCache["bob"]
	c.cacheMu.RUnlock()
	if cached {
		t.Fatal("substituted keys were promoted to the verified cache")
	}

	// 2. Substitute keys for an already-verified user are rejected.
	if _, err := c.getUser(ctx, "bob"); err != nil {
		t.Fatalf("getUser(bob): %v", err)
	}
	vctx, state, _ = withVerificationState(ctx)
	state.observeUser(&forged)
	if err := c.processVerificationQueue(vctx, state); err == nil {
		t.Fatal("deferred verification accepted keys differing from the verified cache")
	}

	// 3. Inconsistent keys for the same user within one operation are rejected.
	_, state, _ = withVerificationState(ctx)
	if err := state.observeUser(real); err != nil {
		t.Fatal(err)
	}
	if err := state.observeUser(&forged); err == nil {
		t.Fatal("inconsistent keys for the same user were accepted")
	}

	// 4. An inode signed with a substitute key for a verified signer is rejected.
	nonce := metadata.GenerateNonce()
	inode := &metadata.Inode{ID: metadata.GenerateInodeID("bob", nonce), Nonce: nonce, OwnerID: "bob", Type: metadata.DirType, Version: 1}
	inode.SetSignerID("bob")
	inode.ClientBlob = nil
	inode.UserSig = attackerSK.Sign(inode.ManifestHash())
	if err := c.verifyInode(ctx, inode); err == nil {
		t.Fatal("inode signed with a substitute key was accepted")
	}
}

// TestSecurity_RecipientKeysMustBeVerified verifies that file keys and group
// seeds are only encrypted to registry-verified (or out-of-band verified) keys.
func TestSecurity_RecipientKeysMustBeVerified(t *testing.T) {
	c, node, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()
	ctx := t.Context()

	provisionUser(t, ts, node, c, adminID, adminSK, "bob")

	// "unanchored" is a user record the server knows about but that no
	// registry attestation vouches for (e.g. a key injected by the server).
	msk, _ := crypto.GenerateIdentityKey()
	mdk, _ := crypto.GenerateEncryptionKey()
	metadata.CreateUser(t, node, metadata.User{ID: "unanchored", SignKey: msk.Public(), EncKey: mdk.EncapsulationKey().Bytes()}, msk, adminID, adminSK)

	payload := make([]byte, 32)
	if err := c.provisionRecipient(ctx, crypto.NewLockbox(), "unanchored", payload, nil); err == nil {
		t.Fatal("file key provisioned to an unverified recipient key")
	}
	if err := c.provisionRecipient(ctx, crypto.NewLockbox(), "bob", payload, nil); err != nil {
		t.Fatalf("provisioning a verified recipient failed: %v", err)
	}

	// Contact info whose keys differ from what the server serves is rejected.
	info, err := c.Stat(ctx, "/users")
	if err != nil {
		t.Fatal(err)
	}
	usersGID := info.Sys().(*InodeInfo).GroupID
	otherDK, _ := crypto.GenerateEncryptionKey()
	ci := &ContactInfo{UserID: "unanchored", EncKey: otherDK.EncapsulationKey().Bytes(), SignKey: msk.Public()}
	if err := c.AddUserToGroup(ctx, usersGID, "unanchored", "x", ci); err == nil {
		t.Fatal("AddUserToGroup accepted contact info that does not match the server's keys")
	}
}

// TestSecurity_AnchorBindsToConfirmedCode verifies that the registry
// attestation is only signed for the exact keys whose verification code the
// administrator confirmed, and that the code is long enough to resist grinding.
func TestSecurity_AnchorBindsToConfirmedCode(t *testing.T) {
	c, node, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()
	ctx := t.Context()

	dsk, _ := crypto.GenerateIdentityKey()
	ddk, _ := crypto.GenerateEncryptionKey()
	metadata.CreateUser(t, node, metadata.User{ID: "dave", SignKey: dsk.Public(), EncKey: ddk.EncapsulationKey().Bytes()}, dsk, adminID, adminSK)

	code, err := c.GetUserVerificationCode(ctx, "dave")
	if err != nil {
		t.Fatal(err)
	}
	if want := VerificationCode(ddk.EncapsulationKey().Bytes(), dsk.Public()); code != want {
		t.Fatalf("code = %s, want %s", code, want)
	}
	if len(code) != 39 { // 8 groups of 4 hex digits = 128 bits
		t.Fatalf("verification code %q is not 128 bits", code)
	}
	if own := c.OwnVerificationCode(); own != VerificationCode(c.decKey.EncapsulationKey().Bytes(), c.signKey.Public()) {
		t.Fatalf("OwnVerificationCode mismatch: %s", own)
	}

	// A code for different keys (the server switched keys after the check).
	otherDK, _ := crypto.GenerateEncryptionKey()
	stale := VerificationCode(otherDK.EncapsulationKey().Bytes(), dsk.Public())
	if err := c.AnchorUserInRegistryWithCode(ctx, "dave", "dave", adminID, stale); err == nil {
		t.Fatal("anchored keys that do not match the confirmed code")
	}
	if err := c.AnchorUserInRegistryWithCode(ctx, "dave", "dave", adminID, code); err != nil {
		t.Fatalf("anchoring with the confirmed code failed: %v", err)
	}
}

// replayTransport records the server's response to the next request and can
// replay it in place of the response to a later request, simulating a server
// that answers with a different (validly signed) object than requested.
type replayTransport struct {
	base     http.RoundTripper
	mu       sync.Mutex
	record   bool
	recorded *http.Response
	body     []byte
	replay   bool
}

func (r *replayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	replay := r.replay && r.recorded != nil && req.URL.Path == "/v1/invoke"
	r.mu.Unlock()
	if replay {
		resp := *r.recorded
		resp.Header = r.recorded.Header.Clone()
		resp.Body = io.NopCloser(bytes.NewReader(r.body))
		resp.Request = req
		return &resp, nil
	}
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.record && req.URL.Path == "/v1/invoke" {
		r.body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(r.body))
		rec := *resp
		r.recorded = &rec
		r.record = false
	}
	return resp, nil
}

// TestSecurity_InodeSubstitution verifies that the client rejects a validly
// signed inode returned in place of the requested one.
func TestSecurity_InodeSubstitution(t *testing.T) {
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()
	ctx := t.Context()

	if err := c.saveDataFile(ctx, "/x", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := c.saveDataFile(ctx, "/y", []byte("attacker-chosen")); err != nil {
		t.Fatal(err)
	}
	x, _, err := c.resolvePath(ctx, "/x")
	if err != nil {
		t.Fatal(err)
	}
	y, _, err := c.resolvePath(ctx, "/y")
	if err != nil {
		t.Fatal(err)
	}

	rt := &replayTransport{base: c.httpCli.Transport}
	if rt.base == nil {
		rt.base = http.DefaultTransport
	}
	c.httpCli.Transport = rt

	rt.record = true
	if _, err := c.getInodeInternal(ctx, y.ID, true); err != nil {
		t.Fatalf("fetch y: %v", err)
	}
	rt.mu.Lock()
	rt.replay = true
	rt.mu.Unlock()

	if got, err := c.getInodeInternal(ctx, x.ID, true); err == nil {
		t.Fatalf("accepted inode %s in place of requested %s", got.ID, x.ID)
	}
}
