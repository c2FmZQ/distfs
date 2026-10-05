package client

import (
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
