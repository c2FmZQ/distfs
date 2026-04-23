// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

func TestChallengeResponseAuth(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Node.Shutdown()
	defer tc.TS.Close()
	defer tc.Server.Shutdown()

	// 1. Create a user in FSM
	userDK, _ := crypto.GenerateEncryptionKey()
	userSK, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "test-user",
		SignKey: userSK.Public(),
		EncKey:  userDK.EncapsulationKey().Bytes(),
	}
	CreateUser(t, tc.Node, user, userSK, tc.AdminID, tc.AdminSK)

	// 2. Request Challenge
	creq := AuthChallengeRequest{UserID: user.ID}
	b, _ := json.Marshal(creq)
	resp, err := http.Post(tc.TS.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge request failed: %d", resp.StatusCode)
	}

	var cresp AuthChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&cresp); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if len(cresp.Challenge) != 32 {
		t.Fatalf("invalid challenge length: %d", len(cresp.Challenge))
	}

	// 3. Solve Challenge (Sign it)
	sig := userSK.Sign(cresp.Challenge)
	solve := AuthChallengeSolve{
		UserID:    user.ID,
		Challenge: cresp.Challenge,
		Signature: sig,
	}
	b, _ = json.Marshal(solve)

	// 4. Login
	token, secret := LoginSessionForTestWithSecret(t, tc.TS, user.ID, userSK)

	// 5. Use Session Token
	req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetUser, GetUserRequest{ID: user.ID}, user.ID, userSK, secret)
	req.Header.Set("Session-Token", token)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request failed: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestMutualRaftAuth(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	secret := "testsecret"
	nonce := []byte("fixed-nonce-for-test-32-bytes---")
	nonceHex := hex.EncodeToString(nonce)

	// 1. Valid Handshake
	req, _ := http.NewRequest("GET", tc.TS.URL+"/v1/node/info", nil)
	req.Header.Set("X-Raft-Nonce", nonceHex)
	req.Header.Set("X-Raft-Signature", tc.Server.signNonce(nonce, "LEADER_PROBE"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	nodeSig := resp.Header.Get("X-Raft-Response")
	if !tc.Server.verifySignature(nonce, "NODE_RESPONSE", nodeSig) {
		t.Error("invalid node response signature")
	}

	// 2. Invalid Leader Signature
	req, _ = http.NewRequest("GET", tc.TS.URL+"/v1/node/info", nil)
	req.Header.Set("X-Raft-Nonce", nonceHex)
	req.Header.Set("X-Raft-Signature", "wrong-sig")

	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid leader sig, got %d", resp.StatusCode)
	}

	// 3. Legacy Secret Support (Optional, depending on policy)
	req, _ = http.NewRequest("GET", tc.TS.URL+"/v1/node/info", nil)
	req.Header.Set("X-Raft-Secret", secret)

	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("legacy auth failed: %d", resp.StatusCode)
	}
}
