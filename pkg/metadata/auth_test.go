// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

func TestChallengeResponseAuth(t *testing.T) {
	node, ts, _, _, _ := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create a user in FSM
	userDK, _ := crypto.GenerateEncryptionKey()
	userSK, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "test-user",
		SignKey: userSK.Public(),
		EncKey:  userDK.EncapsulationKey().Bytes(),
	}
	createUser(t, node, user)

	// 2. Request Challenge
	creq := AuthChallengeRequest{UserID: user.ID}
	b, _ := json.Marshal(creq)
	resp, err := http.Post(ts.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))
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
	resp, err = http.Post(ts.URL+"/v1/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}

	var sresp SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&sresp); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if sresp.Token == "" {
		t.Fatal("empty session token")
	}

	// 5. Use Session Token
	req, _ := http.NewRequest("GET", ts.URL+"/v1/user/"+user.ID, nil)
	req.Header.Set("Session-Token", sresp.Token)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request failed: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func createUser(t *testing.T, raftNode *RaftNode, user User) {
	userBytes, _ := json.Marshal(user)
	cmd := LogCommand{Type: CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := raftNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Create user raft apply failed: %v", err)
	}
}
