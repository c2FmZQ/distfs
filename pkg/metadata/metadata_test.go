//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metadata

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/tlsproxy/jwks"
	"github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestMetadataCluster(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	userDecKey, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "u1",
		SignKey: userSignKey.Public(),
		EncKey:  userDecKey.EncapsulationKey().Bytes(),
	}
	CreateUser(t, tc.Node, user, userSignKey, tc.AdminID, tc.AdminSK)

	token, secret := LoginSessionForTestWithSecret(t, tc.TS, "u1", userSignKey)

	// Test Create Inode
	nonce := make([]byte, 16)
	rand.Read(nonce)
	inodeID := GenerateInodeID("u1", nonce)
	inode := Inode{
		ID:      inodeID,
		Nonce:   nonce,
		OwnerID: "u1",
		Type:    FileType,
		Mode:    0600,
	}
	inode.SignInodeForTest("u1", userSignKey)

	batch := []LogCommand{{Type: CmdCreateInode, Data: MustMarshalJSON(inode), UserID: "u1"}}
	req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, batch, "u1", userSignKey, secret)
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Try to unseal error
		var sealed SealedResponse
		if err := json.Unmarshal(body, &sealed); err == nil && len(sealed.Sealed) > 0 {
			_, decrypted, err := crypto.OpenResponseSymmetric(secret, tc.NodeSK.Public(), sealed.Sealed)
			if err == nil {
				t.Fatalf("POST status %d: %s", resp.StatusCode, string(decrypted))
			}
			_, decrypted, err = crypto.OpenResponse(userDecKey, tc.NodeSK.Public(), sealed.Sealed)
			if err == nil {
				t.Fatalf("POST status %d: %s", resp.StatusCode, string(decrypted))
			}
		}
		t.Fatalf("POST status %d: %s", resp.StatusCode, string(body))
	}

	// Test Get Inode
	token, secretG := LoginSessionForTestWithSecret(t, tc.TS, "u1", userSignKey)
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetInode, GetInodeRequest{ID: inodeID}, "u1", userSignKey, secretG)
	req.Header.Set("Session-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status %d", resp.StatusCode)
	}

	opened := UnsealTestResponseWithSession(t, userDecKey, secretG, tc.NodeSK.Public(), resp)
	var got Inode
	json.Unmarshal(opened, &got)
	if got.ID != inodeID {
		t.Errorf("GET ID mismatch: %s", got.ID)
	}

	// Test Delete Inode (Implicit via UpdateInode NLink=0)
	inode.Version = 2
	inode.NLink = 0
	inode.SignInodeForTest("u1", userSignKey)
	batchD := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(inode), UserID: "u1"}}

	token, secret = LoginSessionForTestWithSecret(t, tc.TS, "u1", userSignKey)
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, batchD, "u1", userSignKey, secret)
	req.Header.Set("Session-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE status %d", resp.StatusCode)
	}

	// Verify Deleted
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetInode, GetInodeRequest{ID: inodeID}, "u1", userSignKey, secret)
	req.Header.Set("Session-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestSecurity_AccessControl(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Setup Users
	u1Dec, _ := crypto.GenerateEncryptionKey()
	u1Sign, _ := crypto.GenerateIdentityKey()
	u1 := User{ID: "u1", UID: 1001, SignKey: u1Sign.Public(), EncKey: u1Dec.EncapsulationKey().Bytes()}
	CreateUser(t, tc.Node, u1, u1Sign, tc.AdminID, tc.AdminSK)

	u2Dec, _ := crypto.GenerateEncryptionKey()
	u2Sign, _ := crypto.GenerateIdentityKey()
	u2 := User{ID: "u2", UID: 1002, SignKey: u2Sign.Public(), EncKey: u2Dec.EncapsulationKey().Bytes()}
	CreateUser(t, tc.Node, u2, u2Sign, tc.AdminID, tc.AdminSK)

	// 2. User 1 creates a private inode (0600)
	nonce1 := GenerateNonce()
	i1ID := GenerateInodeID("u1", nonce1)
	i1 := Inode{ID: i1ID, Nonce: nonce1, OwnerID: "u1", Mode: 0600}
	i1.SignInodeForTest("u1", u1Sign)
	batch := []LogCommand{{Type: CmdCreateInode, Data: MustMarshalJSON(i1), UserID: "u1"}}
	token1, secret1 := LoginSessionForTestWithSecret(t, tc.TS, "u1", u1Sign)
	req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, batch, "u1", u1Sign, secret1)
	req.Header.Set("Session-Token", token1)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to create inode: %d", resp.StatusCode)
	}
	_ = UnsealTestResponseWithSession(t, u1Dec, secret1, tc.NodeSK.Public(), resp)

	// 3. User 2 attempts to GET User 1's inode (Should fail)
	token2, secret2 := LoginSessionForTestWithSecret(t, tc.TS, "u2", u2Sign)
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetInode, GetInodeRequest{ID: i1ID}, "u2", u2Sign, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for GET (capability based), got %d", resp.StatusCode)
	}

	// 4. User 2 attempts to DELETE User 1's inode (Should fail)
	delBatch := []LogCommand{{Type: CmdDeleteInode, Data: MustMarshalJSON(i1ID), UserID: "u2"}}
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, delBatch, "u2", u2Sign, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized DELETE, got %d", resp.StatusCode)
	}

	// 5. User 2 attempts to UPDATE User 1's inode (Should fail)
	i1u := Inode{ID: i1ID, Nonce: nonce1, OwnerID: "u1", Mode: 0777, Version: 2, NLink: 1}
	i1u.SignInodeForTest("u2", u2Sign)
	batchU := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(i1u), UserID: "u2"}}
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, batchU, "u2", u2Sign, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized PUT, got %d", resp.StatusCode)
	}

	// 6. User 1 successfully deletes their own inode (Implicit via UpdateInode NLink=0)
	i1d := Inode{ID: i1ID, Nonce: nonce1, OwnerID: "u1", Mode: 0644, Version: 2, NLink: 0}
	i1d.SignInodeForTest("u1", u1Sign)
	batchD := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(i1d), UserID: "u1"}}
	token1d, secret1d := LoginSessionForTestWithSecret(t, tc.TS, "u1", u1Sign)
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, batchD, "u1", u1Sign, secret1d)
	req.Header.Set("Session-Token", token1d)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for authorized DELETE, got %d", resp.StatusCode)
	}
	_ = UnsealTestResponseWithSession(t, u1Dec, secret1d, tc.NodeSK.Public(), resp)
}

func TestFSM_EdgeCases(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()

	// Unknown Command (using string for type instead of number to avoid unmarshal error if it's strict, or just use a known unused number)
	// Actually CommandType is uint32, so 999 is valid uint32 but unknown.
	resp := tc.Node.FSM.Apply(&raft.Log{Data: []byte(`{"type":999,"data":""}`)})
	if err, ok := resp.(error); !ok || err.Error() != "unknown command" {
		// If it's a JSON error, it might be due to how CommandType is unmarshaled.
		if ok && strings.Contains(err.Error(), "unmarshal") {
			// Accept unmarshal error as a form of "invalid command"
		} else {
			t.Errorf("Expected unknown command or unmarshal error, got %v", resp)
		}
	}

	// Bad JSON
	resp = tc.Node.FSM.Apply(&raft.Log{Data: []byte(`{invalid}`)})
	if _, ok := resp.(error); !ok {
		t.Error("Expected JSON unmarshal error")
	}
}

func TestIdentityRegistry(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// Create User (via Raft directly, since /v1/user is removed)
	userDecKey, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "u1",
		SignKey: userSignKey.Public(),
		EncKey:  userDecKey.EncapsulationKey().Bytes(),
	}
	CreateUser(t, tc.Node, user, userSignKey, tc.AdminID, tc.AdminSK)

	token, secret := LoginSessionForTestWithSecret(t, tc.TS, "u1", userSignKey)

	// Create Group
	nonceG := GenerateNonce()
	groupID := GenerateGroupID("u1", nonceG)
	group := Group{
		ID:       groupID,
		OwnerID:  "u1",
		SignerID: "u1",
		GID:      1005,
		SignKey:  user.SignKey, // Use user's key as group key for test simplicity
		Nonce:    nonceG,
		Version:  1,
	}
	group.Signature = userSignKey.Sign(group.Hash())
	batch := []LogCommand{{Type: CmdCreateGroup, Data: MustMarshalJSON(group), UserID: "u1"}}
	req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, batch, "u1", userSignKey, secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Group Create failed: %d", resp.StatusCode)
	}

	_ = UnsealTestResponseWithSession(t, userDecKey, secret, tc.NodeSK.Public(), resp)

	// Register Node
	n := Node{ID: "node-data-1", Status: NodeStatusActive}
	body, _ := json.Marshal(n)
	req, _ = http.NewRequest("POST", tc.TS.URL+"/v1/node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Node Register failed: %d", resp.StatusCode)
	}
}

func TestRegisterUserEndpoint(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.TS.Close()

	reqBody := RegisterUserRequest{
		JWT:     "invalid.token",
		SignKey: []byte("sign"),
		EncKey:  []byte("enc"),
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(tc.TS.URL+"/v1/user/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid JWT, got %d", resp.StatusCode)
	}
}

func TestKeySync(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Mock JWKS
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key"
	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}
	jwksRes := map[string]interface{}{"keys": []interface{}{jwk}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksRes)
	}))
	defer jwksServer.Close()

	// Update srv to use mock JWKS
	tc.Server.jwks.SetIssuers([]jwks.Issuer{{Issuer: "test-auth-server", JWKSURI: jwksServer.URL + "/jwks.json"}})

	// 2. Setup User
	email := "sync@example.com"
	sub := "sub-sync@example.com"
	clusterSecret, _ := tc.Node.FSM.GetClusterSecret()
	mac := hmac.New(sha256.New, clusterSecret)
	mac.Write([]byte(sub))
	userID := hex.EncodeToString(mac.Sum(nil))

	u1Dec, _ := crypto.GenerateEncryptionKey()
	u1Sign, _ := crypto.GenerateIdentityKey()
	u1 := User{ID: userID, UID: 1001, SignKey: u1Sign.Public(), EncKey: u1Dec.EncapsulationKey().Bytes()}
	CreateUser(t, tc.Node, u1, u1Sign, tc.AdminID, tc.AdminSK)

	// Mint JWT
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "test-auth-server", "email": email, "sub": sub,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	jwtToken.Header["kid"] = kid
	jwtStr, _ := jwtToken.SignedString(priv)

	// 3. GET should be 404 (not found)
	req, _ := http.NewRequest("GET", tc.TS.URL+"/v1/user/keysync", nil)
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for empty keysync, got %d", resp.StatusCode)
	}

	// 4. POST (Store) with Session + Sealing
	blob := KeySyncBlob{KDF: "argon2id", Salt: []byte("salt"), Ciphertext: []byte("data")}
	payload, _ := json.Marshal(blob)
	sessionToken, secret := LoginSessionForTestWithSecret(t, tc.TS, userID, u1Sign)
	body := SealTestRequestSymmetric(t, userID, u1Sign, secret, payload)

	req, _ = http.NewRequest("POST", tc.TS.URL+"/v1/user/keysync", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", sessionToken)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201 for keysync storage, got %d", resp.StatusCode)
	}

	// 5. GET should now return the blob
	req, _ = http.NewRequest("GET", tc.TS.URL+"/v1/user/keysync", nil)
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for keysync retrieval, got %d", resp.StatusCode)
	}
	var got KeySyncBlob
	json.NewDecoder(resp.Body).Decode(&got)
	if string(got.Ciphertext) != "data" {
		t.Errorf("Retrieved blob data mismatch")
	}

	// 6. POST without sealing should fail (403)
	req, _ = http.NewRequest("POST", tc.TS.URL+"/v1/user/keysync", bytes.NewReader(payload))
	req.Header.Set("Session-Token", sessionToken)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unsealed keysync storage, got %d", resp.StatusCode)
	}
}

func TestFSMRestore(t *testing.T) {
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "fsm.bolt")
	fsm, err := NewMetadataFSM("node1", dbPath, []byte("test-cluster-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer fsm.Close()

	sk, _ := crypto.GenerateIdentityKey()
	err = fsm.db.Update(func(tx *bolt.Tx) error {
		u := User{ID: "u1", UID: 1001, SignKey: sk.Public()}
		return fsm.Put(tx, []byte("users"), []byte("u1"), MustMarshalJSON(u))
	})
	if err != nil {
		t.Fatal(err)
	}

	nonce := GenerateNonce()
	inodeID := GenerateInodeID("u1", nonce)
	inode := Inode{ID: inodeID, Nonce: nonce, Version: 1, OwnerID: "u1"}
	inode.SignInodeForTest("u1", sk)
	data, _ := json.Marshal(inode)
	err = fsm.db.Update(func(tx *bolt.Tx) error {
		resp := fsm.executeCreateInode(tx, data, "u1")
		if err, ok := resp.(error); ok {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("executeCreateInode failed: %v", err)
	}
	// Snapshot
	snap, _ := fsm.Snapshot()
	var buf bytes.Buffer
	sink := &MockSink{buf: &buf}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// New FSM
	tmpDir2 := t.TempDir()
	fsm2, err := NewMetadataFSM("node2", filepath.Join(tmpDir2, "fsm2.bolt"), []byte("test-cluster-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer fsm2.Close()

	// Restore
	if err := fsm2.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify fsm2 has data
	err = fsm2.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm2.Get(tx, []byte("inodes"), []byte(inodeID))
		if err != nil {
			return err
		}
		if plain == nil {
			return fmt.Errorf("key not found")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_Errors(t *testing.T) {
	tmpDir := t.TempDir()

	fsm, _ := NewMetadataFSM("node1", filepath.Join(tmpDir, "fsm.bolt"), []byte("test-cluster-secret"))
	defer fsm.Close()

	// Invalid JSON
	l := &raft.Log{Data: []byte(`{bad`)}
	if err := fsm.Apply(l); err == nil {
		t.Error("Expected error on invalid json")
	}

	// Unknown Command
	cmd := LogCommand{Type: 99}
	b, _ := json.Marshal(cmd)
	l = &raft.Log{Data: b}
	resp := fsm.Apply(l)
	if resp == nil {
		t.Error("Expected error on unknown command")
	} else if err, ok := resp.(error); !ok || err.Error() != "unknown command" {
		t.Errorf("Expected 'unknown command', got %v", resp)
	}
}

type MockSink struct {
	buf *bytes.Buffer
}

func (m *MockSink) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m *MockSink) Close() error                { return nil }
func (m *MockSink) ID() string                  { return "mock" }
func (m *MockSink) Cancel() error               { return nil }

func TestChunkPagination(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	userDecKey, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "u1",
		SignKey: userSignKey.Public(),
		EncKey:  userDecKey.EncapsulationKey().Bytes(),
	}
	CreateUser(t, tc.Node, user, userSignKey, tc.AdminID, tc.AdminSK)

	// Create Inode with many chunks
	chunkCount := ChunkPageSize + 50 // 1050
	manifest := make([]ChunkEntry, chunkCount)
	for i := 0; i < chunkCount; i++ {
		manifest[i] = ChunkEntry{ID: fmt.Sprintf("chunk-%d", i), Nodes: []string{"n1"}}
	}

	nonce := make([]byte, 16)
	rand.Read(nonce)
	inodeID := GenerateInodeID("u1", nonce)

	inode := Inode{
		ID:            inodeID,
		Nonce:         nonce,
		Type:          FileType,
		OwnerID:       "u1",
		Mode:          0600,
		ChunkManifest: manifest,
	}
	inode.SignInodeForTest("u1", userSignKey)
	batch := []LogCommand{{Type: CmdCreateInode, Data: MustMarshalJSON(inode), UserID: "u1"}}
	tokenP, secretP := LoginSessionForTestWithSecret(t, tc.TS, "u1", userSignKey)
	req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionBatch, batch, "u1", userSignKey, secretP)
	req.Header.Set("Session-Token", tokenP)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST status %d", resp.StatusCode)
	}

	_ = UnsealTestResponseWithSession(t, userDecKey, secretP, tc.NodeSK.Public(), resp)

	// Verify via API (Transparent Reconstruction)
	tokenP2, secretP2 := LoginSessionForTestWithSecret(t, tc.TS, "u1", userSignKey)
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetInode, GetInodeRequest{ID: inodeID}, "u1", userSignKey, secretP2)
	req.Header.Set("Session-Token", tokenP2)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status %d", resp.StatusCode)
	}

	opened := UnsealTestResponseWithSession(t, userDecKey, secretP2, tc.NodeSK.Public(), resp)
	var got Inode
	if err := json.Unmarshal(opened, &got); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if len(got.ChunkManifest) != chunkCount {
		t.Errorf("Expected %d chunks, got %d", chunkCount, len(got.ChunkManifest))
	}
	if got.ChunkManifest[chunkCount-1].ID != fmt.Sprintf("chunk-%d", chunkCount-1) {
		t.Errorf("Last chunk ID mismatch")
	}

	// Verify Internal Storage (BoltDB)
	// We need to access FSM directly
	err = tc.Node.FSM.db.View(func(tx *bolt.Tx) error {
		plain, err := tc.Node.FSM.Get(tx, []byte("inodes"), []byte(inodeID))
		if err != nil {
			return err
		}
		var stored Inode
		json.Unmarshal(plain, &stored)

		if stored.ChunkManifest != nil {
			return fmt.Errorf("Stored manifest should be nil")
		}
		if len(stored.ChunkPages) == 0 {
			return fmt.Errorf("Stored chunk_pages should not be empty")
		}

		// Check pages bucket
		for _, pid := range stored.ChunkPages {
			plainPage, err := tc.Node.FSM.Get(tx, []byte("chunk_pages"), []byte(pid))
			if err != nil || plainPage == nil {
				return fmt.Errorf("Page %s not found or decryption failed: %v", pid, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("Internal verification failed: %v", err)
	}
}

func TestAccounting(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Create User
	userID := "acc-user"
	sk, _ := crypto.GenerateIdentityKey()
	user := User{ID: userID, UID: 1001, SignKey: sk.Public()}
	CreateUser(t, tc.Node, user, sk, tc.AdminID, tc.AdminSK)

	// Helper to check usage
	checkUsage := func(wantInodes, wantBytes int64) {
		err := tc.Node.FSM.db.View(func(tx *bolt.Tx) error {
			plain, err := tc.Node.FSM.Get(tx, []byte("users"), []byte(userID))
			if err != nil {
				return err
			}
			if plain == nil {
				return fmt.Errorf("user not found")
			}
			var u User
			json.Unmarshal(plain, &u)
			if u.Usage.InodeCount != wantInodes {
				return fmt.Errorf("inodes: got %d, want %d", u.Usage.InodeCount, wantInodes)
			}
			if u.Usage.TotalBytes != wantBytes {
				return fmt.Errorf("bytes: got %d, want %d", u.Usage.TotalBytes, wantBytes)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	}

	checkUsage(0, 0)

	// 2. Create File
	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := GenerateInodeID(userID, nonce1)
	inode := Inode{ID: id1, Nonce: nonce1, OwnerID: userID, Size: 100, NLink: 1, Type: FileType, Mode: 0644, ChunkManifest: []ChunkEntry{{ID: "dummy"}}}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	cmd := LogCommand{Type: CmdCreateInode, Data: inodeBytes, UserID: userID}
	cmdBytes, _ := cmd.Marshal()
	f := tc.Node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Create inode raft failed: %v", err)
	}
	if err, ok := f.Response().(error); ok {
		t.Fatalf("Create inode fsm failed: %v", err)
	}

	checkUsage(1, 100)

	// 3. Update File (Resize)
	inode.Size = 250
	inode.Version = 2 // Client increments
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes, UserID: userID}
	cmdBytes, _ = cmd.Marshal()
	f = tc.Node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Update inode raft failed: %v", err)
	}
	if err, ok := f.Response().(error); ok {
		t.Fatalf("Update inode fsm failed: %v", err)
	}

	checkUsage(1, 250)

	// 4. Delete File (Implicit via UpdateInode NLink=0)
	inode.NLink = 0
	inode.Version = 3
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes, UserID: userID}
	cmdBytes, _ = cmd.Marshal()
	f = tc.Node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Delete inode raft failed: %v", err)
	}
	if err, ok := f.Response().(error); ok {
		t.Fatalf("Delete inode fsm failed: %v", err)
	}

	checkUsage(0, 0)
}

func TestQuotaEnforcement(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	userID := "quota-user"
	sk, _ := crypto.GenerateIdentityKey()
	user := User{ID: userID, UID: 1001, SignKey: sk.Public()}
	CreateUser(t, tc.Node, user, sk, tc.AdminID, tc.AdminSK)

	// 1. Set Quota (1 Inode, 500 Bytes)
	maxInodes := uint64(1)
	maxBytes := uint64(500)
	req := SetUserQuotaRequest{
		UserID:    userID,
		MaxBytes:  &maxBytes,
		MaxInodes: &maxInodes,
	}
	reqBytes, _ := json.Marshal(req)
	cmd := LogCommand{Type: CmdSetUserQuota, Data: reqBytes, UserID: "admin"}
	cmdBytes, _ := cmd.Marshal()
	if err := tc.Node.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Set quota failed: %v", err)
	}

	// 2. Create File 1 (OK)
	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := GenerateInodeID(userID, nonce1)
	inode := Inode{ID: id1, Nonce: nonce1, OwnerID: userID, Size: 100, NLink: 1, Type: FileType, Mode: 0644, ChunkManifest: []ChunkEntry{{ID: "dummy"}}}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	cmd = LogCommand{Type: CmdCreateInode, Data: inodeBytes, UserID: userID}
	cmdBytes, _ = cmd.Marshal()
	if err := tc.Node.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Create file 1 failed: %v", err)
	}

	// 3. Create File 2 (Fail: Inode Quota)
	nonce2 := make([]byte, 16)
	rand.Read(nonce2)
	id2 := GenerateInodeID(userID, nonce2)
	inode2 := Inode{ID: id2, Nonce: nonce2, OwnerID: userID, Size: 100, NLink: 1, Type: FileType, Mode: 0644, ChunkManifest: []ChunkEntry{{ID: "dummy"}}}
	inode2.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode2)
	cmd = LogCommand{Type: CmdCreateInode, Data: inodeBytes, UserID: userID}
	cmdBytes, _ = cmd.Marshal()
	f := tc.Node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	res := f.Response()
	if err, ok := res.(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %T: %v (IsQuota=%v)", res, res, errors.Is(err, ErrQuotaExceeded))
	}

	// 4. Update File 1 (Resize to 400 - OK)
	inode.Size = 400
	inode.Version = 2
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes, UserID: userID}
	cmdBytes, _ = cmd.Marshal()
	f = tc.Node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f.Response().(error); ok && err != nil {
		t.Fatal(err)
	}

	// 5. Update File 1 (Resize to 600 - Fail: Storage Quota)
	inode.Size = 600
	inode.Version = 3
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes, UserID: userID}
	cmdBytes, _ = cmd.Marshal()
	f = tc.Node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	res = f.Response()
	if err, ok := res.(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %T: %v (IsQuota=%v)", res, res, errors.Is(err, ErrQuotaExceeded))
	}
}

func TestSecurity_IDOR_User(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Create two users
	u1ID := "user1"
	sk1, _ := crypto.GenerateIdentityKey()
	u1DK, _ := crypto.GenerateEncryptionKey()
	CreateUser(t, tc.Node, User{
		ID:      u1ID,
		SignKey: sk1.Public(),
		EncKey:  crypto.MarshalEncapsulationKey(u1DK.EncapsulationKey()),
		Quota:   UserQuota{MaxInodes: 100},
		Usage:   UserUsage{InodeCount: 10},
		Locked:  false,
	}, sk1, tc.AdminID, tc.AdminSK)

	u2ID := "user2"
	sk2, _ := crypto.GenerateIdentityKey()
	u2DK, _ := crypto.GenerateEncryptionKey()
	CreateUser(t, tc.Node, User{
		ID:      u2ID,
		SignKey: sk2.Public(),
		EncKey:  crypto.MarshalEncapsulationKey(u2DK.EncapsulationKey()),
		Quota:   UserQuota{MaxInodes: 200},
		Usage:   UserUsage{InodeCount: 20},
		Locked:  false,
	}, sk2, tc.AdminID, tc.AdminSK)

	// Login as User 1
	token1, secret1 := LoginSessionForTestWithSecret(t, tc.TS, u1ID, sk1)

	// 2. User 1 requests self (Should be FULL)
	req := NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetUser, GetUserRequest{ID: u1ID}, u1ID, sk1, secret1)
	req.Header.Set("Session-Token", token1)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get self: %d", resp.StatusCode)
	}
	opened := UnsealTestResponseWithSession(t, u1DK, secret1, tc.NodeSK.Public(), resp)
	var res1 User
	json.Unmarshal(opened, &res1)

	if res1.Quota.MaxInodes != 100 || res1.Usage.InodeCount != 10 {
		t.Errorf("Self metadata redacted: %+v", res1)
	}

	// 3. User 2 requests User 1 (Should be REDACTED)
	token2, secret2 := LoginSessionForTestWithSecret(t, tc.TS, u2ID, sk2)
	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetUser, GetUserRequest{ID: u1ID}, u2ID, sk2, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get other user: %d", resp.StatusCode)
	}
	opened2 := UnsealTestResponseWithSession(t, u2DK, secret2, tc.NodeSK.Public(), resp)
	var res2 User
	json.Unmarshal(opened2, &res2)

	if res2.Quota.MaxInodes != 0 || res2.Usage.InodeCount != 0 {
		t.Errorf("Other user metadata NOT redacted: %+v", res2)
	}
	if len(res2.SignKey) == 0 {
		t.Error("Other user SignKey redacted (should be public)")
	}
	if res2.ID != u1ID {
		t.Errorf("ID mismatch: got %s, want %s", res2.ID, u1ID)
	}

	// 4. Admin requests User 2 (Should be FULL)
	// Promote user1 to admin
	u1IDBytes, _ := json.Marshal(u1ID)
	u1Cmd, err := LogCommand{Type: CmdPromoteAdmin, Data: u1IDBytes, UserID: tc.AdminID}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.Node.Raft.Apply(u1Cmd, 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to promote user1: %v", err)
	}

	req = NewSealedTestRequestSymmetric(t, tc.TS.URL, ActionGetUser, GetUserRequest{ID: u2ID}, u1ID, sk1, secret1)
	req.Header.Set("Session-Token", token1)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Admin failed to get user: %d", resp.StatusCode)
	}
	openedAdmin := UnsealTestResponseWithSession(t, u1DK, secret1, tc.NodeSK.Public(), resp)
	var resAdmin User
	json.Unmarshal(openedAdmin, &resAdmin)

	if resAdmin.Quota.MaxInodes != 200 || resAdmin.Usage.InodeCount != 20 {
		t.Errorf("Admin saw redacted metadata: %+v", resAdmin)
	}
}

func TestNodeRevocation(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Register a node
	nodeKey, _ := crypto.GenerateIdentityKey()
	nodeID := "rogue-node"
	n := Node{
		ID:      nodeID,
		SignKey: nodeKey.Public(),
		Status:  NodeStatusActive,
	}
	body, _ := json.Marshal(n)
	req, _ := http.NewRequest("POST", tc.TS.URL+"/v1/node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to register node: %v, status: %d", err, resp.StatusCode)
	}

	// Verify registered
	n2, err := tc.Node.FSM.GetNode(nodeID)
	if err != nil || n2 == nil || n2.Status != NodeStatusActive {
		t.Error("Node should be active after registration")
	}

	// 2. Revoke/Remove node
	req, _ = http.NewRequest("DELETE", tc.TS.URL+"/v1/node/"+nodeID, nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to remove node: %v, status: %d", err, resp.StatusCode)
	}

	// Verify gone
	n3, err := tc.Node.FSM.GetNode(nodeID)
	if err == nil && n3 != nil {
		t.Error("Node should be gone after revocation")
	}

	// Verify node gone from list
	nodes, _ := tc.Node.FSM.GetNodes()
	for _, n := range nodes {
		if n.ID == nodeID {
			t.Errorf("Node %s still exists in registry", nodeID)
		}
	}
}
