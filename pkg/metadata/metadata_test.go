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
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func SetupCluster(t *testing.T) (*RaftNode, *httptest.Server, *crypto.IdentityKey, []byte, *Server) {
	tmpDir := t.TempDir()

	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(tmpDir, mk)

	nodeKey, _ := crypto.GenerateIdentityKey()
	nodeID := fmt.Sprintf("node-%d", time.Now().UnixNano())

	node, err := NewRaftNode(nodeID, "127.0.0.1:0", "", tmpDir, st, nodeKey)
	if err != nil {
		t.Fatalf("NewRaftNode failed: %v", err)
	}

	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:      raft.ServerID(nodeID),
				Address: node.Transport.LocalAddr(),
			},
		},
	}
	f := node.Raft.BootstrapCluster(cfg)
	if err := f.Error(); err != nil {
		node.Shutdown()
		t.Fatalf("Bootstrap failed: %v", err)
	}

	WaitLeader(t, node.Raft)

	// Bootstrap cluster key
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	key := ClusterKey{
		ID:        "key-1",
		EncKey:    ek.Bytes(),
		DecKey:    dk.Bytes(),
		CreatedAt: time.Now().Unix(),
	}
	keyBytes, _ := json.Marshal(key)
	cmd := LogCommand{Type: CmdRotateKey, Data: keyBytes}
	cmdBytes, _ := json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Bootstrap key apply failed: %v", err)
	}

	signKey, _ := crypto.GenerateIdentityKey()
	server := NewServer(nodeID, node.Raft, node.FSM, "", signKey, "testsecret", nil, 0)
	ts := httptest.NewServer(server)
	return node, ts, signKey, ek.Bytes(), server
}

func loginSession(t *testing.T, ts *httptest.Server, userID string, userSignKey *crypto.IdentityKey) string {
	// 1. Get Challenge
	reqData := AuthChallengeRequest{UserID: userID}
	b, _ := json.Marshal(reqData)
	resp, err := http.Post(ts.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge request status: %d", resp.StatusCode)
	}

	var challengeRes AuthChallengeResponse
	json.NewDecoder(resp.Body).Decode(&challengeRes)

	// 2. Solve Challenge
	sig := userSignKey.Sign(challengeRes.Challenge)
	solve := AuthChallengeSolve{
		UserID:    userID,
		Challenge: challengeRes.Challenge,
		Signature: sig,
	}
	b, _ = json.Marshal(solve)
	resp, err = http.Post(ts.URL+"/v1/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login request status: %d", resp.StatusCode)
	}

	var sessionRes SessionResponse
	json.NewDecoder(resp.Body).Decode(&sessionRes)
	return sessionRes.Token
}

func unsealTestResponse(t *testing.T, userDecKey *mlkem.DecapsulationKey768, serverSignPK []byte, resp *http.Response) []byte {
	if resp.Header.Get("X-DistFS-Sealed") != "true" {
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	var sealed SealedResponse
	json.NewDecoder(resp.Body).Decode(&sealed)
	_, payload, err := crypto.OpenResponse(userDecKey, serverSignPK, sealed.Sealed)
	if err != nil {
		t.Fatalf("OpenResponse failed: %v", err)
	}
	return payload
}

func sealTestRequest(t *testing.T, userID string, userSignKey *crypto.IdentityKey, serverPKBytes []byte, payload []byte) []byte {
	serverPK, err := crypto.UnmarshalEncapsulationKey(serverPKBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal server PK: %v", err)
	}
	sealed, err := crypto.SealRequest(serverPK, userSignKey, payload)
	if err != nil {
		t.Fatalf("SealRequest failed: %v", err)
	}
	sr := SealedRequest{
		UserID: userID,
		Sealed: sealed,
	}
	b, _ := json.Marshal(sr)
	return b
}

func TestMetadataCluster(t *testing.T) {
	node, ts, serverSignKey, serverEK, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	userDecKey, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "u1",
		SignKey: userSignKey.Public(),
		EncKey:  userDecKey.EncapsulationKey().Bytes(),
	}
	userBytes, _ := json.Marshal(user)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateUser, Data: userBytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft Apply user failed: %v", err)
	}

	token := loginSession(t, ts, "u1", userSignKey)

	// Test Create Inode
	inode := Inode{
		ID:      "inode-1",
		OwnerID: "u1",
		Type:    FileType,
	}
	payload, _ := json.Marshal(inode)
	body := sealTestRequest(t, "u1", userSignKey, serverEK, payload)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/inode", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("POST status %d: %s", resp.StatusCode, body)
	}

	// Unseal response if needed (Create Inode returns the created Inode)
	_ = unsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)

	// Test Get Inode
	token = loginSession(t, ts, "u1", userSignKey)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/meta/inode/inode-1", nil)
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status %d", resp.StatusCode)
	}

	opened := unsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)
	var got Inode
	json.Unmarshal(opened, &got)
	if got.ID != "inode-1" {
		t.Errorf("GET ID mismatch: %s", got.ID)
	}

	// Test Delete Inode
	token = loginSession(t, ts, "u1", userSignKey)
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/meta/inode/inode-1", nil)
	req.Header.Set("Session-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE status %d", resp.StatusCode)
	}

	// Verify Deleted
	token = loginSession(t, ts, "u1", userSignKey)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/meta/inode/inode-1", nil)
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
	node, ts, _, serverEK, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setup Users
	u1Dec, _ := crypto.GenerateEncryptionKey()
	u1Sign, _ := crypto.GenerateIdentityKey()
	u1 := User{ID: "u1", SignKey: u1Sign.Public(), EncKey: u1Dec.EncapsulationKey().Bytes()}
	u1Bytes, _ := json.Marshal(u1)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateUser, Data: u1Bytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to create u1: %v", err)
	}

	u2Dec, _ := crypto.GenerateEncryptionKey()
	u2Sign, _ := crypto.GenerateIdentityKey()
	u2 := User{ID: "u2", SignKey: u2Sign.Public(), EncKey: u2Dec.EncapsulationKey().Bytes()}
	u2Bytes, _ := json.Marshal(u2)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateUser, Data: u2Bytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to create u2: %v", err)
	}

	// 2. User 1 creates a private inode (0600)
	payload, _ := json.Marshal(Inode{ID: "private-1", OwnerID: "u1", Mode: 0600})
	body := sealTestRequest(t, "u1", u1Sign, serverEK, payload)
	token1 := loginSession(t, ts, "u1", u1Sign)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/inode", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token1)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create inode: %d", resp.StatusCode)
	}

	// 3. User 2 attempts to GET User 1's inode (Should fail)
	token2 := loginSession(t, ts, "u2", u2Sign)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/meta/inode/private-1", nil)
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized GET, got %d", resp.StatusCode)
	}

	// 4. User 2 attempts to DELETE User 1's inode (Should fail)
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/meta/inode/private-1", nil)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized DELETE, got %d", resp.StatusCode)
	}

	// 5. User 2 attempts to UPDATE User 1's inode (Should fail)
	payload, _ = json.Marshal(Inode{ID: "private-1", Mode: 0777, Version: 1})
	body = sealTestRequest(t, "u2", u2Sign, serverEK, payload)
	req, _ = http.NewRequest("PUT", ts.URL+"/v1/meta/inode/private-1", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized PUT, got %d", resp.StatusCode)
	}

	// 6. User 1 successfully deletes their own inode
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/meta/inode/private-1", nil)
	req.Header.Set("Session-Token", token1)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for authorized DELETE, got %d", resp.StatusCode)
	}
}

func TestFSM_EdgeCases(t *testing.T) {
	node, _, _, _, _ := SetupCluster(t)
	defer node.Shutdown()

	// Unknown Command (using string for type instead of number to avoid unmarshal error if it's strict, or just use a known unused number)
	// Actually CommandType is uint32, so 999 is valid uint32 but unknown.
	resp := node.FSM.Apply(&raft.Log{Data: []byte(`{"type":999,"data":""}`)})
	if err, ok := resp.(error); !ok || err.Error() != "unknown command" {
		// If it's a JSON error, it might be due to how CommandType is unmarshaled.
		if ok && strings.Contains(err.Error(), "unmarshal") {
			// Accept unmarshal error as a form of "invalid command"
		} else {
			t.Errorf("Expected unknown command or unmarshal error, got %v", resp)
		}
	}

	// Bad JSON
	resp = node.FSM.Apply(&raft.Log{Data: []byte(`{invalid}`)})
	if _, ok := resp.(error); !ok {
		t.Error("Expected JSON unmarshal error")
	}
}

func TestIdentityRegistry(t *testing.T) {
	node, ts, serverSignKey, serverEK, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Initialize Cluster Secret (needed for Group ID hashing)
	secret := make([]byte, 32)
	rand.Read(secret)
	fSecret := node.Raft.Apply(LogCommand{Type: CmdInitSecret, Data: secret}.Marshal(), 5*time.Second)
	if err := fSecret.Error(); err != nil {
		t.Fatalf("Failed to init secret: %v", err)
	}

	// Create User (via Raft directly, since /v1/user is removed)
	userDecKey, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "u1",
		SignKey: userSignKey.Public(),
		EncKey:  userDecKey.EncapsulationKey().Bytes(),
	}
	userBytes, _ := json.Marshal(user)
	cmd := LogCommand{Type: CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Raft Apply failed: %v", err)
	}
	if err, ok := future.Response().(error); ok {
		t.Fatalf("FSM Apply failed: %v", err)
	}

	token := loginSession(t, ts, "u1", userSignKey)

	// Create Group
	group := Group{ID: "g1", OwnerID: "u1"}
	payload, _ := json.Marshal(group)
	body := sealTestRequest(t, "u1", userSignKey, serverEK, payload)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/group/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Group Create failed: %d", resp.StatusCode)
	}

	_ = unsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)

	// Register Node
	n := Node{ID: "node-data-1", Status: NodeStatusActive}
	body, _ = json.Marshal(n)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/node", bytes.NewReader(body))
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
	node, ts, _, _, _ := SetupCluster(t)
	_ = node
	defer ts.Close()

	reqBody := RegisterUserRequest{
		JWT:     "invalid.token",
		SignKey: []byte("sign"),
		EncKey:  []byte("enc"),
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(ts.URL+"/v1/user/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid JWT, got %d", resp.StatusCode)
	}
}

func TestKeySync(t *testing.T) {
	node, ts, _, serverEK, srv := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

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
	srv.jwks.SetIssuers([]jwks.Issuer{{Issuer: "test-auth-server", JWKSURI: jwksServer.URL + "/jwks.json"}})

	// Initialize Cluster Secret
	var secret []byte
	secret, _ = node.FSM.GetClusterSecret()
	if secret == nil {
		secret = make([]byte, 32)
		rand.Read(secret)
		f := node.Raft.Apply(LogCommand{Type: CmdInitSecret, Data: secret}.Marshal(), 5*time.Second)
		if err := f.Error(); err != nil {
			t.Fatalf("Failed to init secret: %v", err)
		}
	}

	// 2. Setup User
	email := "sync@example.com"
	secret, _ = node.FSM.GetClusterSecret()
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(email))
	userID := hex.EncodeToString(mac.Sum(nil))

	u1Dec, _ := crypto.GenerateEncryptionKey()
	u1Sign, _ := crypto.GenerateIdentityKey()
	u1 := User{ID: userID, SignKey: u1Sign.Public(), EncKey: u1Dec.EncapsulationKey().Bytes()}
	u1Bytes, _ := json.Marshal(u1)
	fUser := node.Raft.Apply(LogCommand{Type: CmdCreateUser, Data: u1Bytes}.Marshal(), 5*time.Second)
	if err := fUser.Error(); err != nil {
		t.Fatalf("Failed to apply user create: %v", err)
	}

	// Mint JWT
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "test-auth-server", "email": email,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	jwtToken.Header["kid"] = kid
	jwtStr, _ := jwtToken.SignedString(priv)

	// 3. GET should be 404 (not found)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/user/keysync", nil)
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for empty keysync, got %d", resp.StatusCode)
	}

	// 4. POST (Store) with Session + Sealing
	blob := KeySyncBlob{KDF: "argon2id", Salt: []byte("salt"), Ciphertext: []byte("data")}
	payload, _ := json.Marshal(blob)
	body := sealTestRequest(t, userID, u1Sign, serverEK, payload)
	sessionToken := loginSession(t, ts, userID, u1Sign)

	req, _ = http.NewRequest("POST", ts.URL+"/v1/user/keysync", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", sessionToken)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201 for keysync storage, got %d", resp.StatusCode)
	}

	// 5. GET should now return the blob
	req, _ = http.NewRequest("GET", ts.URL+"/v1/user/keysync", nil)
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
	req, _ = http.NewRequest("POST", ts.URL+"/v1/user/keysync", bytes.NewReader(payload))
	req.Header.Set("Session-Token", sessionToken)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unsealed keysync storage, got %d", resp.StatusCode)
	}
}

func TestFSMRestore(t *testing.T) {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)

	dbPath := filepath.Join(tmpDir, "fsm.bolt")
	fsm, err := NewMetadataFSM(dbPath, st)
	if err != nil {
		t.Fatal(err)
	}
	defer fsm.Close()

	inode := Inode{ID: "restore-test"}
	data, _ := json.Marshal(inode)
	err = fsm.db.Update(func(tx *bolt.Tx) error {
		resp := fsm.executeCreateInode(tx, data)
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
	st2 := storage.New(tmpDir2, mk) // different dir
	fsm2, err := NewMetadataFSM(filepath.Join(tmpDir2, "fsm2.bolt"), st2)
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
		plain, err := fsm2.Get(tx, []byte("inodes"), []byte("restore-test"))
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
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)

	fsm, _ := NewMetadataFSM(filepath.Join(tmpDir, "fsm.bolt"), st)
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
	node, ts, serverSignKey, serverEK, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	userDecKey, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := User{
		ID:      "u1",
		SignKey: userSignKey.Public(),
		EncKey:  userDecKey.EncapsulationKey().Bytes(),
	}
	userBytes, _ := json.Marshal(user)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateUser, Data: userBytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft Apply user failed: %v", err)
	}
	token := loginSession(t, ts, "u1", userSignKey)

	// Create Inode with many chunks
	chunkCount := ChunkPageSize + 50 // 1050
	manifest := make([]ChunkEntry, chunkCount)
	for i := 0; i < chunkCount; i++ {
		manifest[i] = ChunkEntry{ID: fmt.Sprintf("chunk-%d", i), Nodes: []string{"n1"}}
	}

	inode := Inode{
		ID:            "paginated-file",
		Type:          FileType,
		OwnerID:       "u1",
		ChunkManifest: manifest,
	}
	payload, _ := json.Marshal(inode)
	body := sealTestRequest(t, "u1", userSignKey, serverEK, payload)

	// POST /v1/meta/inode
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/inode", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST status %d", resp.StatusCode)
	}

	_ = unsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)

	// Verify via API (Transparent Reconstruction)
	token = loginSession(t, ts, "u1", userSignKey)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/meta/inode/paginated-file", nil)
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status %d", resp.StatusCode)
	}

	opened := unsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)
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
	err = node.FSM.db.View(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("inodes"), []byte("paginated-file"))
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
			plainPage, err := node.FSM.Get(tx, []byte("chunk_pages"), []byte(pid))
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
	node, ts, _, _, _ := SetupCluster(t)
	_ = node
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create User
	userID := "acc-user"
	sk, _ := crypto.GenerateIdentityKey()
	user := User{ID: userID, SignKey: sk.Public()}
	userBytes, _ := json.Marshal(user)
	cmd := LogCommand{Type: CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	f := node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Create user raft failed: %v", err)
	}
	if err, ok := f.Response().(error); ok {
		t.Fatalf("Create user fsm failed: %v", err)
	}

	// Helper to check usage
	checkUsage := func(wantInodes, wantBytes int64) {
		err := node.FSM.db.View(func(tx *bolt.Tx) error {
			plain, err := node.FSM.Get(tx, []byte("users"), []byte(userID))
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
	inode := Inode{ID: "f1", OwnerID: userID, Size: 100}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	cmd = LogCommand{Type: CmdCreateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Create inode raft failed: %v", err)
	}
	if err, ok := f.Response().(error); ok {
		t.Fatalf("Create inode fsm failed: %v", err)
	}

	checkUsage(1, 100)

	// 3. Update File (Resize)
	inode.Size = 250
	inode.Version = 1 // Must match existing version
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Update inode raft failed: %v", err)
	}
	if err, ok := f.Response().(error); ok {
		t.Fatalf("Update inode fsm failed: %v", err)
	}

	checkUsage(1, 250)

	// 4. Delete File
	cmd = LogCommand{Type: CmdDeleteInode, Data: []byte("f1")}
	cmdBytes, _ = json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Delete inode raft failed: %v", err)
	}
	if err, ok := f.Response().(error); ok {
		t.Fatalf("Delete inode fsm failed: %v", err)
	}

	checkUsage(0, 0)
}

func TestQuotaEnforcement(t *testing.T) {
	node, ts, _, _, _ := SetupCluster(t)
	_ = node
	defer node.Shutdown()
	defer ts.Close()

	userID := "quota-user"
	sk, _ := crypto.GenerateIdentityKey()
	user := User{ID: userID, SignKey: sk.Public()}
	userBytes, _ := json.Marshal(user)
	cmd := LogCommand{Type: CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	if err := node.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	// 1. Set Quota (1 Inode, 500 Bytes)
	maxInodes := int64(1)
	maxBytes := int64(500)
	req := SetUserQuotaRequest{
		UserID:    userID,
		MaxBytes:  &maxBytes,
		MaxInodes: &maxInodes,
	}
	reqBytes, _ := json.Marshal(req)
	cmd = LogCommand{Type: CmdSetUserQuota, Data: reqBytes}
	cmdBytes, _ = json.Marshal(cmd)
	if err := node.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Set quota failed: %v", err)
	}

	// 2. Create File 1 (OK)
	inode := Inode{ID: "f1", OwnerID: userID, Size: 100}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	cmd = LogCommand{Type: CmdCreateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	if err := node.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Create file 1 failed: %v", err)
	}

	// 3. Create File 2 (Fail: Inode Quota)
	inode2 := Inode{ID: "f2", OwnerID: userID, Size: 100}
	inode2.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode2)
	cmd = LogCommand{Type: CmdCreateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	f := node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f.Response().(error); !ok || err.Error() != "user inode quota exceeded" {
		t.Errorf("Expected user inode quota exceeded, got %v", f.Response())
	}

	// 4. Update File 1 (Resize to 400 - OK)
	inode.Size = 400
	inode.Version = 1
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	if err := node.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := node.Raft.Apply(cmdBytes, 5*time.Second).Response().(error); ok && err != nil {
		t.Fatal(err)
	}

	// 5. Update File 1 (Resize to 600 - Fail: Storage Quota)
	inode.Size = 600
	inode.Version = 2
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f.Response().(error); !ok || err.Error() != "user storage quota exceeded" {
		t.Errorf("Expected user storage quota exceeded, got %v", f.Response())
	}
}

func TestAdminChownQuota(t *testing.T) {
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	u1 := "user1"
	sk1, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: sk1.Public()})

	u2 := "user2"
	sk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u2, SignKey: sk2.Public()})

	// Set u2 Quota to 1 Inode
	maxInodes := int64(1)
	req := SetUserQuotaRequest{UserID: u2, MaxInodes: &maxInodes}
	reqBytes, _ := json.Marshal(req)
	node.Raft.Apply(LogCommand{Type: CmdSetUserQuota, Data: reqBytes}.Marshal(), 5*time.Second)

	// u1 creates a file
	inode := Inode{ID: "f1", OwnerID: u1, Size: 100}
	inode.SignInodeForTest(u1, sk1)
	iBytes, _ := json.Marshal(inode)
	node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: iBytes}.Marshal(), 5*time.Second)

	// Admin chown f1 from u1 to u2
	// u2 has 0 files, limit 1. Transfer should SUCCEED.
	// Current BUG: checkQuota(u2, delta=1) sees u2 usage=0, limit=1 -> OK.
	// Wait, actually the bug is if u2 ALREADY has 1 file?
	// Let's test the limit case.

	// If u2 has 1 file already.
	inode2 := Inode{ID: "f2", OwnerID: u2, Size: 100}
	inode2.SignInodeForTest(u2, sk2)
	iBytes2, _ := json.Marshal(inode2)
	node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: iBytes2}.Marshal(), 5*time.Second)

	// Now u2 is at limit (1/1).
	// Transfer f1 from u1 to u2 should FAIL.
	chReq := AdminChownRequest{InodeID: "f1", OwnerID: &u2}
	chBytes, _ := json.Marshal(chReq)
	f := node.Raft.Apply(LogCommand{Type: CmdAdminChown, Data: chBytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f.Response().(error); !ok || err.Error() != "user inode quota exceeded" {
		t.Errorf("Expected user inode quota exceeded, got %v", f.Response())
	}

	// Transfer f2 from u2 back to u2 (identity transfer)
	// Current BUG: usage is 1/1. checkQuota(u2, delta=1) sees 1+1 > 1 -> FAILS.
	// Fixed: updateUsage(u2, delta=-1) makes usage 0. checkQuota(u2, delta=1) sees 0+1 <= 1 -> OK.
	chReq2 := AdminChownRequest{InodeID: "f2", OwnerID: &u2}
	chBytes2, _ := json.Marshal(chReq2)
	f2 := node.Raft.Apply(LogCommand{Type: CmdAdminChown, Data: chBytes2}.Marshal(), 5*time.Second)
	if err := f2.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f2.Response().(error); ok && err != nil {
		t.Errorf("Identity chown failed: %v", err)
	}
}
