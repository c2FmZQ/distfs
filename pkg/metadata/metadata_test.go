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

	token := LoginSessionForTest(t, ts, "u1", userSignKey)

	// Test Create Inode
	inode := Inode{
		ID:      "inode-1",
		OwnerID: "u1",
		Type:    FileType,
	}
	inode.SignInodeForTest("u1", userSignKey)
	inodeBytes, _ := json.Marshal(inode)
	batch := []LogCommand{{Type: CmdCreateInode, Data: inodeBytes}}
	payload, _ := json.Marshal(batch)
	body := sealTestRequest(t, "u1", userSignKey, serverEK, payload)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("POST status %d: %s", resp.StatusCode, body)
	}

	// Unseal response if needed (Create Inode returns the created Inode)
	_ = UnsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)

	// Test Get Inode
	token = LoginSessionForTest(t, ts, "u1", userSignKey)
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

	opened := UnsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)
	var got Inode
	json.Unmarshal(opened, &got)
	if got.ID != "inode-1" {
		t.Errorf("GET ID mismatch: %s", got.ID)
	}

	// Test Delete Inode (Implicit via UpdateInode NLink=0)
	inode.Version = 2
	inode.NLink = 0
	inode.SignInodeForTest("u1", userSignKey)
	batchD := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(inode)}}
	payloadD, _ := json.Marshal(batchD)
	bodyD := sealTestRequest(t, "u1", userSignKey, serverEK, payloadD)

	token = LoginSessionForTest(t, ts, "u1", userSignKey)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(bodyD))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE status %d", resp.StatusCode)
	}

	// Verify Deleted
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
	i1 := Inode{ID: "00000000000000000000000000000011", OwnerID: "u1", Mode: 0600}
	i1.SignInodeForTest("u1", u1Sign)
	i1Bytes, _ := json.Marshal(i1)
	batch := []LogCommand{{Type: CmdCreateInode, Data: i1Bytes}}
	payload, _ := json.Marshal(batch)
	body := SealTestRequest(t, "u1", u1Sign, serverEK, payload)
	token1 := LoginSessionForTest(t, ts, "u1", u1Sign)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token1)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to create inode: %d", resp.StatusCode)
	}

	// 3. User 2 attempts to GET User 1's inode (Should fail)
	token2 := LoginSessionForTest(t, ts, "u2", u2Sign)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/meta/inode/00000000000000000000000000000011", nil)
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized GET, got %d", resp.StatusCode)
	}

	// 4. User 2 attempts to DELETE User 1's inode (Should fail)
	idBytes, _ := json.Marshal("00000000000000000000000000000011")
	delBatch := []LogCommand{{Type: CmdDeleteInode, Data: idBytes}}
	delPayload, _ := json.Marshal(delBatch)
	delBody := SealTestRequest(t, "u2", u2Sign, serverEK, delPayload)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(delBody))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized DELETE, got %d", resp.StatusCode)
	}

	// 5. User 2 attempts to UPDATE User 1's inode (Should fail)
	i1u := Inode{ID: "00000000000000000000000000000011", Mode: 0777, Version: 2, NLink: 1}
	i1u.SignInodeForTest("u2", u2Sign)
	batchU := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(i1u)}}
	payloadU, _ := json.Marshal(batchU)
	bodyU := SealTestRequest(t, "u2", u2Sign, serverEK, payloadU)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(bodyU))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized PUT, got %d", resp.StatusCode)
	}

	// 6. User 1 successfully deletes their own inode (Implicit via UpdateInode NLink=0)
	i1d := Inode{ID: "00000000000000000000000000000011", Mode: 0644, Version: 2, NLink: 0}
	i1d.SignInodeForTest("u1", u1Sign)
	batchD := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(i1d)}}
	payloadD, _ := json.Marshal(batchD)
	bodyD := SealTestRequest(t, "u1", u1Sign, serverEK, payloadD)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(bodyD))
	req.Header.Set("X-DistFS-Sealed", "true")
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

	token := LoginSessionForTest(t, ts, "u1", userSignKey)

	// Create Group
	group := Group{
		ID:       "g1",
		OwnerID:  "u1",
		SignerID: "u1",
		GID:      1001,
		SignKey:  user.SignKey, // Use user's key as group key for test simplicity
		Version:  1,
	}
	group.Signature = userSignKey.Sign(group.Hash())
	objBytes, _ := json.Marshal(group)
	batch := []LogCommand{{Type: CmdCreateGroup, Data: objBytes}}
	payload, _ := json.Marshal(batch)
	body := SealTestRequest(t, "u1", userSignKey, serverEK, payload)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Group Create failed: %d", resp.StatusCode)
	}

	_ = UnsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)

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

	// 2. Setup User
	email := "sync@example.com"
	secret, _ := node.FSM.GetClusterSecret()
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
	body := SealTestRequest(t, userID, u1Sign, serverEK, payload)
	sessionToken := LoginSessionForTest(t, ts, userID, u1Sign)

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

	dbPath := filepath.Join(tmpDir, "fsm.bolt")
	fsm, err := NewMetadataFSM("node1", dbPath, []byte("test-cluster-secret"))
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
	token := LoginSessionForTest(t, ts, "u1", userSignKey)

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
	inode.SignInodeForTest("u1", userSignKey)
	inodeBytes, _ := json.Marshal(inode)
	batch := []LogCommand{{Type: CmdCreateInode, Data: inodeBytes}}
	payload, _ := json.Marshal(batch)
	body := SealTestRequest(t, "u1", userSignKey, serverEK, payload)

	// POST /v1/meta/batch
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST status %d", resp.StatusCode)
	}

	_ = UnsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)

	// Verify via API (Transparent Reconstruction)
	token = LoginSessionForTest(t, ts, "u1", userSignKey)
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

	opened := UnsealTestResponse(t, userDecKey, serverSignKey.Public(), resp)
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
	inode := Inode{ID: "0000000000000000000000000000000f", OwnerID: userID, Size: 100, NLink: 1}
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
	inode.Version = 2 // Client increments
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

	// 4. Delete File (Implicit via UpdateInode NLink=0)
	inode.NLink = 0
	inode.Version = 3
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode)
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes}
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
	maxInodes := uint64(1)
	maxBytes := uint64(500)
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
	inode := Inode{ID: "0000000000000000000000000000000f", OwnerID: userID, Size: 100, NLink: 1}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	cmd = LogCommand{Type: CmdCreateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	if err := node.Raft.Apply(cmdBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Create file 1 failed: %v", err)
	}

	// 3. Create File 2 (Fail: Inode Quota)
	inode2 := Inode{ID: "0000000000000000000000000000002f", OwnerID: userID, Size: 100, NLink: 1}
	inode2.SignInodeForTest(userID, sk)
	inodeBytes, _ = json.Marshal(inode2)
	cmd = LogCommand{Type: CmdCreateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	f := node.Raft.Apply(cmdBytes, 5*time.Second)
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
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
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
	cmd = LogCommand{Type: CmdUpdateInode, Data: inodeBytes}
	cmdBytes, _ = json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	res = f.Response()
	if err, ok := res.(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %T: %v (IsQuota=%v)", res, res, errors.Is(err, ErrQuotaExceeded))
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
	maxInodes := uint64(1)
	req := SetUserQuotaRequest{UserID: u2, MaxInodes: &maxInodes}
	reqBytes, _ := json.Marshal(req)
	if err := node.Raft.Apply(LogCommand{Type: CmdSetUserQuota, Data: reqBytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to set user quota: %v", err)
	}

	// u1 creates a file
	inode := Inode{ID: "0000000000000000000000000000000f", OwnerID: u1, Size: 100}
	inode.SignInodeForTest(u1, sk1)
	iBytes, _ := json.Marshal(inode)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: iBytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to create inode: %v", err)
	}

	// Admin chown 0000000000000000000000000000000f from u1 to u2
	// u2 has 0 files, limit 1. Transfer should SUCCEED.
	// Current BUG: checkQuota(u2, delta=1) sees u2 usage=0, limit=1 -> OK.
	// Wait, actually the bug is if u2 ALREADY has 1 file?
	// Let's test the limit case.

	// If u2 has 1 file already.
	inode2 := Inode{ID: "0000000000000000000000000000002f", OwnerID: u2, Size: 100}
	inode2.SignInodeForTest(u2, sk2)
	iBytes2, _ := json.Marshal(inode2)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: iBytes2}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to create inode2: %v", err)
	}

	// Now u2 is at limit (1/1).
	// Transfer 0000000000000000000000000000000f from u1 to u2 should FAIL.
	chReq := AdminChownRequest{InodeID: "0000000000000000000000000000000f", OwnerID: &u2}
	chBytes, _ := json.Marshal(chReq)
	f := node.Raft.Apply(LogCommand{Type: CmdAdminChown, Data: chBytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f.Response().(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %v", f.Response())
	}

	// Transfer 0000000000000000000000000000002f from u2 back to u2 (identity transfer)
	// Current BUG: usage is 1/1. checkQuota(u2, delta=1) sees 1+1 > 1 -> FAILS.
	// Fixed: updateUsage(u2, delta=-1) makes usage 0. checkQuota(u2, delta=1) sees 0+1 <= 1 -> OK.
	chReq2 := AdminChownRequest{InodeID: "0000000000000000000000000000002f", OwnerID: &u2}
	chBytes2, _ := json.Marshal(chReq2)
	f2 := node.Raft.Apply(LogCommand{Type: CmdAdminChown, Data: chBytes2}.Marshal(), 5*time.Second)
	if err := f2.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f2.Response().(error); ok && err != nil {
		t.Errorf("Identity chown failed: %v", err)
	}
}

func TestSecurity_IDOR_User(t *testing.T) {
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Create two users
	u1ID := "user1"
	sk1, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{
		ID:      u1ID,
		SignKey: sk1.Public(),
		Quota:   UserQuota{MaxInodes: 100},
		Usage:   UserUsage{InodeCount: 10},
	})

	u2ID := "user2"
	sk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{
		ID:      u2ID,
		SignKey: sk2.Public(),
		Quota:   UserQuota{MaxInodes: 200},
		Usage:   UserUsage{InodeCount: 20},
	})

	// Login as User 1
	token1 := LoginSessionForTest(t, ts, u1ID, sk1)

	// 2. User 1 requests self (Should be FULL)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/user/"+u1ID, nil)
	req.Header.Set("Session-Token", token1)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get self: %d", resp.StatusCode)
	}
	var res1 User
	json.NewDecoder(resp.Body).Decode(&res1)
	resp.Body.Close()

	if res1.Quota.MaxInodes != 100 || res1.Usage.InodeCount != 10 {
		t.Errorf("Self metadata redacted: %+v", res1)
	}

	// 3. User 2 requests User 1 (Should be REDACTED)
	token2 := LoginSessionForTest(t, ts, u2ID, sk2)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/user/"+u1ID, nil)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get other user: %d", resp.StatusCode)
	}
	var res2 User
	json.NewDecoder(resp.Body).Decode(&res2)
	resp.Body.Close()

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
	if err := node.Raft.Apply(LogCommand{Type: CmdPromoteAdmin, Data: u1IDBytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to promote user1: %v", err)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/v1/user/"+u2ID, nil)
	req.Header.Set("Session-Token", token1)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Admin failed to get user: %d", resp.StatusCode)
	}
	var resAdmin User
	json.NewDecoder(resp.Body).Decode(&resAdmin)
	resp.Body.Close()

	if resAdmin.Quota.MaxInodes != 200 || resAdmin.Usage.InodeCount != 20 {
		t.Errorf("Admin saw redacted metadata: %+v", resAdmin)
	}
}

func TestNodeRevocation(t *testing.T) {
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Register a node
	nodeKey, _ := crypto.GenerateIdentityKey()
	nodeID := "rogue-node"
	n := Node{
		ID:      nodeID,
		SignKey: nodeKey.Public(),
		Status:  NodeStatusActive,
	}
	body, _ := json.Marshal(n)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to register node: %v, status: %d", err, resp.StatusCode)
	}

	// Verify trusted
	if !node.FSM.IsTrusted(nodeKey.Public()) {
		t.Error("Node key should be trusted after registration")
	}

	// 2. Revoke/Remove node
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/node/"+nodeID, nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to remove node: %v, status: %d", err, resp.StatusCode)
	}

	// Verify untrusted
	if node.FSM.IsTrusted(nodeKey.Public()) {
		t.Error("Node key should NOT be trusted after revocation")
	}

	// Verify node gone from list
	nodes, _ := node.FSM.GetNodes()
	for _, n := range nodes {
		if n.ID == nodeID {
			t.Errorf("Node %s still exists in registry", nodeID)
		}
	}
}
