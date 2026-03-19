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

package data

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func TestSecurity_ClusterSignKey(t *testing.T) {
	node, ts, serverSignKey, _, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setup User
	u1Dec, _ := crypto.GenerateEncryptionKey()
	u1Sign, _ := crypto.GenerateIdentityKey()
	u1 := metadata.User{
		ID:      "u1",
		SignKey: u1Sign.Public(),
		EncKey:  u1Dec.EncapsulationKey().Bytes(),
	}
	metadata.CreateUser(t, node, u1)

	token1, secret1 := metadata.LoginSessionForTestWithSecret(t, ts, "u1", u1Sign)

	// Create Inode so token issuance succeeds (exists=true check)
	inode := metadata.Inode{
		ID:      "file1",
		OwnerID: "u1",
		Mode:    0644,
	}
	inodeBytes, _ := json.Marshal(inode)
	lcmdBytes, err := metadata.LogCommand{Type: metadata.CmdCreateInode, Data: inodeBytes}.Marshal()
	if err != nil {
		t.Fatalf("LogCommand Marshal failed: %v", err)
	}
	f := node.Raft.Apply(lcmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("CreateInode failed: %v", err)
	}

	// 2. Request a valid token from Leader (Cluster-signed)
	reqBody := struct {
		InodeID string   `json:"inode_id"`
		Chunks  []string `json:"chunks"`
		Mode    string   `json:"mode"`
	}{
		InodeID: "file1",
		Chunks:  []string{"chunk1"},
		Mode:    "W",
	}
	payload, _ := json.Marshal(reqBody)
	// Must seal POST requests to /v1/meta/token
	body := metadata.SealTestRequestSymmetric(t, "u1", u1Sign, secret1, payload)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/token", bytes.NewReader(body))
	req.Header.Set("Session-Token", token1)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to request token: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("Failed to get token: %d %s", resp.StatusCode, string(b))
	}

	opened := metadata.UnsealTestResponseWithSession(t, u1Dec, secret1, serverSignKey.Public(), resp)

	var signedToken metadata.SignedAuthToken
	if err := json.Unmarshal(opened, &signedToken); err != nil {
		t.Fatalf("Failed to unmarshal token: %v", err)
	}
	resp.Body.Close()

	if signedToken.SignerID != "" {
		t.Errorf("Expected empty SignerID for cluster-signed token, got %s", signedToken.SignerID)
	}

	// 3. Verify with Data Node Logic (Strict metaPubKey check)
	clusterPub, _ := node.FSM.GetClusterSignPublicKey()

	tmpDir := t.TempDir()
	stChunks, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(stChunks)
	dataSrv := NewServer(store, clusterPub, nil, NoopValidator{}, true, true)

	// Validate valid token
	authReq, _ := http.NewRequest("GET", "/v1/data/chunk1", nil)
	tokenStr := base64.StdEncoding.EncodeToString(signedToken.Marshal())
	authReq.Header.Set("Authorization", "Bearer "+tokenStr)

	// Session Locking: Provide the actual session token used to issue the capability
	authReq.Header.Set("Session-Token", token1)

	err = dataSrv.Internal_Authenticate(authReq, "chunk1", "W")
	if err != nil {
		t.Errorf("Data server rejected valid cluster-signed token: %v", err)
	}

	// 4. FORGERY: Sign a token using a Node's individual key (legacy/malicious behavior)
	capToken := metadata.CapabilityToken{
		Chunks: []string{"chunk1"},
		Mode:   "W",
		Exp:    time.Now().Add(time.Hour).Unix(),
	}
	payload, _ = json.Marshal(capToken)
	badSig := serverSignKey.Sign(payload)
	forgedToken := metadata.SignedAuthToken{
		SignerID:  "node-1",
		Payload:   payload,
		Signature: badSig,
	}

	forgedReq, _ := http.NewRequest("GET", "/v1/data/chunk1", nil)
	forgedTokenStr := base64.StdEncoding.EncodeToString(forgedToken.Marshal())
	forgedReq.Header.Set("Authorization", "Bearer "+forgedTokenStr)

	err = dataSrv.Internal_Authenticate(forgedReq, "chunk1", "W")
	if err == nil {
		t.Error("Data server ACCEPTED forged node-signed token (expected rejection)")
	}
}

func TestDiskStore(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, err := NewDiskStore(st)
	if err != nil {
		t.Fatalf("NewDiskStore failed: %v", err)
	}

	content := []byte("hello world")
	h := sha256.Sum256(content)
	chunkID := hex.EncodeToString(h[:])

	// 1. Write
	if err := store.WriteChunk(chunkID, bytes.NewReader(content)); err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}

	// 2. Read
	rc, err := store.ReadChunk(chunkID)
	if err != nil {
		t.Fatalf("ReadChunk failed: %v", err)
	}
	readContent, _ := io.ReadAll(rc)
	rc.Close()
	if string(readContent) != string(content) {
		t.Errorf("Content mismatch: got %s, want %s", readContent, content)
	}

	// 2.5 GetChunkSize
	sz, err := store.GetChunkSize(chunkID)
	if err != nil {
		t.Errorf("GetChunkSize failed: %v", err)
	}
	// Note: Encrypted size > Plaintext size.
	// We expect size >= len(content).
	if sz < int64(len(content)) {
		t.Errorf("Size mismatch: got %d, want >= %d", sz, len(content))
	}

	// 3. HasChunk
	has, _ := store.HasChunk(chunkID)
	if !has {
		t.Error("HasChunk returned false")
	}

	// 4. List (Iterator)
	count := 0
	for id, err := range store.ListChunks() {
		if err != nil {
			t.Fatalf("ListChunks error: %v", err)
		}
		if id != chunkID {
			t.Errorf("ListChunks ID mismatch: %s", id)
		}
		count++
	}
	if count != 1 {
		t.Errorf("ListChunks count %d", count)
	}

	// 5. Delete
	if err := store.DeleteChunk(chunkID); err != nil {
		t.Fatalf("DeleteChunk failed: %v", err)
	}
	has, _ = store.HasChunk(chunkID)
	if has {
		t.Error("HasChunk true after delete")
	}
}

func TestIntegrityScrubber(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(st)

	content := []byte("valid data")
	h := sha256.Sum256(content)
	id := hex.EncodeToString(h[:])

	if err := store.WriteChunk(id, bytes.NewReader(content)); err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}

	scrubber := NewIntegrityScrubber(store, time.Millisecond*100)

	// Verify Valid
	if err := scrubber.verifyChunk(id); err != nil {
		t.Errorf("verifyChunk failed on valid chunk: %v", err)
	}

	// Corrupt it manually
	// Storage files are sharded
	shard := id[:2]
	path := filepath.Join(tmpDir, shard, id)

	// Overwrite with garbage
	if err := os.WriteFile(path, []byte("garbage"), 0600); err != nil {
		t.Fatalf("Failed to corrupt file at %s: %v", path, err)
	}

	// Verify Corrupt
	if err := scrubber.verifyChunk(id); err == nil {
		t.Error("verifyChunk passed on corrupt chunk")
	}

	// Test Start/Stop Loop
	scrubber.Start()
	time.Sleep(150 * time.Millisecond)
	scrubber.Stop()
}

func TestDiskStore_WriteError(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(st)

	h := sha256.Sum256([]byte("fail"))
	id := hex.EncodeToString(h[:])

	// Make shard dir read-only to force write error
	shardDir := filepath.Join(tmpDir, id[:2])
	if err := os.Chmod(shardDir, 0500); err != nil {
		t.Skip("Cannot chmod")
	}

	if err := store.WriteChunk(id, bytes.NewReader([]byte("fail"))); err == nil {
		t.Error("Expected error writing to readonly dir")
	}

	os.Chmod(shardDir, 0755) // Restore
}

func TestAPI(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(st)

	pub, sk := setupTestAuth(t)
	server := NewServer(store, pub, nil, NoopValidator{}, true, true)
	ts := httptest.NewServer(server)
	defer ts.Close()

	content := []byte("api content")
	h := sha256.Sum256(content)
	chunkID := hex.EncodeToString(h[:])

	// PUT
	req, _ := http.NewRequest("PUT", ts.URL+"/v1/data/"+chunkID, bytes.NewReader(content))
	req.Header.Set("Authorization", signTestToken(t, sk, []string{chunkID}, "W"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("PUT status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify stored
	has, _ := store.HasChunk(chunkID)
	if !has {
		t.Error("Chunk not stored after PUT")
	}

	// GET
	req, _ = http.NewRequest("GET", ts.URL+"/v1/data/"+chunkID, nil)
	req.Header.Set("Authorization", signTestToken(t, sk, []string{chunkID}, "R"))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != string(content) {
		t.Errorf("GET mismatch")
	}

	// Verify Invalid ID
	resp, _ = http.Get(ts.URL + "/v1/data/bad-id")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for bad ID, got %d", resp.StatusCode)
	}

	// Test Method Not Allowed
	req2, _ := http.NewRequest("POST", ts.URL+"/v1/data/"+chunkID, nil)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", resp2.StatusCode)
	}

	// Test PUT Too Large (3MB) - Should SUCCEED with storage lib
	large := make([]byte, 3*1024*1024)
	reqLarge, _ := http.NewRequest("PUT", ts.URL+"/v1/data/"+chunkID, bytes.NewReader(large))
	reqLarge.Header.Set("Authorization", signTestToken(t, sk, []string{chunkID}, "W"))
	respLarge, _ := http.DefaultClient.Do(reqLarge)
	if respLarge.StatusCode != http.StatusCreated { // Changed expectation
		t.Errorf("Expected 201 for large body, got %d", respLarge.StatusCode)
	}
}

func TestDiskStore_TempFiles(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(st)

	// Create temp files
	os.Create(filepath.Join(tmpDir, "tmp-123"))
	os.Create(filepath.Join(tmpDir, "tmp-456"))

	count := 0
	for range store.ListChunks() {
		count++
	}
	if count != 0 {
		t.Errorf("ListChunks should ignore tmp files, got %d", count)
	}
}

func TestDiskStore_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(st)

	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Read missing
	_, err := store.ReadChunk(id)
	if err == nil {
		t.Error("ReadChunk should fail for missing chunk")
	}

	// Size missing
	_, err = store.GetChunkSize(id)
	if err == nil {
		t.Error("GetChunkSize should fail for missing chunk")
	}

	// Delete missing
	err = store.DeleteChunk(id)
	if err == nil {
		t.Error("DeleteChunk should fail for missing chunk")
	}

	// Invalid ID formats
	badID := "too-short"
	if err := store.WriteChunk(badID, nil); err == nil {
		t.Error("WriteChunk should fail for bad ID")
	}
	if _, err := store.ReadChunk(badID); err == nil {
		t.Error("ReadChunk should fail for bad ID")
	}
}

func TestAPI_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(st)

	pub, sk := setupTestAuth(t)
	server := NewServer(store, pub, nil, NoopValidator{}, true, true)
	ts := httptest.NewServer(server)
	defer ts.Close()

	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	store.WriteChunk(id, bytes.NewReader([]byte("data")))

	// DELETE
	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/data/"+id, nil)
	req.Header.Set("Authorization", signTestToken(t, sk, []string{id}, "D"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE failed: %d", resp.StatusCode)
	}

	// Verify gone
	has, _ := store.HasChunk(id)
	if has {
		t.Error("Chunk still exists after DELETE")
	}

	// DELETE missing
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/data/"+id, nil)
	req.Header.Set("Authorization", signTestToken(t, sk, []string{id}, "D"))
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for missing DELETE, got %d", resp.StatusCode)
	}
}

func createTestStore(t *testing.T) (*DiskStore, string) {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)
	ds, _ := NewDiskStore(st)
	return ds, tmpDir
}

func signToken(t *testing.T, sk *crypto.IdentityKey, chunks []string, mode string) string {
	cap := metadata.CapabilityToken{
		Chunks: chunks,
		Mode:   mode,
		Exp:    time.Now().Add(1 * time.Hour).Unix(),
	}
	payload, _ := json.Marshal(cap)
	sig := sk.Sign(payload)
	signed := metadata.SignedAuthToken{
		Payload:   payload,
		Signature: sig,
	}
	b, _ := json.Marshal(signed)
	return base64.StdEncoding.EncodeToString(b)
}

func TestData_DiskStoreExtra(t *testing.T) {
	ds, tmpDir := createTestStore(t)
	defer ds.Close()

	// 1. Stats
	_, _, err := ds.Stats()
	if err != nil {
		t.Errorf("Stats failed: %v", err)
	}

	// Stats error (missing dir)
	os.RemoveAll(tmpDir)
	_, _, err = ds.Stats()
	if err == nil {
		t.Error("Stats should fail for missing directory")
	}

	// 2. ListChunks error path (missing dir)
	os.RemoveAll(tmpDir)
	it := ds.ListChunks()
	for _, err := range it {
		if err == nil {
			t.Error("Expected error from ListChunks after dir removal")
		}
	}

	// 3. Quarantine missing
	err = ds.QuarantineChunk("0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("Quarantine should fail for missing chunk")
	}

	// 4. GetChunkSize missing
	_, err = ds.GetChunkSize("0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("GetChunkSize should fail for missing chunk")
	}
}

func TestData_APIHandlersExtra(t *testing.T) {
	ds, _ := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{}, true, true)

	id1 := "1111111111111111111111111111111111111111111111111111111111111111"
	id2 := "2222222222222222222222222222222222222222222222222222222222222222"
	ds.WriteChunk(id1, bytes.NewReader([]byte("data 1")))
	ds.WriteChunk(id2, bytes.NewReader([]byte("data 2")))

	// 1. handleDelete (Success)
	token1 := signToken(t, usk, []string{id1}, "D")
	req, _ := http.NewRequest("DELETE", "/v1/data/"+id1, nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleDelete failed: %d %s", rr.Code, rr.Body.String())
	}

	// 2. handleGet (Success)
	token2 := signToken(t, usk, []string{id2}, "R")
	req, _ = http.NewRequest("GET", "/v1/data/"+id2, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleGet failed: %d %s", rr.Code, rr.Body.String())
	}

	// 3. handleGet (Missing)
	missingID := "3333333333333333333333333333333333333333333333333333333333333333"
	token3 := signToken(t, usk, []string{missingID}, "R")
	req, _ = http.NewRequest("GET", "/v1/data/"+missingID, nil)
	req.Header.Set("Authorization", "Bearer "+token3)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("handleGet should return 404 for missing chunk, got %d", rr.Code)
	}

	// 4. handleReplicate (Success with NoopValidator)
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts2.Close()

	reqBody, _ := json.Marshal(map[string][]string{"targets": {ts2.URL}})
	req, _ = http.NewRequest("POST", "/v1/data/"+id2+"/replicate", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token2)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleReplicate failed: %d %s", rr.Code, rr.Body.String())
	}

	// 5. handleReplicate (Denied by Validator)
	serverDeny := NewServer(ds, usk.Public(), nil, DenyAllValidator{}, true, true)
	req, _ = http.NewRequest("POST", "/v1/data/"+id2+"/replicate", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token2)
	rr = httptest.NewRecorder()
	serverDeny.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("handleReplicate should fail with BadGateway when validator denies, got %d", rr.Code)
	}

	// 6. handlePut (With Replicas)
	token4 := signToken(t, usk, []string{id1}, "W")
	req, _ = http.NewRequest("PUT", "/v1/data/"+id1+"?replicas="+ts2.URL, bytes.NewReader([]byte("new data")))
	req.Header.Set("Authorization", "Bearer "+token4)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Errorf("handlePut with replicas failed: %d %s", rr.Code, rr.Body.String())
	}

	// 7. handleGet store error (unreadable)
	unreadableID := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffffffffffff"
	ds.WriteChunk(unreadableID, bytes.NewReader([]byte("unreadable")))
	path := filepath.Join(ds.st.Dir(), getShardPath(unreadableID))
	os.Chmod(path, 0000)
	defer os.Chmod(path, 0644)

	tokenUnreadable := signToken(t, usk, []string{unreadableID}, "R")
	req, _ = http.NewRequest("GET", "/v1/data/"+unreadableID, nil)
	req.Header.Set("Authorization", "Bearer "+tokenUnreadable)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("handleGet should return 500 for unreadable chunk, got %d", rr.Code)
	}

	// 8. ServeHTTP nested path not replicate
	req, _ = http.NewRequest("POST", "/v1/data/"+id2+"/notreplicate", nil)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("ServeHTTP should return 404 for unknown nested path, got %d", rr.Code)
	}

	// 9. ServeHTTP deep path
	req, _ = http.NewRequest("GET", "/v1/data/"+id2+"/too/deep", nil)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("ServeHTTP should return 404 for too deep path, got %d", rr.Code)
	}

	// 10. Authentication failures
	sNoKey := NewServer(ds, nil, nil, nil, true, true)
	req, _ = http.NewRequest("GET", "/v1/data/"+id2, nil)
	aerr := sNoKey.Internal_Authenticate(req, id2, "R")
	if aerr == nil || !strings.Contains(aerr.Error(), "cluster signing key not available") {
		t.Errorf("Expected key not available error, got %v", aerr)
	}

	req, _ = http.NewRequest("GET", "/v1/data/"+id2, nil)
	aerr = server.Internal_Authenticate(req, id2, "R")
	if aerr == nil {
		t.Error("Internal_Authenticate should fail for missing auth")
	}

	req.Header.Set("Authorization", "not-bearer")
	aerr = server.Internal_Authenticate(req, id2, "R")
	if aerr == nil {
		t.Error("Internal_Authenticate should fail for non-bearer auth")
	}

	req.Header.Set("Authorization", "Bearer invalid-base64")
	aerr = server.Internal_Authenticate(req, id2, "R")
	if aerr == nil {
		t.Error("Internal_Authenticate should fail for invalid base64")
	}

	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte("invalid-json")))
	aerr = server.Internal_Authenticate(req, id2, "R")
	if aerr == nil {
		t.Error("Internal_Authenticate should fail for invalid JSON")
	}

	// 11. Replicate with multiple targets, some failing
	tsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tsFail.Close()

	reqBody, _ = json.Marshal(map[string][]string{"targets": {ts2.URL, tsFail.URL}})
	req, _ = http.NewRequest("POST", "/v1/data/"+id2+"/replicate", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token2)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("handleReplicate should return 502 if any target fails, got %d", rr.Code)
	}
	// 12. handleReplicate (No targets)
	reqBody, _ = json.Marshal(map[string][]string{"targets": {}})
	req, _ = http.NewRequest("POST", "/v1/data/"+id2+"/replicate", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token2)
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleReplicate should return 400 for no targets, got %d", rr.Code)
	}
}

func TestData_ScrubberErrors(t *testing.T) {
	ds, _ := createTestStore(t)
	scrubber := NewIntegrityScrubber(ds, 1*time.Hour)

	// 1. Scrub with unreadable chunk
	unreadableID := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffffffffffff"
	ds.WriteChunk(unreadableID, bytes.NewReader([]byte("unreadable")))
	path := filepath.Join(ds.st.Dir(), getShardPath(unreadableID))
	os.Chmod(path, 0000)
	defer os.Chmod(path, 0644)

	scrubber.scrub()
}

func TestData_NewServerExtra(t *testing.T) {
	ds, _ := createTestStore(t)

	// 1. With FSM
	s1 := NewServer(ds, nil, &metadata.MetadataFSM{}, nil, true, true)
	if s1.validator == nil {
		t.Error("Validator should be set from FSM")
	}

	// 2. Without FSM, without Validator
	s2 := NewServer(ds, nil, nil, nil, true, true)
	if _, ok := s2.validator.(DenyAllValidator); !ok {
		t.Errorf("Expected DenyAllValidator, got %T", s2.validator)
	}
}

func TestData_Validators(t *testing.T) {
	dv := DenyAllValidator{}
	if err := dv.ValidateNode("any"); err == nil {
		t.Error("DenyAllValidator should deny all")
	}

	nv := NoopValidator{}
	if err := nv.ValidateNode("any"); err != nil {
		t.Errorf("NoopValidator should allow all, got %v", err)
	}
}

func TestData_ScrubberExtra(t *testing.T) {
	ds, tmpDir := createTestStore(t)
	scrubber := NewIntegrityScrubber(ds, 1*time.Hour)

	// 1. Create a valid chunk
	data := []byte("valid data")
	hash := sha256.Sum256(data)
	id := hex.EncodeToString(hash[:])
	ds.WriteChunk(id, bytes.NewReader(data))

	// 2. Create a corrupted chunk (id mismatch)
	corruptID := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	ds.WriteChunk(corruptID, bytes.NewReader([]byte("corrupt")))

	// 3. Create an unreadable chunk (permission denied)
	unreadableID := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffffffffffff"
	ds.WriteChunk(unreadableID, bytes.NewReader([]byte("unreadable")))
	path := filepath.Join(tmpDir, getShardPath(unreadableID))
	os.Chmod(path, 0000)
	defer os.Chmod(path, 0644) // Clean up

	// 4. Trigger scrub
	scrubber.scrub()

	// 5. Verify corruptID is quarantined (gone from store)
	exists, _ := ds.HasChunk(corruptID)
	if exists {
		t.Error("Corrupted chunk should have been quarantined")
	}

	// 6. Stop scrubber
	scrubber.Stop()
}

func TestData_DiskStoreErrors(t *testing.T) {
	ds, _ := createTestStore(t)

	// 1. WriteChunk bad ID
	err := ds.WriteChunk("too-short", bytes.NewReader([]byte("data")))
	if err == nil {
		t.Error("WriteChunk should fail for bad ID")
	}

	// 2. ReadChunk missing
	_, err = ds.ReadChunk("0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("ReadChunk should fail for missing chunk")
	}

	// 3. DeleteChunk missing
	err = ds.DeleteChunk("0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("DeleteChunk should fail for missing chunk")
	}

	// 4. DeleteChunk error (read-only dir)
	idD := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	ds.WriteChunk(idD, bytes.NewReader([]byte("data")))
	shardDir := filepath.Join(ds.st.Dir(), idD[:2])
	os.Chmod(shardDir, 0500)
	defer os.Chmod(shardDir, 0700)
	err = ds.DeleteChunk(idD)
	if err == nil {
		t.Error("DeleteChunk should fail for read-only shard directory")
	}

	// 4. HasChunk error (unreadable)
	idH := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ds.WriteChunk(idH, bytes.NewReader([]byte("data")))
	pathH := filepath.Join(ds.st.Dir(), getShardPath(idH))
	os.Chmod(pathH, 0000)
	defer os.Chmod(pathH, 0644)
	_, err = ds.HasChunk(idH)
	if err == nil {
		t.Error("HasChunk should fail for unreadable file")
	}

	// 3. WriteChunk directory error
	id := "2222222222222222222222222222222222222222222222222222222222222222"
	// Make shard store dir read-only
	shardDir = filepath.Join(ds.st.Dir(), id[:2])
	os.Chmod(shardDir, 0500)
	defer os.Chmod(shardDir, 0700)

	err = ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	if err == nil {
		t.Error("WriteChunk should fail for read-only store directory")
	}
}

func TestData_ReplicationErrors(t *testing.T) {
	ds, _ := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{}, true, true)

	// 1. Replicate missing chunk
	id := "3333333333333333333333333333333333333333333333333333333333333333"
	err := server.replicate(id, "http://localhost:1234", "", "token", "")
	if err == nil {
		t.Error("replicate should fail for missing chunk")
	}
}

func TestData_Scrubber_QuarantineFail(t *testing.T) {
	ds, _ := createTestStore(t)
	scrubber := NewIntegrityScrubber(ds, 1*time.Hour)

	// 1. Create a corrupted chunk
	corruptID := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	ds.WriteChunk(corruptID, bytes.NewReader([]byte("corrupt")))

	// 2. Make shard dir read-only to make QuarantineChunk (rename) fail
	shardDir := filepath.Join(ds.st.Dir(), corruptID[:2])
	os.Chmod(shardDir, 0500)
	defer os.Chmod(shardDir, 0700)

	// 3. Trigger scrub
	scrubber.scrub()
	// Should log failure and continue
}

func TestServer_Get_Abort(t *testing.T) {
	ds, _ := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{}, true, true)

	id := "4444444444444444444444444444444444444444444444444444444444444444"
	// Write large chunk to make Copy take time
	ds.WriteChunk(id, bytes.NewReader(make([]byte, 1024*1024)))

	ts := httptest.NewServer(server)
	defer ts.Close()

	token := signToken(t, usk, []string{id}, "R")
	req, _ := http.NewRequest("GET", ts.URL+"/v1/data/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{
		Timeout: 50 * time.Millisecond, // Force abort
	}
	client.Do(req)
	// Should hit io.Copy error branch
}

func TestData_Replication_NetworkError(t *testing.T) {
	ds, _ := createTestStore(t)
	server := NewServer(ds, nil, nil, NoopValidator{}, true, true)

	id := "5555555555555555555555555555555555555555555555555555555555555555"
	ds.WriteChunk(id, bytes.NewReader([]byte("data")))

	// Replicate to invalid address
	err := server.replicate(id, "http://invalid.domain", "", "token", "")
	if err == nil {
		t.Error("replicate should fail for invalid domain")
	}
}

func TestData_DiskStoreShortID(t *testing.T) {
	path := getShardPath("a")
	if path != "a" {
		t.Errorf("Expected 'a', got %s", path)
	}

	ds, _ := createTestStore(t)
	// 1. Idempotency
	id := "1111111111111111111111111111111111111111111111111111111111111111"
	ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	err := ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	if err != nil {
		t.Errorf("Second WriteChunk failed: %v", err)
	}

	// 2. ListChunks skips .tmp
	tmpFile := filepath.Join(ds.st.Dir(), "00", "0000000000000000000000000000000000000000000000000000000000000000.tmp")
	os.MkdirAll(filepath.Dir(tmpFile), 0700)
	os.WriteFile(tmpFile, []byte("tmp"), 0600)

	count := 0
	for cid, _ := range ds.ListChunks() {
		if strings.HasSuffix(cid, ".tmp") {
			t.Error("ListChunks should skip .tmp files")
		}
		if cid != "" {
			count++
		}
	}
	// 3. ListChunks break
	ds.WriteChunk("2222222222222222222222222222222222222222222222222222222222222222", bytes.NewReader([]byte("data")))
	for _, _ = range ds.ListChunks() {
		break // Hits !yield branch
	}
}

func TestData_Internal_Authenticate(t *testing.T) {
	sk, _ := crypto.GenerateIdentityKey()
	pub := sk.Public()
	store, _ := NewDiskStore(storage.New(t.TempDir(), nil))
	server := NewServer(store, pub, nil, NoopValidator{}, true, true)

	cid := "0000000000000000000000000000000000000000000000000000000000000000"

	// 1. Missing Auth
	req, _ := http.NewRequest("GET", "/v1/data/"+cid, nil)
	if err := server.Internal_Authenticate(req, cid, "R"); err == nil || !strings.Contains(err.Error(), "missing auth") {
		t.Errorf("Expected missing auth error, got %v", err)
	}

	// 2. Invalid token format
	req.Header.Set("Authorization", "Bearer notbase64")
	if err := server.Internal_Authenticate(req, cid, "R"); err == nil || !strings.Contains(err.Error(), "invalid token format") {
		t.Errorf("Expected invalid token format error, got %v", err)
	}

	// 3. Invalid token structure
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte("invalid json")))
	if err := server.Internal_Authenticate(req, cid, "R"); err == nil || !strings.Contains(err.Error(), "invalid token structure") {
		t.Errorf("Expected invalid token structure error, got %v", err)
	}

	// 4. Invalid signature
	cap := metadata.CapabilityToken{
		Chunks: []string{cid},
		Mode:   "R",
		Exp:    time.Now().Add(time.Hour).Unix(),
	}
	capB, _ := json.Marshal(cap)
	signed := metadata.SignedAuthToken{
		Payload:   capB,
		Signature: make([]byte, 64),
	}
	signedB, _ := json.Marshal(signed)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(signedB))
	if err := server.Internal_Authenticate(req, cid, "R"); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("Expected invalid signature error, got %v", err)
	}

	// 5. Token expired
	cap.Exp = time.Now().Add(-time.Hour).Unix()
	capB, _ = json.Marshal(cap)
	sig := sk.Sign(capB)
	signed.Payload = capB
	signed.Signature = sig
	signedB, _ = json.Marshal(signed)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(signedB))
	if err := server.Internal_Authenticate(req, cid, "R"); err == nil || !strings.Contains(err.Error(), "token expired") {
		t.Errorf("Expected token expired error, got %v", err)
	}

	// 6. Permission denied
	cap.Exp = time.Now().Add(time.Hour).Unix()
	cap.Mode = "W"
	capB, _ = json.Marshal(cap)
	sig = sk.Sign(capB)
	signed.Payload = capB
	signed.Signature = sig
	signedB, _ = json.Marshal(signed)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(signedB))
	if err := server.Internal_Authenticate(req, cid, "R"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("Expected permission denied error, got %v", err)
	}

	// 7. Chunk access denied
	cap.Mode = "R"
	cap.Chunks = []string{"other"}
	capB, _ = json.Marshal(cap)
	sig = sk.Sign(capB)
	signed.Payload = capB
	signed.Signature = sig
	signedB, _ = json.Marshal(signed)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(signedB))
	if err := server.Internal_Authenticate(req, cid, "R"); err == nil || !strings.Contains(err.Error(), "chunk access denied") {
		t.Errorf("Expected chunk access denied error, got %v", err)
	}
}

func TestData_Scrubber_Stop(t *testing.T) {
	ds, _ := NewDiskStore(storage.New(t.TempDir(), nil))
	scrubber := NewIntegrityScrubber(ds, time.Hour)

	// Pre-fill some chunks
	for i := 0; i < 10; i++ {
		id := strings.Repeat(fmt.Sprintf("%x", i), 64)
		ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	}

	stopCh := make(chan struct{})
	scrubber.stopCh = stopCh
	close(stopCh) // Immediate stop

	// This should return quickly without processing much
	scrubber.scrub()
}

func TestData_DiskStore_WriteChunk_Idempotency(t *testing.T) {
	ds, _ := NewDiskStore(storage.New(t.TempDir(), nil))
	id := strings.Repeat("a", 64)
	ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	// Rewrite same chunk should succeed (idempotent)
	err := ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	if err != nil {
		t.Errorf("WriteChunk idempotency failed: %v", err)
	}
}

func TestData_API_MethodNotAllowed(t *testing.T) {
	ds, _ := NewDiskStore(storage.New(t.TempDir(), nil))
	server := NewServer(ds, nil, nil, NoopValidator{}, true, true)
	ts := httptest.NewServer(server)
	defer ts.Close()

	cid := strings.Repeat("0", 64)
	req, _ := http.NewRequest("PATCH", ts.URL+"/v1/data/"+cid, nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", resp.StatusCode)
	}
}

type mockStore struct {
	Store
	readErr error
}

func (m *mockStore) ReadChunk(id string) (io.ReadCloser, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return m.Store.ReadChunk(id)
}

func TestData_API_GetReadError(t *testing.T) {
	ds, _ := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	ms := &mockStore{Store: ds, readErr: fmt.Errorf("injected read error")}
	server := NewServer(ms, usk.Public(), nil, NoopValidator{}, true, true)

	id := strings.Repeat("a", 64)
	ds.WriteChunk(id, bytes.NewReader([]byte("data")))

	token := signToken(t, usk, []string{id}, "R")
	req, _ := http.NewRequest("GET", "/v1/data/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for failed ReadChunk, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestData_API_PutError(t *testing.T) {
	ds, tmpDir := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{}, true, true)

	id := strings.Repeat("a", 64)

	// Make shard dir read-only
	shardDir := filepath.Join(tmpDir, id[:2])
	os.Chmod(shardDir, 0500)
	defer os.Chmod(shardDir, 0700)

	token := signToken(t, usk, []string{id}, "W")
	req, _ := http.NewRequest("PUT", "/v1/data/"+id, bytes.NewReader([]byte("data")))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for failed put, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestData_API_ReplicateMalformed(t *testing.T) {
	ds, _ := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{}, true, true)

	id := strings.Repeat("e", 64)
	token := signToken(t, usk, []string{id}, "R")

	req, _ := http.NewRequest("POST", "/v1/data/"+id+"/replicate", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for malformed replicate request, got %d", rr.Code)
	}
}

func TestData_DiskStore_WriteErrors(t *testing.T) {
	ds, tmpDir := createTestStore(t)
	defer ds.Close()

	id := strings.Repeat("b", 64)

	// 1. MkdirAll failure (simulated by making shard dir read-only since they're pre-created)
	shardDir := filepath.Join(tmpDir, id[:2])
	os.Chmod(shardDir, 0500)
	err := ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	if err == nil {
		t.Error("Expected write to fail for read-only shard directory")
	}
	os.Chmod(shardDir, 0700)

	// 2. Create failure
	shardDir = filepath.Join(tmpDir, id[:2])
	os.MkdirAll(shardDir, 0700)
	os.Chmod(shardDir, 0500)
	err = ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	if err == nil {
		t.Error("Expected os.Create to fail")
	}
	os.Chmod(shardDir, 0700)
}

func TestData_Scrubber_ListError(t *testing.T) {
	ds, tmpDir := createTestStore(t)
	scrubber := NewIntegrityScrubber(ds, time.Hour)

	id := strings.Repeat("a", 64)
	ds.WriteChunk(id, bytes.NewReader([]byte("data")))

	// Simulate walk error by removing the directory mid-scrub?
	// Hard to time. Let's just remove it and call scrub.
	os.RemoveAll(tmpDir)
	scrubber.scrub()
	// Should hit "error listing chunks"
}

func TestData_API_DeleteError(t *testing.T) {
	ds, tmpDir := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{}, true, true)

	id := strings.Repeat("d", 64)
	ds.WriteChunk(id, bytes.NewReader([]byte("data")))

	// Make shard dir read-only to make os.Remove fail
	shardDir := filepath.Join(tmpDir, id[:2])
	os.Chmod(shardDir, 0500)
	defer os.Chmod(shardDir, 0700)

	token := signToken(t, usk, []string{id}, "D")
	req, _ := http.NewRequest("DELETE", "/v1/data/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for failed delete, got %d", rr.Code)
	}
}

func TestData_API_MissingChunks(t *testing.T) {
	ds, _ := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{}, true, true)
	ts := httptest.NewServer(server)
	defer ts.Close()

	id := strings.Repeat("f", 64)
	tokenR := signToken(t, usk, []string{id}, "R")
	tokenD := signToken(t, usk, []string{id}, "D")

	// 1. GET missing
	req, _ := http.NewRequest("GET", ts.URL+"/v1/data/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tokenR)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for missing chunk, got %d", resp.StatusCode)
	}

	// 2. DELETE missing
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/data/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tokenD)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for missing chunk delete, got %d", resp.StatusCode)
	}
}
