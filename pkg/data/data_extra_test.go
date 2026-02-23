// Copyright 2026 TTBT Enterprises LLC
package data

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	server := NewServer(ds, usk.Public(), nil, NoopValidator{})
	
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
	serverDeny := NewServer(ds, usk.Public(), nil, DenyAllValidator{})
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
	sNoKey := NewServer(ds, nil, nil, nil)
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
	s1 := NewServer(ds, nil, &metadata.MetadataFSM{}, nil)
	if s1.validator == nil {
		t.Error("Validator should be set from FSM")
	}

	// 2. Without FSM, without Validator
	s2 := NewServer(ds, nil, nil, nil)
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
	// Make root store dir read-only
	os.Chmod(ds.st.Dir(), 0500)
	defer os.Chmod(ds.st.Dir(), 0700)
	
	err = ds.WriteChunk(id, bytes.NewReader([]byte("data")))
	if err == nil {
		t.Error("WriteChunk should fail for read-only store directory")
	}
}

func TestData_ReplicationErrors(t *testing.T) {
	ds, _ := createTestStore(t)
	usk, _ := crypto.GenerateIdentityKey()
	server := NewServer(ds, usk.Public(), nil, NoopValidator{})

	// 1. Replicate missing chunk
	id := "3333333333333333333333333333333333333333333333333333333333333333"
	err := server.replicate(id, "http://localhost:1234", "", "token")
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
	server := NewServer(ds, usk.Public(), nil, NoopValidator{})
	
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
	server := NewServer(ds, nil, nil, NoopValidator{})
	
	id := "5555555555555555555555555555555555555555555555555555555555555555"
	ds.WriteChunk(id, bytes.NewReader([]byte("data")))

	// Replicate to invalid address
	err := server.replicate(id, "http://invalid.domain", "", "token")
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
	for _ , _ = range ds.ListChunks() {
		break // Hits !yield branch
	}
}
