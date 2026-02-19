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
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

	// Make dir read-only to force write error
	if err := os.Chmod(tmpDir, 0500); err != nil {
		t.Skip("Cannot chmod")
	}

	h := sha256.Sum256([]byte("fail"))
	id := hex.EncodeToString(h[:])

	if err := store.WriteChunk(id, bytes.NewReader([]byte("fail"))); err == nil {
		t.Error("Expected error writing to readonly dir")
	}

	os.Chmod(tmpDir, 0755) // Restore
}

func TestAPI(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	store, _ := NewDiskStore(st)

	server := NewServer(store, nil, nil)
	ts := httptest.NewServer(server)
	defer ts.Close()

	content := []byte("api content")
	h := sha256.Sum256(content)
	chunkID := hex.EncodeToString(h[:])

	// PUT
	req, _ := http.NewRequest("PUT", ts.URL+"/v1/data/"+chunkID, bytes.NewReader(content))
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
	resp, err = http.Get(ts.URL + "/v1/data/" + chunkID)
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

	server := NewServer(store, nil, nil)
	ts := httptest.NewServer(server)
	defer ts.Close()

	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	store.WriteChunk(id, bytes.NewReader([]byte("data")))

	// DELETE
	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/data/"+id, nil)
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
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for missing DELETE, got %d", resp.StatusCode)
	}
}
