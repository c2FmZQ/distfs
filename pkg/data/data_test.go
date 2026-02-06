// Copyright 2026 TTBT Enterprises LLC
// ... License ...

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
	store, err := NewDiskStore(tmpDir)
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
	if sz != int64(len(content)) {
		t.Errorf("Size mismatch: got %d, want %d", sz, len(content))
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
	store, _ := NewDiskStore(tmpDir)

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
	// We need to construct the sharded path manually for corruption test
	// id[:2]/id[2:4]/id
	relPath := filepath.Join(id[:2], id[2:4], id)
	path := filepath.Join(tmpDir, relPath)
	
	if err := os.WriteFile(path, []byte("garbage"), 0600); err != nil {
		t.Fatalf("Failed to corrupt file at %s: %v", path, err)
	}

	// Verify Corrupt
	if err := scrubber.verifyChunk(id); err == nil {
		t.Error("verifyChunk passed on corrupt chunk")
	}
}

func TestAPI(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewDiskStore(tmpDir)
	server := NewServer(store)
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
}