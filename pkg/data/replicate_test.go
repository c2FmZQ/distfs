// Copyright 2026 TTBT Enterprises LLC
package data

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReplicateChain(t *testing.T) {
	// Setup 3 nodes
	servers := make([]*httptest.Server, 3)
	stores := make([]*DiskStore, 3)

	pub, sk := setupTestAuth(t)

	for i := 0; i < 3; i++ {
		tmpDir := t.TempDir()
		st, _ := createTestStorage(t, tmpDir)
		store, _ := NewDiskStore(st)
		stores[i] = store
		server := NewServer(store, pub, nil, NoopValidator{}, true, true)
		ts := httptest.NewServer(server)
		servers[i] = ts
		defer ts.Close()
	}

	content := []byte("pipelined replication content")
	h := sha256.Sum256(content)
	chunkID := hex.EncodeToString(h[:])

	// PUT to Node 0 with replicas Node 1 and Node 2
	replicas := fmt.Sprintf("%s,%s", servers[1].URL, servers[2].URL)
	url := fmt.Sprintf("%s/v1/data/%s?replicas=%s", servers[0].URL, chunkID, replicas)

	req, _ := http.NewRequest("PUT", url, bytes.NewReader(content))
	req.Header.Set("Authorization", signTestToken(t, sk, []string{chunkID}, "RW"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify on all nodes
	for i := 0; i < 3; i++ {
		has, _ := stores[i].HasChunk(chunkID)
		if !has {
			t.Errorf("Node %d missing chunk", i)
		} else {
			rc, _ := stores[i].ReadChunk(chunkID)
			data, _ := io.ReadAll(rc)
			rc.Close()
			if string(data) != string(content) {
				t.Errorf("Node %d content mismatch", i)
			}
		}
	}
}

func TestReplicateEndpoint(t *testing.T) {
	// Node 0 has data, Replicate to Node 1
	tmpDir0 := t.TempDir()
	st0, _ := createTestStorage(t, tmpDir0)
	store0, _ := NewDiskStore(st0)

	tmpDir1 := t.TempDir()
	st1, _ := createTestStorage(t, tmpDir1)
	store1, _ := NewDiskStore(st1)

	pub, sk := setupTestAuth(t)

	server0 := NewServer(store0, pub, nil, NoopValidator{}, true, true)
	ts0 := httptest.NewServer(server0)
	defer ts0.Close()

	server1 := NewServer(store1, pub, nil, NoopValidator{}, true, true)
	ts1 := httptest.NewServer(server1)
	defer ts1.Close()

	content := []byte("manual replicate")
	h := sha256.Sum256(content)
	id := hex.EncodeToString(h[:])
	store0.WriteChunk(id, bytes.NewReader(content))

	// POST /v1/data/{id}/replicate
	reqBody := []byte(fmt.Sprintf(`{"targets":["%s"]}`, ts1.URL))
	req, _ := http.NewRequest("POST", ts0.URL+"/v1/data/"+id+"/replicate", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", signTestToken(t, sk, []string{id}, "RW"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST replicate failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	// Verify
	has, _ := store1.HasChunk(id)
	if !has {
		t.Error("Node 1 missing replicated chunk")
	}
}

func TestParallelReplication(t *testing.T) {
	servers := make([]*httptest.Server, 4)
	stores := make([]*DiskStore, 4)

	pub, sk := setupTestAuth(t)

	for i := 0; i < 4; i++ {
		tmpDir := t.TempDir()
		st, _ := createTestStorage(t, tmpDir)
		store, _ := NewDiskStore(st)
		stores[i] = store
		server := NewServer(store, pub, nil, NoopValidator{}, true, true)
		ts := httptest.NewServer(server)
		servers[i] = ts
		defer ts.Close()
	}

	content := []byte("parallel fan-out content")
	h := sha256.Sum256(content)
	chunkID := hex.EncodeToString(h[:])

	replicas := fmt.Sprintf("%s,%s,%s", servers[1].URL, servers[2].URL, servers[3].URL)
	url := fmt.Sprintf("%s/v1/data/%s?replicas=%s", servers[0].URL, chunkID, replicas)

	req, _ := http.NewRequest("PUT", url, bytes.NewReader(content))
	req.Header.Set("Authorization", signTestToken(t, sk, []string{chunkID}, "RW"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	for i := 0; i < 4; i++ {
		has, _ := stores[i].HasChunk(chunkID)
		if !has {
			t.Errorf("Node %d missing chunk", i)
		}
	}
}

func TestParallelReplicationFailure(t *testing.T) {
	servers := make([]*httptest.Server, 3)
	stores := make([]*DiskStore, 3)

	pub, sk := setupTestAuth(t)

	for i := 0; i < 3; i++ {
		tmpDir := t.TempDir()
		st, _ := createTestStorage(t, tmpDir)
		store, _ := NewDiskStore(st)
		stores[i] = store
		server := NewServer(store, pub, nil, NoopValidator{}, true, true)
		ts := httptest.NewServer(server)
		servers[i] = ts
		defer ts.Close()
	}

	servers[2].Close()

	content := []byte("failure test content")
	h := sha256.Sum256(content)
	chunkID := hex.EncodeToString(h[:])

	replicas := fmt.Sprintf("%s,%s", servers[1].URL, servers[2].URL)
	url := fmt.Sprintf("%s/v1/data/%s?replicas=%s", servers[0].URL, chunkID, replicas)

	req, _ := http.NewRequest("PUT", url, bytes.NewReader(content))
	req.Header.Set("Authorization", signTestToken(t, sk, []string{chunkID}, "RW"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request itself failed: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	has0, _ := stores[0].HasChunk(chunkID)
	if !has0 {
		t.Error("Node 0 should have the chunk even if replication failed")
	}
}
