//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestCacheIsolationViaCloning(t *testing.T) {
	c := &Client{
		inodeMemCache: make(map[string]cachedInode),
		metadataTTL:   5 * time.Second,
	}
	c.inodeMemMu = new(sync.RWMutex)

	inode := &metadata.Inode{
		ID:    "test-id",
		Links: map[string]bool{"parent:name": true},
	}

	// Insert into cache
	c.inodeMemMu.Lock()
	c.inodeMemCache[inode.ID] = cachedInode{
		inode:    inode.Clone(),
		cachedAt: time.Now(),
	}
	c.inodeMemMu.Unlock()

	// Retrieve from cache
	retrieved, err := c.getInodeInternal(context.Background(), inode.ID, false)
	if err != nil {
		t.Fatalf("Failed to retrieve inode: %v", err)
	}

	// Mutate retrieved inode
	retrieved.Links["parent:name"] = false

	// Retrieve again and verify original is unchanged
	retrieved2, err := c.getInodeInternal(context.Background(), inode.ID, false)
	if err != nil {
		t.Fatalf("Failed to retrieve inode again: %v", err)
	}

	if !retrieved2.Links["parent:name"] {
		t.Errorf("Cache pollution detected: mutation of retrieved inode affected cached inode")
	}
}

func TestFileWriterPlaceholderCleanup(t *testing.T) {
	c := &Client{
		allocMu: &sync.RWMutex{},
		keyMu:   &sync.RWMutex{},
		pathMu:  &sync.RWMutex{},
		offline: true,
	}

	w := &FileWriter{
		client:    c,
		ctx:       context.Background(),
		fileKey:   make([]byte, 32),
		buf:       make([]byte, crypto.ChunkSize),
		uploadSem: make(chan struct{}, 2),
		inode:     metadata.Inode{ID: "test-file"},
	}

	// Since w.client is a client with empty metadata servers, allocateNodes will fail.
	// Let's verify that when it fails, the placeholder is removed.
	err := w.flushChunkAsync()
	if err == nil {
		t.Fatalf("Expected flushChunkAsync to fail")
	}

	w.manifestMu.Lock()
	manifestLen := len(w.manifest)
	w.manifestMu.Unlock()

	if manifestLen != 0 {
		t.Errorf("Expected manifest to be empty after synchronous failure, got length %d", manifestLen)
	}

	if w.uploadErr.Load() == nil {
		t.Errorf("Expected upload error to be stored")
	}
}

func TestNativeStorePruneDriftCorrection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "native-store-prune-test")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	s, err := NewNativeStore(tmpDir, 50) // limit of 50 bytes
	if err != nil {
		t.Fatalf("Failed to create native store: %v", err)
	}
	defer s.Close()

	// Put some chunks
	err = s.Put("chunks", "chunk1", []byte("1234567890")) // 10 bytes
	if err != nil {
		t.Fatalf("Failed to put chunk: %v", err)
	}
	err = s.Put("chunks", "chunk2", []byte("1234567890")) // 10 bytes
	if err != nil {
		t.Fatalf("Failed to put chunk: %v", err)
	}

	// Verify estimate is correct (20 bytes)
	if s.estimatedBytes.Load() != 20 {
		t.Errorf("Expected estimate to be 20, got %d", s.estimatedBytes.Load())
	}

	// Manually inject drift into the in-memory estimate
	s.estimatedBytes.Store(100)

	// Trigger Prune (even though under 50 bytes limit, total size is 20)
	err = s.Prune()
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}

	// Verify estimate got corrected to 20
	if s.estimatedBytes.Load() != 20 {
		t.Errorf("Expected estimate to be corrected to 20, got %d", s.estimatedBytes.Load())
	}
}
