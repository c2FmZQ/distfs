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

	// Close store and reopen to verify BoltDB persistence of the corrected estimate
	s.Close()
	s2, err := NewNativeStore(tmpDir, 50)
	if err != nil {
		t.Fatalf("Failed to recreate native store: %v", err)
	}
	defer s2.Close()

	if s2.estimatedBytes.Load() != 20 {
		t.Errorf("Expected persisted estimate to be 20, got %d", s2.estimatedBytes.Load())
	}
}

func TestNativeStorePruneTimerDeferred(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "native-store-prune-timer-test")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	s, err := NewNativeStore(tmpDir, 10) // limit of 10 bytes
	if err != nil {
		t.Fatalf("Failed to create native store: %v", err)
	}
	defer s.Close()

	// Set prune interval to 100ms
	s.SetPruneInterval(100 * time.Millisecond)

	// Mock lastPrune to just now to trigger rate-limiting
	s.mu.Lock()
	s.lastPrune = time.Now()
	s.mu.Unlock()

	// Put chunk exceeding the limit (12 bytes)
	err = s.Put("chunks", "chunk1", []byte("123456789012"))
	if err != nil {
		t.Fatalf("Failed to put chunk: %v", err)
	}

	// Trigger maybeSchedulePrune. It should be skipped due to rate-limiting,
	// but schedule a deferred timer for ~100ms.
	s.maybeSchedulePrune()

	path := s.getChunkPath("chunk1")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Expected chunk to still exist (pruning should be deferred): %v", err)
	}

	// Wait 150ms for deferred timer to fire and execute Prune
	time.Sleep(150 * time.Millisecond)

	if _, err := os.Stat(path); err == nil {
		t.Errorf("Expected chunk to be pruned by the deferred timer")
	}
}

func TestMetadataCacheSignatureVerification(t *testing.T) {
	c := &Client{
		inodeMemCache: make(map[string]cachedInode),
		metadataTTL:   5 * time.Second,
		keyCache:      make(map[string]fileMetadata),
	}
	c.inodeMemMu = new(sync.RWMutex)
	c.keyMu = new(sync.RWMutex)

	inode := &metadata.Inode{
		ID: "test-id",
	}

	// Insert into cache
	c.inodeMemMu.Lock()
	c.inodeMemCache[inode.ID] = cachedInode{
		inode:    inode.Clone(),
		cachedAt: time.Now(),
	}
	c.inodeMemMu.Unlock()

	// Retrieve with verify=true. It should perform verifyInode and fail since the signatures are missing.
	_, err := c.getInodeInternal(context.Background(), inode.ID, true)
	if err == nil {
		t.Fatalf("Expected getInodeInternal to fail signature verification on cache hit with verify=true")
	}
}

func TestFileWriterCloseDrainsGoroutines(t *testing.T) {
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	w := &FileWriter{
		client: c,
		ctx:    ctx,
		cancel: cancel,
		inode:  metadata.Inode{ID: "test-file"},
	}

	running := make(chan struct{})
	done := make(chan struct{})

	w.uploadWg.Add(1)
	go func() {
		defer w.uploadWg.Done()
		close(running)
		<-w.ctx.Done() // Block until cancelled
		close(done)
	}()

	<-running

	// Call Close(). It should cancel the context, wait for the goroutine, and return.
	// Since w.Finish() will return nil (as w.written is 0 and no chunks flushed),
	// it will run the deferred cleanup block.
	_ = w.Close()

	// Verify that the goroutine has actually finished
	select {
	case <-done:
		// Passed!
	default:
		t.Errorf("Expected goroutine to have finished and been waited on by Close()")
	}
}

func TestNativeStoreCloseRaceCondition(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "native-store-close-race-test")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	s, err := NewNativeStore(tmpDir, 10)
	if err != nil {
		t.Fatalf("Failed to create native store: %v", err)
	}

	// Put chunk to exceed limit
	err = s.Put("chunks", "chunk1", []byte("123456789012"))
	if err != nil {
		t.Fatalf("Failed to put chunk: %v", err)
	}

	// Trigger maybeSchedulePrune to start a background pruning goroutine
	s.maybeSchedulePrune()

	// Immediately call Close(). It should wait for the background pruning goroutine
	// to complete via pruneWg.Wait() before closing s.db.
	err = s.Close()
	if err != nil {
		t.Errorf("Unexpected error from Close: %v", err)
	}
}



