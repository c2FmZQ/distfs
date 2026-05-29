//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// TestHedgeDelayBuilder verifies the WithHedgeDelay builder method.
func TestHedgeDelayBuilder(t *testing.T) {
	c := NewClient("http://localhost:8080")
	if c.hedgeDelay != 150*time.Millisecond {
		t.Errorf("expected default hedgeDelay to be 150ms, got %v", c.hedgeDelay)
	}

	c = c.WithHedgeDelay(500 * time.Millisecond)
	if c.hedgeDelay != 500*time.Millisecond {
		t.Errorf("expected configured hedgeDelay to be 500ms, got %v", c.hedgeDelay)
	}

	c = c.WithHedgeDelay(0)
	if c.hedgeDelay != 0 {
		t.Errorf("expected configured hedgeDelay of 0, got %v", c.hedgeDelay)
	}
}

// TestDownloadChunk_HedgeZero verifies that a hedgeDelay of 0 fires all downloads simultaneously.
func TestDownloadChunk_HedgeZero(t *testing.T) {
	c := NewClient("http://localhost:8080").WithHedgeDelay(0)

	var callCount int32
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chunk-data-1"))
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chunk-data-2"))
	}))
	defer server2.Close()

	urls := []string{server1.URL, server2.URL}
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
	defer cancel()

	_, err := c.downloadChunk(ctx, "chunk-0", urls, "token")
	if err != nil {
		t.Fatalf("downloadChunk failed: %v", err)
	}

	// Because hedgeDelay is 0, both replicas should have been fired immediately (simultaneously)
	// before any response returned.
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("expected 2 concurrent calls, got %d", callCount)
	}
}

// TestPrefetchWindowAutoTuning verifies that the FileReader prefetch window increases
// on sequential cache hits, decreases on sequential cache misses (direct downloads),
// and resets to 1 on seeks.
func TestPrefetchWindowAutoTuning(t *testing.T) {
	c := NewClient("http://localhost:8080").WithMaxPrefetch(4)

	// We prepare an Inode with multiple chunks.
	manifest := make([]metadata.ChunkEntry, 10)
	for i := range manifest {
		manifest[i] = metadata.ChunkEntry{ID: fmt.Sprintf("chunk-%d", i), URLs: []string{"http://dummy"}}
	}

	fileKey := make([]byte, 32)
	r := &FileReader{
		client:         c,
		inode:          &metadata.Inode{ChunkManifest: manifest, Size: 10 * crypto.ChunkSize},
		fileKey:        fileKey,
		readAhead:      make(map[int64]*readAheadResult),
		prefetchWindow: 1,
		maxPrefetch:    4,
		ctx:            context.Background(),
	}

	// 1. Initial prefetchWindow is 1.
	if r.prefetchWindow != 1 {
		t.Errorf("expected initial prefetchWindow to be 1, got %d", r.prefetchWindow)
	}

	// 2. Simulate reading chunk 0.
	// This is the first read, so sequentialHits should become 0.
	p := make([]byte, 100)
	r.sequentialHits = 0
	r.lastChunkIdx = 0

	// 3. Simulate cache hit on chunk 1.
	// A read-ahead result is populated in readAhead map.
	r.readAheadMu.Lock()
	r.readAhead[1] = &readAheadResult{
		ready: make(chan struct{}),
		data:  make([]byte, crypto.ChunkSize),
	}
	close(r.readAhead[1].ready)
	r.readAheadMu.Unlock()

	// Read chunk 1 sequentially.
	// Since lastChunkIdx was 0 and we read 1:
	// sequentialHits should increment to 1.
	// Since chunk 1 is found in r.readAhead, it's a hit.
	// prefetchWindow should scale up: 1 -> 2.
	r.mu.Lock()
	n, err := r.readInternal(p, true, crypto.ChunkSize)
	r.mu.Unlock()
	if err != nil && err != io.EOF {
		t.Fatalf("readInternal failed: %v", err)
	}
	if n != len(p) {
		t.Errorf("expected read of %d bytes, got %d", len(p), n)
	}
	if r.prefetchWindow != 2 {
		t.Errorf("expected prefetchWindow to grow to 2 after cache hit, got %d", r.prefetchWindow)
	}

	// 4. Simulate another cache hit on chunk 2.
	r.readAheadMu.Lock()
	r.readAhead[2] = &readAheadResult{
		ready: make(chan struct{}),
		data:  make([]byte, crypto.ChunkSize),
	}
	close(r.readAhead[2].ready)
	r.readAheadMu.Unlock()

	// Read chunk 2 sequentially.
	// prefetchWindow should grow: 2 -> 3.
	r.mu.Lock()
	_, _ = r.readInternal(p, true, crypto.ChunkSize*2)
	r.mu.Unlock()
	if r.prefetchWindow != 3 {
		t.Errorf("expected prefetchWindow to grow to 3, got %d", r.prefetchWindow)
	}

	// 5. Simulate a sequential cache MISS on chunk 3 (direct download).
	// We mock the client to return a mock chunk.
	fileKeyCopy := fileKey
	c.httpCli.Transport = &mockRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			// Return encrypted empty chunk.
			_, ct, _ := crypto.EncryptChunk(fileKeyCopy, make([]byte, crypto.ChunkSize), 3)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(ct)),
			}, nil
		},
	}

	// Clear cache for chunk 3 to guarantee a cache miss.
	r.readAheadMu.Lock()
	delete(r.readAhead, 3)
	r.readAheadMu.Unlock()

	// Read chunk 3 sequentially. Since it's a miss, prefetchWindow should shrink: 3 -> 2.
	r.mu.Lock()
	_, _ = r.readInternal(p, true, crypto.ChunkSize*3)
	r.mu.Unlock()
	if r.prefetchWindow != 2 {
		t.Errorf("expected prefetchWindow to shrink to 2 on cache miss, got %d", r.prefetchWindow)
	}

	// 6. Simulate a seek / random access.
	// reading with isReadAt=true, or reading non-sequentially should reset window to 1.
	r.mu.Lock()
	_, _ = r.readInternal(p, true, crypto.ChunkSize*5) // jump from 3 to 5
	r.mu.Unlock()
	if r.prefetchWindow != 1 {
		t.Errorf("expected prefetchWindow to reset to 1 on seek, got %d", r.prefetchWindow)
	}
}

// TestFileWriter_PipelinedWritesErrorPropagation verifies that errors in background
// upload goroutines are successfully bubbled up to subsequent Write calls and Finish/Close.
func TestFileWriter_PipelinedWritesErrorPropagation(t *testing.T) {
	c := NewClient("http://localhost:8080").WithWritePipeline(2)

	// Mock transport to return error for uploads.
	c.httpCli.Transport = &mockRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			// Mock authentication challenge & login so client thinks it's logged in.
			if req.URL.Path == "/v1/auth/challenge" {
				chal := make([]byte, 32)
				res := metadata.AuthChallengeResponse{Challenge: chal, Signature: make([]byte, 64)}
				b, _ := json.Marshal(res)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b))}, nil
			}
			if req.URL.Path == "/v1/login" {
				res := metadata.SessionResponse{Token: "fake-token"}
				b, _ := json.Marshal(res)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b))}, nil
			}
			if req.URL.Path == "/v1/meta/key/sign" {
				sk, _ := crypto.GenerateIdentityKey()
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(sk.Public()))}, nil
			}
			if req.URL.Path == "/v1/meta/key" {
				dk, _ := crypto.GenerateEncryptionKey()
				ek := dk.EncapsulationKey()
				b := crypto.MarshalEncapsulationKey(ek)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b))}, nil
			}
			if req.URL.Path == "/v1/meta/token" || req.URL.Path == "/v1/invoke" {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("fake-token")))}, nil
			}

			// Reject chunk uploads (PUT requests) with error
			if req.Method == "PUT" {
				return nil, errors.New("network upload failure")
			}

			return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(bytes.NewReader([]byte{}))}, nil
		},
	}

	sk, _ := crypto.GenerateIdentityKey()
	c = c.withSignKey(sk)

	w := &FileWriter{
		client:    c,
		ctx:       context.Background(),
		fileKey:   make([]byte, 32),
		inode:     metadata.Inode{ID: "inode-1"},
		uploadSem: make(chan struct{}, 2),
		nodes:     []metadata.Node{{ID: "n1", Address: "http://node1"}},
	}

	// Write more than ChunkSize bytes to trigger flushChunkAsync.
	// Since the upload fails, the background goroutine will store the error.
	largeData := make([]byte, crypto.ChunkSize+100)
	_, err := w.Write(largeData)

	// Since upload is async, the first Write might succeed before the goroutine fails,
	// or it might already detect the failure if the goroutine executes quickly.
	// Let's do a small sleep to ensure the background goroutine runs and fails,
	// then call Write again or call Finish.
	time.Sleep(100 * time.Millisecond)

	// Subsequent write should return the async error.
	_, err = w.Write([]byte("more data"))
	if err == nil {
		// If Write didn't catch it, Finish must catch it.
		err = w.Finish()
	}

	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("network upload failure")) {
		t.Errorf("expected upload error 'network upload failure', got: %v", err)
	}
}

// TestBenchmark_LatencyOptimization compares performance of sequential vs pipelined writes,
// and no-prefetch vs dynamic prefetch reads under simulated latency.
func TestBenchmark_LatencyOptimization(t *testing.T) {
	// Mock server that introduces 50ms of network latency for chunk uploads/downloads.
	var uploadCalls, downloadCalls int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // simulate 50ms RTT

		if r.URL.Path == "/v1/auth/challenge" {
			chal := make([]byte, 32)
			res := metadata.AuthChallengeResponse{Challenge: chal, Signature: make([]byte, 64)}
			b, _ := json.Marshal(res)
			w.WriteHeader(http.StatusOK)
			w.Write(b)
			return
		}
		if r.URL.Path == "/v1/login" {
			res := metadata.SessionResponse{Token: "fake-token"}
			b, _ := json.Marshal(res)
			w.WriteHeader(http.StatusOK)
			w.Write(b)
			return
		}
		if r.URL.Path == "/v1/meta/key/sign" {
			sk, _ := crypto.GenerateIdentityKey()
			w.WriteHeader(http.StatusOK)
			w.Write(sk.Public())
			return
		}
		if r.URL.Path == "/v1/meta/key" {
			dk, _ := crypto.GenerateEncryptionKey()
			w.WriteHeader(http.StatusOK)
			w.Write(crypto.MarshalEncapsulationKey(dk.EncapsulationKey()))
			return
		}
		if r.URL.Path == "/v1/meta/token" || r.URL.Path == "/v1/invoke" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("fake-token"))
			return
		}
		if r.URL.Path == "/v1/meta/allocate" {
			nodes := []metadata.Node{
				{ID: "node-1", Address: "http://dummy1"},
				{ID: "node-2", Address: "http://dummy2"},
			}
			b, _ := json.Marshal(nodes)
			w.WriteHeader(http.StatusOK)
			w.Write(b)
			return
		}

		if r.Method == "PUT" {
			atomic.AddInt64(&uploadCalls, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == "GET" && bytes.Contains([]byte(r.URL.Path), []byte("chunk")) {
			atomic.AddInt64(&downloadCalls, 1)
			w.WriteHeader(http.StatusOK)
			// Return encrypted empty chunk with the correct index.
			var idx uint64
			fmt.Sscanf(r.URL.Path, "/v1/data/chunk-%d", &idx)
			fileKey := make([]byte, 32)
			_, ct, _ := crypto.EncryptChunk(fileKey, make([]byte, crypto.ChunkSize), idx)
			w.Write(ct)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// 1. Measure Pipelined Writes (Sequential vs Pipelined)
	t.Run("PipelinedWrites", func(t *testing.T) {
		sk, _ := crypto.GenerateIdentityKey()

		// Run sequential (WritePipeline=1)
		cSeq := NewClient(server.URL).WithWritePipeline(1).withSignKey(sk)
		wSeq := &FileWriter{
			client:    cSeq,
			ctx:       context.Background(),
			fileKey:   make([]byte, 32),
			inode:     metadata.Inode{ID: "inode-seq"},
			uploadSem: make(chan struct{}, 1),
			nodes:     []metadata.Node{{ID: "n1", Address: server.URL}},
		}

		// 5 chunks
		largeData := make([]byte, 5*crypto.ChunkSize)
		atomic.StoreInt64(&uploadCalls, 0)
		start := time.Now()
		if _, err := wSeq.Write(largeData); err != nil {
			t.Fatalf("wSeq.Write failed: %v", err)
		}
		if err := wSeq.Finish(); err != nil {
			t.Fatalf("wSeq.Finish failed: %v", err)
		}
		seqDuration := time.Since(start)
		seqUploads := atomic.LoadInt64(&uploadCalls)

		// Run pipelined (WritePipeline=4)
		cPipe := NewClient(server.URL).WithWritePipeline(4).withSignKey(sk)
		wPipe := &FileWriter{
			client:    cPipe,
			ctx:       context.Background(),
			fileKey:   make([]byte, 32),
			inode:     metadata.Inode{ID: "inode-pipe"},
			uploadSem: make(chan struct{}, 4),
			nodes:     []metadata.Node{{ID: "n1", Address: server.URL}},
		}

		atomic.StoreInt64(&uploadCalls, 0)
		start = time.Now()
		if _, err := wPipe.Write(largeData); err != nil {
			t.Fatalf("wPipe.Write failed: %v", err)
		}
		if err := wPipe.Finish(); err != nil {
			t.Fatalf("wPipe.Finish failed: %v", err)
		}
		pipeDuration := time.Since(start)
		pipeUploads := atomic.LoadInt64(&uploadCalls)

		t.Logf("Sequential Writes (Pipeline=1) took: %v (uploads: %d)", seqDuration, seqUploads)
		t.Logf("Pipelined Writes (Pipeline=4) took: %v (uploads: %d)", pipeDuration, pipeUploads)
		t.Logf("Write speedup: %.2fx", float64(seqDuration)/float64(pipeDuration))
	})

	// 2. Measure Prefetching (No-prefetch vs Auto-tuning Prefetch)
	t.Run("Prefetching", func(t *testing.T) {
		manifest := make([]metadata.ChunkEntry, 10)
		for i := range manifest {
			manifest[i] = metadata.ChunkEntry{ID: fmt.Sprintf("chunk-%d", i), URLs: []string{server.URL}}
		}
		fileKey := make([]byte, 32)

		// Run No-prefetch (MaxPrefetch=0)
		cNoPrefetch := NewClient(server.URL).WithMaxPrefetch(0)
		rNoPrefetch := &FileReader{
			client:         cNoPrefetch,
			inode:          &metadata.Inode{ChunkManifest: manifest, Size: 10 * crypto.ChunkSize},
			fileKey:        fileKey,
			readAhead:      make(map[int64]*readAheadResult),
			prefetchWindow: 0,
			maxPrefetch:    0,
			ctx:            context.Background(),
		}

		p := make([]byte, crypto.ChunkSize)
		atomic.StoreInt64(&downloadCalls, 0)
		start := time.Now()
		for i := 0; i < 10; i++ {
			if _, err := rNoPrefetch.Read(p); err != nil {
				t.Fatalf("rNoPrefetch.Read chunk %d failed: %v", i, err)
			}
		}
		noPrefetchDuration := time.Since(start)
		noPrefetchDownloads := atomic.LoadInt64(&downloadCalls)

		// Run Auto-tuning Prefetch (MaxPrefetch=4)
		cPrefetch := NewClient(server.URL).WithMaxPrefetch(4)
		rPrefetch := &FileReader{
			client:         cPrefetch,
			inode:          &metadata.Inode{ChunkManifest: manifest, Size: 10 * crypto.ChunkSize},
			fileKey:        fileKey,
			readAhead:      make(map[int64]*readAheadResult),
			prefetchWindow: 1,
			maxPrefetch:    4,
			ctx:            context.Background(),
		}

		atomic.StoreInt64(&downloadCalls, 0)
		start = time.Now()
		for i := 0; i < 10; i++ {
			if _, err := rPrefetch.Read(p); err != nil {
				t.Fatalf("rPrefetch.Read chunk %d failed: %v", i, err)
			}
		}
		prefetchDuration := time.Since(start)
		prefetchDownloads := atomic.LoadInt64(&downloadCalls)

		t.Logf("No Prefetch took: %v (downloads: %d)", noPrefetchDuration, noPrefetchDownloads)
		t.Logf("Dynamic Prefetch took: %v (downloads: %d)", prefetchDuration, prefetchDownloads)
		t.Logf("Read speedup: %.2fx", float64(noPrefetchDuration)/float64(prefetchDuration))
	})
}

// TestNativeStore_EstimatedBytesPersistence verifies that estimatedBytes is persisted
// to BoltDB on updates and loaded on startup without running a directory walk fallback.
func TestNativeStore_EstimatedBytesPersistence(t *testing.T) {
	dir := t.TempDir()

	// 1. Create native store, write a chunk.
	store, err := NewNativeStore(dir, 1000)
	if err != nil {
		t.Fatalf("failed to create NativeStore: %v", err)
	}

	chunkData := []byte("hello-world-chunk-data")
	err = store.Put("chunks", "chunk1", chunkData)
	if err != nil {
		t.Fatalf("failed to put chunk: %v", err)
	}

	expectedSize := int64(len(chunkData))
	if size := store.estimatedBytes.Load(); size != expectedSize {
		t.Errorf("expected estimatedBytes in memory to be %d, got %d", expectedSize, size)
	}

	// Close database file to release BoltDB lock
	store.Close()

	// 2. Modify physical filesystem by deleting the chunk file.
	// If the startup performs a directory walk, the size will compute to 0.
	// If it successfully loads the persisted count from BoltDB, it will compute to expectedSize.
	chunkPath := store.getChunkPath("chunk1")
	err = os.Remove(chunkPath)
	if err != nil {
		t.Fatalf("failed to remove chunk file: %v", err)
	}

	// 3. Re-open NativeStore on same directory.
	store2, err := NewNativeStore(dir, 1000)
	if err != nil {
		t.Fatalf("failed to re-open NativeStore: %v", err)
	}
	defer store2.Close()

	if size := store2.estimatedBytes.Load(); size != expectedSize {
		t.Errorf("expected loaded estimatedBytes from BoltDB to be %d, got %d", expectedSize, size)
	}
}
