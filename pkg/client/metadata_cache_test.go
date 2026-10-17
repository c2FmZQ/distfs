//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type roundTripCounter struct {
	underlying http.RoundTripper
	count      int64
}

func (r *roundTripCounter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/v1/invoke" && req.Method == http.MethodPost {
		atomic.AddInt64(&r.count, 1)
	}
	return r.underlying.RoundTrip(req)
}

func TestMetadataTTLCache(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	// 1. Wrap the transport to count GET Inode calls
	counter := &roundTripCounter{underlying: c.httpCli.Transport}
	c.httpCli.Transport = counter

	// Configure metadata TTL to 500ms
	c = c.WithMetadataTTL(500 * time.Millisecond)

	// Fetch an Inode to populate cache
	inode, err := c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode: %v", err)
	}
	if inode == nil {
		t.Fatalf("returned root inode is nil")
	}

	// Verify it hit the network
	initialCount := atomic.LoadInt64(&counter.count)
	if initialCount == 0 {
		t.Error("expected initial getInode to query server")
	}

	// Reset counter
	atomic.StoreInt64(&counter.count, 0)

	// Fetch again immediately (should hit cache)
	inode2, err := c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode second time: %v", err)
	}
	if inode2.ID != c.rootID {
		t.Errorf("expected Inode ID %s, got %s", c.rootID, inode2.ID)
	}

	// Network count should still be 0
	if cnt := atomic.LoadInt64(&counter.count); cnt != 0 {
		t.Errorf("expected cache hit (0 network requests), got %d requests", cnt)
	}

	// Wait for TTL to expire (500ms + margin)
	time.Sleep(600 * time.Millisecond)

	// Fetch again (should hit network now)
	_, err = c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode after expiry: %v", err)
	}

	if cnt := atomic.LoadInt64(&counter.count); cnt == 0 {
		t.Error("expected cache miss after TTL expiration, but count was 0")
	}
}

func TestMetadataTTLCache_Disabled(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	counter := &roundTripCounter{underlying: c.httpCli.Transport}
	c.httpCli.Transport = counter

	// Configure metadata TTL to 0 (disabled)
	c = c.WithMetadataTTL(0)

	// Fetch 1st time
	_, err := c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode: %v", err)
	}

	// Fetch 2nd time
	atomic.StoreInt64(&counter.count, 0)
	_, err = c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode second time: %v", err)
	}

	if cnt := atomic.LoadInt64(&counter.count); cnt == 0 {
		t.Error("expected network request for getInode when TTL is 0, but count was 0")
	}
}

func TestMetadataTTLCache_InvalidationOnWrite(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	counter := &roundTripCounter{underlying: c.httpCli.Transport}
	c.httpCli.Transport = counter

	// Configure long TTL (5s)
	c = c.WithMetadataTTL(5 * time.Second)

	// Fetch to cache
	_, err := c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode: %v", err)
	}

	// Verify cached
	atomic.StoreInt64(&counter.count, 0)
	_, err = c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode from cache: %v", err)
	}
	if cnt := atomic.LoadInt64(&counter.count); cnt != 0 {
		t.Fatalf("expected cache hit, got %d network requests", cnt)
	}

	// Perform a mutating command (mkdir) which triggers applyBatch
	err = c.Mkdir(ctx, "/test_mkdir_ttl", 0755)
	if err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}

	// Fetch root inode again (should hit network because cache was cleared)
	atomic.StoreInt64(&counter.count, 0)
	_, err = c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode: %v", err)
	}

	if cnt := atomic.LoadInt64(&counter.count); cnt == 0 {
		t.Error("expected cache invalidation after Mkdir mutation, but got 0 network requests")
	}
}

func TestMetadataTTLCache_WriteThrough(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	counter := &roundTripCounter{underlying: c.httpCli.Transport}
	c.httpCli.Transport = counter

	// Configure long TTL (5s)
	c = c.WithMetadataTTL(5 * time.Second)

	// Fetch root node to establish a base
	inodeBefore, err := c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode: %v", err)
	}

	// Update the root inode using updateInode directly (mutate MTime)
	updated, err := c.updateInode(ctx, c.rootID, func(i *metadata.Inode) error {
		i.SetMTime(99999)
		return nil
	})
	if err != nil {
		t.Fatalf("updateInode failed: %v", err)
	}
	if updated.GetMTime() != 99999 {
		t.Errorf("expected updated MTime to be 99999, got %d", updated.GetMTime())
	}

	// Reset counter
	atomic.StoreInt64(&counter.count, 0)

	// Fetch root inode immediately. It should be served from memory cache (write-through)
	inodeAfter, err := c.getInode(ctx, c.rootID)
	if err != nil {
		t.Fatalf("failed to get root inode: %v", err)
	}

	if inodeAfter.GetMTime() != 99999 {
		t.Errorf("expected cached MTime to be 99999, got %d", inodeAfter.GetMTime())
	}

	if cnt := atomic.LoadInt64(&counter.count); cnt != 0 {
		t.Errorf("expected write-through cache hit (0 network requests), got %d requests", cnt)
	}

	// Check that the persistent BoltDB cache was also written through (matching the Version)
	if c.store != nil {
		data, err := c.store.Get("inodes", c.rootID)
		if err != nil {
			t.Fatalf("failed to get root inode from BoltDB cache: %v", err)
		}
		var stored metadata.Inode
		if err := json.Unmarshal(data, &stored); err != nil {
			t.Fatalf("failed to unmarshal stored inode: %v", err)
		}
		if stored.Version != updated.Version {
			t.Errorf("expected BoltDB stored Version to be %d, got %d", updated.Version, stored.Version)
		}
	}
	_ = inodeBefore
}
