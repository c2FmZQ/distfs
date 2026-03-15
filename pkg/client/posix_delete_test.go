//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestPOSIX_DeleteWhileOpen(t *testing.T) {
	// 1. Setup Cluster
	c, metaNode, _, tsMeta := SetupTestClient(t)
	defer tsMeta.Close()

	if err := c.Mkdir(t.Context(), "/dir", 0755); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}

	// 2. Create a file with multiple chunks
	path := "/dir/test-posix"
	content := bytes.Repeat([]byte("Chunk Data 1MB!"), 1024*1024/16*2) // 2MB
	if err := c.CreateFile(t.Context(), path, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 3. Client A opens the file for reading
	rc, err := c.OpenBlobRead(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenBlobRead failed: %v", err)
	}
	reader := rc.(*FileReader)
	inodeID := reader.inode.ID
	defer reader.Close()

	// Verify we can read first part
	buf := make([]byte, 1024)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}

	// 4. Client B (same user, different "device" simulated) deletes the file
	if err := c.Remove(t.Context(), path); err != nil {
		t.Fatal(err)
	}

	// 5. Verify file is gone from namespace
	_, _, err = c.ResolvePath(t.Context(), path)
	if err == nil {
		t.Error("Expected error resolving deleted path, got nil")
	}

	// 6. Verify Client A can still read the rest of the file
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read from unlinked file: %v", err)
	}
	if len(rest) != len(content)-1024 {
		t.Errorf("Expected to read remaining %d bytes, got %d", len(content)-1024, len(rest))
	}

	// 7. Close reader (releases lease)
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	// 8. Verify that GC eventually processes it
	time.Sleep(200 * time.Millisecond) // Give Raft a moment to apply the release-triggered delete

	// Check if inode is gone
	_, err = c.GetInode(t.Context(), inodeID)
	if err == nil {
		t.Error("Inode still exists via API after last lease released")
	}

	// Check if chunks are in GC bucket
	gcCount := 0
	err = metaNode.FSM.InspectBucket("garbage_collection", func(k, v []byte) error {
		gcCount++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if gcCount == 0 {
		t.Error("Chunks not enqueued for GC")
	}
}
