//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewNativeStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Test Chunks (Filesystem)
	chunkID := "abcdef1234567890"
	chunkData := []byte("chunk-payload")
	if err := store.Put("chunks", chunkID, chunkData); err != nil {
		t.Fatalf("Put chunk failed: %v", err)
	}

	gotChunk, err := store.Get("chunks", chunkID)
	if err != nil {
		t.Fatalf("Get chunk failed: %v", err)
	}
	if !bytes.Equal(gotChunk, chunkData) {
		t.Errorf("expected %s, got %s", chunkData, gotChunk)
	}

	// Test Metadata (BoltDB)
	inodeID := "inode-1"
	inodeData := []byte("inode-payload")
	if err := store.Put("inodes", inodeID, inodeData); err != nil {
		t.Fatalf("Put inode failed: %v", err)
	}

	gotInode, err := store.Get("inodes", inodeID)
	if err != nil {
		t.Fatalf("Get inode failed: %v", err)
	}
	if !bytes.Equal(gotInode, inodeData) {
		t.Errorf("expected %s, got %s", inodeData, gotInode)
	}

	// Test Delete
	if err := store.Delete("inodes", inodeID); err != nil {
		t.Fatal(err)
	}
	_, err = store.Get("inodes", inodeID)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestNativeStorePruning(t *testing.T) {
	dir := t.TempDir()
	// Limit to 100 bytes (roughly 4 chunks of 25 bytes)
	maxBytes := int64(100)
	store, err := NewNativeStore(dir, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Put 10 chunks of 25 bytes each (total 250 bytes)
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("chunk-%d", i)
		data := make([]byte, 25)
		for j := range data {
			data[j] = byte(i)
		}
		if err := store.Put("chunks", key, data); err != nil {
			t.Fatal(err)
		}
		// Small sleep to ensure different mod times
		time.Sleep(20 * time.Millisecond)
	}

	// Give background pruning a moment
	time.Sleep(200 * time.Millisecond)

	// List files in chunks directory
	var count int
	filepath.WalkDir(filepath.Join(dir, "chunks"), func(path string, d os.DirEntry, err error) error {
		if !d.IsDir() {
			count++
		}
		return nil
	})

	// 100 / 25 = 4 chunks should remain
	if count > 4 {
		t.Errorf("expected at most 4 chunks, got %d", count)
	}

	// Verify that the LATEST chunks are the ones that remained
	// (Pruning removes oldest first)
	for i := 6; i < 10; i++ {
		key := fmt.Sprintf("chunk-%d", i)
		_, err := store.Get("chunks", key)
		if err != nil {
			t.Errorf("chunk-%d should still be in cache", i)
		}
	}
}

func TestSecureKVStore(t *testing.T) {
	dir := t.TempDir()
	native, _ := NewNativeStore(dir, 0)
	defer native.Close()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewSecureKVStore(native, key)
	if err != nil {
		t.Fatal(err)
	}

	bucket := "secret"
	k := "mykey"
	val := []byte("confidential-data")

	if err := store.Put(bucket, k, val); err != nil {
		t.Fatal(err)
	}

	// Verify it's encrypted in the underlying store
	ciphertext, _ := native.Get(bucket, k)
	if bytes.Equal(ciphertext, val) {
		t.Fatal("data was not encrypted!")
	}

	// Verify we can decrypt it
	got, err := store.Get(bucket, k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, val) {
		t.Errorf("expected %s, got %s", val, got)
	}
}
