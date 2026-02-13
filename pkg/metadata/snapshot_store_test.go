// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"io"
	"testing"

	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
)

func TestSnapshotStore(t *testing.T) {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)
	store := NewStorageSnapshotStore(st)

	// 1. Create Snapshot Sink
	sink, err := store.Create(raft.SnapshotVersion(1), 10, 2, raft.Configuration{}, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("snapshot data")
	sink.Write(content)
	
	if sink.ID() == "" {
		t.Error("Empty sink ID")
	}

	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	// 2. Open Snapshot (Manual ID)
	meta, rc, err := store.Open(sink.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if meta.Index != 10 {
		t.Errorf("Expected index 10, got %d", meta.Index)
	}
	readBack, _ := io.ReadAll(rc)
	if string(readBack) != string(content) {
		t.Errorf("Data mismatch: %s", readBack)
	}
}

func TestSnapshotStore_Errors(t *testing.T) {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)
	store := NewStorageSnapshotStore(st)

	// Open missing
	_, _, err := store.Open("missing")
	if err == nil {
		t.Error("Open should fail for missing snapshot")
	}

	// Cancel sink
	sink, _ := store.Create(raft.SnapshotVersion(1), 1, 1, raft.Configuration{}, 1, nil)
	sink.Write([]byte("data"))
	if err := sink.Cancel(); err != nil {
		t.Errorf("Cancel failed: %v", err)
	}
	
	// List (empty)
	snaps, _ := store.List()
	if len(snaps) != 0 {
		t.Errorf("Expected 0 snaps, got %d", len(snaps))
	}
}
