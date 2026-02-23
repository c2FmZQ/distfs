// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"fmt"
	"io"
	"testing"

	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
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

	// List malformed
	if err := st.SaveDataFile("snap-malformed.meta", map[string]string{"invalid": "data"}); err != nil {
		t.Fatalf("failed to save malformed snap: %v", err)
	}
	snaps, _ = store.List()
	if len(snaps) != 0 {
		t.Errorf("Expected 0 valid snaps after malformed, got %d", len(snaps))
	}
}

func TestSnapshotEncryption(t *testing.T) {
	// 1. Setup Source FSM
	tmpDir1 := t.TempDir()
	mk1, _ := storage_crypto.CreateAESMasterKeyForTest()
	st1 := storage.New(tmpDir1, mk1)
	fsm1, _ := NewMetadataFSM(tmpDir1+"/fsm.bolt", st1)
	defer fsm1.Close()

	// Add data
	fsm1.db.Update(func(tx *bolt.Tx) error {
		return fsm1.Put(tx, []byte("system"), []byte("secret"), []byte("value"))
	})

	// 2. Persist Snapshot
	store := NewStorageSnapshotStore(st1)
	sink, _ := store.Create(raft.SnapshotVersion(1), 5, 1, raft.Configuration{}, 1, nil)
	snap, _ := fsm1.Snapshot()
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}

	// 3. Setup Target FSM (Clean state)
	tmpDir2 := t.TempDir()
	mk2, _ := storage_crypto.CreateAESMasterKeyForTest()
	st2 := storage.New(tmpDir2, mk2)
	fsm2, _ := NewMetadataFSM(tmpDir2+"/fsm.bolt", st2) // Has random key initially
	defer fsm2.Close()

	// 4. Restore Snapshot
	_, rc, err := store.Open(sink.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := fsm2.Restore(rc); err != nil {
		t.Fatal(err)
	}

	// 5. Verify Data readable in Target
	err = fsm2.db.View(func(tx *bolt.Tx) error {
		val, err := fsm2.Get(tx, []byte("system"), []byte("secret"))
		if err != nil {
			return err
		}
		if string(val) != "value" {
			return fmt.Errorf("decryption failed or data mismatch: got %s", val)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// 6. Verify Key persisted in Storage
	var keyData KeyData
	if err := st2.ReadDataFile("fsm.key", &keyData); err != nil {
		t.Fatal("fsm.key not saved")
	}
	if string(keyData.Bytes) != string(fsm1.keyRing.Marshal()) {
		t.Error("fsm.key mismatch")
	}
}
