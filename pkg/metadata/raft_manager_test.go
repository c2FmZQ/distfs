// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func TestNodeIDFromPublicKey(t *testing.T) {
	key, _ := crypto.GenerateIdentityKey()
	id1 := NodeIDFromKey(key)
	id2 := NodeIDFromPublicKey(key.Public())
	if id1 != id2 {
		t.Errorf("ID mismatch: %s != %s", id1, id2)
	}
	if len(id1) != 16 { // 8 bytes in hex
		t.Errorf("Unexpected ID length: %d", len(id1))
	}
}

func TestRaftNode_KeyRing(t *testing.T) {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)
	nodeKey, _ := crypto.GenerateIdentityKey()

	// 1. Create RaftNode
	node, err := NewRaftNode("node1", "127.0.0.1:0", "", tmpDir, st, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Shutdown().Error()
	node.FSM.Close()
	node.LogStore.Close()

	// 2. Verify KeyRing persisted
	if _, err := os.Stat(filepath.Join(tmpDir, "keyring.bin")); err != nil {
		t.Errorf("keyring.bin not found: %v", err)
	}

	// 3. Re-open
	node2, err := NewRaftNode("node1", "127.0.0.1:0", "", tmpDir, st, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	node2.Raft.Shutdown().Error()
	node2.FSM.Close()
	node2.LogStore.Close()
}
