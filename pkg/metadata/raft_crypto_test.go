// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"path/filepath"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb"
)

func TestEncryptedLogStore(t *testing.T) {
	tmpDir := t.TempDir()
	bolt, _ := raftboltdb.NewBoltStore(filepath.Join(tmpDir, "logs.bolt"))
	kr := crypto.NewKeyRing(make([]byte, 32))
	el := NewEncryptedLogStore(bolt, kr)

	// 1. Store Log
	l := &raft.Log{Index: 1, Term: 1, Data: []byte("secret data")}
	if err := el.StoreLog(l); err != nil {
		t.Fatal(err)
	}

	// 2. Retrieve Log
	var out raft.Log
	if err := el.GetLog(1, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.Data) != "secret data" {
		t.Errorf("Decryption failed: %s", out.Data)
	}

	// 3. Rotate Key and verify still readable
	kr.Rotate()
	l2 := &raft.Log{Index: 2, Term: 1, Data: []byte("new data")}
	el.StoreLog(l2)

	if err := el.GetLog(1, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.Data) != "secret data" {
		t.Error("Old log no longer readable after rotation")
	}
	if err := el.GetLog(2, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.Data) != "new data" {
		t.Error("New log not readable")
	}
}
