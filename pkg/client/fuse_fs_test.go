//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"testing"

	"bazil.org/fuse"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestDir_Forget(t *testing.T) {
	d := &Dir{inode: &metadata.Inode{ID: "test-dir"}}
	d.Forget() // Should not crash
}

func TestFile_Forget(t *testing.T) {
	f := &File{inode: &metadata.Inode{ID: "test-file"}}
	f.Forget() // Should not crash
}

func TestFile_Fsync(t *testing.T) {
	// Minimal test for interface compliance
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &File{
		fs:    &FS{ctx: ctx},
		inode: &metadata.Inode{ID: "test"},
	}
	err := f.Fsync(t.Context(), &fuse.FsyncRequest{})
	if err != nil {
		t.Errorf("Fsync failed: %v", err)
	}
}
