// Copyright 2026 TTBT Enterprises LLC
package fuse

import (
	"testing"

	"bazil.org/fuse"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestFS_Statfs(t *testing.T) {
	// Minimal test to ensure it doesn't crash and returns expected structure
	c := client.NewClient("http://localhost:8080")
	f := NewFS(c)

	// Since we are not running a real server, this will fail but we want to check mapError integration
	req := &fuse.StatfsRequest{}
	resp := &fuse.StatfsResponse{}
	err := f.Statfs(t.Context(), req, resp)
	if err == nil {
		t.Errorf("expected error from unstarted client")
	}
}

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
	f := &File{
		inode: &metadata.Inode{ID: "test"},
	}
	err := f.Fsync(t.Context(), &fuse.FsyncRequest{})
	if err != nil {
		t.Errorf("Fsync failed: %v", err)
	}
}
