//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestSymlinks(t *testing.T) {
	c, node, srv, ts := SetupTestClient(t)
	defer node.Shutdown()
	defer srv.Shutdown()
	defer ts.Close()

	ctx := context.Background()

	// 1. Create a real file
	filePath := "/real_file.txt"
	content := []byte("hello world")
	if err := c.CreateFile(ctx, filePath, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 2. Create an absolute symlink
	absLinkPath := "/abs_link"
	if err := c.Symlink(ctx, filePath, absLinkPath); err != nil {
		t.Fatalf("Symlink (abs) failed: %v", err)
	}

	// 3. Create a relative symlink
	relLinkPath := "/rel_link"
	if err := c.Symlink(ctx, "real_file.txt", relLinkPath); err != nil {
		t.Fatalf("Symlink (rel) failed: %v", err)
	}

	// 4. Test Stat (follows link)
	info, err := c.Stat(ctx, absLinkPath)
	if err != nil {
		t.Fatalf("Stat(abs_link) failed: %v", err)
	}
	if info.Name() != "abs_link" {
		t.Errorf("Expected name abs_link, got %s", info.Name())
	}
	if info.IsDir() {
		t.Errorf("Expected not a directory")
	}
	// Verify it points to the real file's content/inode
	realInode, _, _ := c.ResolvePath(ctx, filePath)
	if info.Sys().(*metadata.Inode).ID != realInode.ID {
		t.Errorf("Stat did not follow absolute symlink")
	}

	infoRel, err := c.Stat(ctx, relLinkPath)
	if err != nil {
		t.Fatalf("Stat(rel_link) failed: %v", err)
	}
	if infoRel.Sys().(*metadata.Inode).ID != realInode.ID {
		t.Errorf("Stat did not follow relative symlink")
	}

	// 5. Test Lstat (does NOT follow link)
	infoL, err := c.Lstat(ctx, absLinkPath)
	if err != nil {
		t.Fatalf("Lstat failed: %v", err)
	}
	if infoL.Sys().(*metadata.Inode).Type != metadata.SymlinkType {
		t.Errorf("Lstat followed symlink, expected SymlinkType")
	}

	// 6. Test nested symlinks
	nestedLinkPath := "/nested_link"
	if err := c.Symlink(ctx, absLinkPath, nestedLinkPath); err != nil {
		t.Fatalf("Symlink (nested) failed: %v", err)
	}
	infoN, err := c.Stat(ctx, nestedLinkPath)
	if err != nil {
		t.Fatalf("Stat(nested_link) failed: %v", err)
	}
	if infoN.Sys().(*metadata.Inode).ID != realInode.ID {
		t.Errorf("Stat did not follow nested symlink")
	}

	// 7. Test symlink loop
	loop1 := "/loop1"
	loop2 := "/loop2"
	c.Symlink(ctx, loop2, loop1)
	c.Symlink(ctx, loop1, loop2)
	_, err = c.Stat(ctx, loop1)
	if err == nil || !strings.Contains(err.Error(), "too many symbolic links") {
		t.Errorf("Expected too many symbolic links error, got %v", err)
	}
}
