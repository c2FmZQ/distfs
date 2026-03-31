//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"io/fs"
	"testing"
)

func TestDistFS_ReadDir(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)
	defer metaNode.Shutdown()
	defer ts.Close()

	// 1. Setup User
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// Fetch actual users group ID
	info, err := adminClient.Stat(t.Context(), "/users")
	if err != nil {
		t.Fatalf("Stat /users failed: %v", err)
	}
	usersGID := info.Sys().(*InodeInfo).GroupID

	// 2. Create Structure
	// Admin creates /dir1 and shares it with 'users' group
	if err := adminClient.MkdirExtended(t.Context(), "/dir1", 0775, MkdirOptions{GroupID: usersGID}); err != nil {
		t.Fatalf("Mkdir /dir1 failed: %v", err)
	}

	// User-1 creates files inside /dir1
	if err := c.CreateFile(t.Context(), "/dir1/file1", bytes.NewReader([]byte("content")), 7); err != nil {
		t.Fatalf("CreateFile /dir1/file1 failed: %v", err)
	}
	if err := c.CreateFile(t.Context(), "/dir1/file2", bytes.NewReader([]byte("content")), 7); err != nil {
		t.Fatalf("CreateFile /dir1/file2 failed: %v", err)
	}

	// 3. ReadDir
	dfs := c.FS(t.Context())
	entries, err := fs.ReadDir(dfs, "dir1")
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}

	// Verify names
	found := make(map[string]bool)
	for _, e := range entries {
		found[e.Name()] = true
		if e.IsDir() {
			t.Error("Expected file, got dir")
		}
	}
	if !found["file1"] || !found["file2"] {
		t.Error("Missing expected files")
	}

	// Test ReadDirFile
	f, err := dfs.Open("dir1")
	if err != nil {
		t.Fatalf("Open dir1 failed: %v", err)
	}
	dirFile, ok := f.(fs.ReadDirFile)
	if !ok {
		t.Fatal("Open directory did not return ReadDirFile")
	}
	defer f.Close()
	entries2, _ := dirFile.ReadDir(-1)
	if len(entries2) != 2 {
		t.Errorf("ReadDir(-1) got %d entries, want 2", len(entries2))
	}
}
