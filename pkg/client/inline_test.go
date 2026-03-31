//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bytes"
	"io"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestSmallFileInlining(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)
	defer metaNode.Shutdown()
	defer ts.Close()

	// 1. Setup User
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")

	// 2. Write Small File (Inlined)
	smallContent := []byte("small file content")
	nonce := metadata.GenerateNonce()
	fileID := metadata.GenerateInodeID("user-1", nonce)
	if _, err := c.writeFile(t.Context(), fileID, nonce, bytes.NewReader(smallContent), int64(len(smallContent)), 0644); err != nil {
		t.Fatalf("Write small file failed: %v", err)
	}

	// 3. Verify Inode state
	inode, err := c.getInode(t.Context(), fileID)
	if err != nil {
		t.Fatal(err)
	}
	if len(inode.GetInlineData()) == 0 {
		t.Error("Expected InlineData to be set for small file")
	}
	if len(inode.ChunkManifest) != 0 {
		t.Error("Expected ChunkManifest to be empty for inlined file")
	}

	// 4. Read back
	rc, err := c.readFile(t.Context(), fileID, nil)
	if err != nil {
		t.Fatal(err)
	}
	readBack, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(readBack, smallContent) {
		t.Errorf("Read back mismatch: got %s, want %s", readBack, smallContent)
	}

	// 5. Grow file beyond InlineLimit (Eviction)
	largeSize := metadata.InlineLimit + 100
	largeContent := bytes.Repeat([]byte("A"), largeSize)
	// For eviction, we need a fresh nonce for the new large inode or it must be an update.
	// WriteFile with the same fileID will trigger UpdateInode.
	if _, err := c.writeFile(t.Context(), fileID, nil, bytes.NewReader(largeContent), int64(len(largeContent)), 0644); err != nil {
		t.Fatalf("Grow file failed: %v", err)
	}

	// 6. Verify Eviction
	inode, err = c.getInode(t.Context(), fileID)
	if err != nil {
		t.Fatal(err)
	}
	if len(inode.GetInlineData()) > 0 {
		t.Error("Expected InlineData to be cleared after growth")
	}
	if len(inode.ChunkManifest) == 0 {
		t.Error("Expected ChunkManifest to be populated after growth")
	}

	// 7. Read back large
	rc, err = c.readFile(t.Context(), fileID, nil)
	if err != nil {
		t.Fatal(err)
	}
	readBackLarge, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(readBackLarge, largeContent) {
		t.Error("Large read back mismatch")
	}
}
