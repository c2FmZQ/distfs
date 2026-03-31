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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestPathCache(t *testing.T) {
	// 1. Setup Cluster
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, []byte("test-cluster-secret"))
	defer metaNode.Shutdown()
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()

	// Create a custom handler to count Inode GET requests
	var getInodeCount uint64
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	metaServer.StopKeyRotation()

	tsMeta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Count GET /v1/meta/inode/{id}
		if r.Method == "GET" && (len(r.URL.Path) > 14 && r.URL.Path[:15] == "/v1/meta/inode/") {
			atomic.AddUint64(&getInodeCount, 1)
		}
		if r.URL.Path == "/v1/meta/key/sign" {
			w.Write(signKey.Public())
			return
		}
		// Delegate auth and metadata routes to the real metaServer
		metaServer.ServeHTTP(w, r)
	}))
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	userID := "user-1"
	createUser(t, metaNode, metadata.User{
		ID: userID, SignKey: userSignKey.Public(), EncKey: dk.EncapsulationKey().Bytes(),
	}, userSignKey, userID, userSignKey)

	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()
	registerNode(t, tsMeta.URL, "testsecret", metadata.Node{
		ID: "d1", Address: tsData.URL, Status: metadata.NodeStatusActive,
	})

	c := NewClient(tsMeta.URL)
	c = c.withIdentity(userID, dk)
	c = c.withSignKey(userSignKey)
	c = c.withServerKey(serverEK)
	c = c.WithAdmin(true) // Bootstrap requires admin

	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Phase 69: Initialize Backbone
	if err := c.BootstrapFileSystem(t.Context()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// 2. Create deep hierarchy
	if err := c.Mkdir(t.Context(), "/a", 0755); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir(t.Context(), "/a/b", 0755); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir(t.Context(), "/a/b/c", 0755); err != nil {
		t.Fatal(err)
	}
	content := []byte("cached-data")
	if err := c.CreateFile(t.Context(), "/a/b/c/f.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}

	// 3. First Resolution (Sequential)
	// Clear cache to force sequential resolution
	c.clearPathCache()

	atomic.StoreUint64(&getInodeCount, 0)
	t.Log("Starting first resolution (sequential)...")
	_, _, err := c.resolvePath(t.Context(), "/a/b/c/f.txt")
	if err != nil {
		t.Fatalf("First resolve failed: %v", err)
	}
	count1 := atomic.LoadUint64(&getInodeCount)
	t.Logf("First resolution took %d Inode fetches", count1)

	// Expect root + a + b + c + f.txt = 5 fetches?
	// ResolvePath(t.Context(), "/") caches root.
	// a caches /a, etc.
	if count1 < 4 {
		t.Errorf("Expected multiple Inode fetches for sequential resolution, got %d", count1)
	}

	// 4. Second Resolution (Cached)
	// Expect exactly 0 Inode fetches (f.txt) because of the cache hit + validation.
	atomic.StoreUint64(&getInodeCount, 0)
	t.Log("Starting second resolution (cached)...")
	_, _, err = c.resolvePath(t.Context(), "/a/b/c/f.txt")
	if err != nil {
		t.Fatalf("Second resolve failed: %v", err)
	}
	count2 := atomic.LoadUint64(&getInodeCount)
	t.Logf("Second resolution took %d Inode fetches", count2)

	if count2 != 0 {
		t.Errorf("Expected 0 Inode fetches for cached resolution, got %d", count2)
	}

	// 5. Invalidation on Remove
	if err := c.Remove(t.Context(), "/a/b/c/f.txt"); err != nil {
		t.Fatal(err)
	}
	_, ok := c.getPathCache("/a/b/c/f.txt")
	if ok {
		t.Error("Cache entry should have been invalidated after Remove")
	}

	// 6. Invalidation on Rename
	if err := c.CreateFile(t.Context(), "/a/b/c/f2.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.resolvePath(t.Context(), "/a/b/c/f2.txt"); err != nil {
		t.Fatal(err)
	}
	_, ok = c.getPathCache("/a/b/c/f2.txt")
	if !ok {
		t.Fatal("Cache not populated")
	}

	if err := c.Rename(t.Context(), "/a/b/c/f2.txt", "/a/b/c/f3.txt"); err != nil {
		t.Fatal(err)
	}
	_, ok = c.getPathCache("/a/b/c/f2.txt")
	if ok {
		t.Error("Old cache entry should have been invalidated after Rename")
	}

	// 7. Validation Logic Test
	// Manually inject a stale entry pointing to a non-existent ID
	c.putPathCache("/stale", pathCacheEntry{
		inodeID: "missing-id",
		key:     make([]byte, 32),
		linkTag: "wrong-parent:wrong-hmac",
	})

	// Resolving /stale should fall back to sequential (which fails with 404)
	_, _, err = c.resolvePath(t.Context(), "/stale")
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
	_, ok = c.getPathCache("/stale")
	if ok {
		t.Error("Stale cache entry should have been invalidated after validation failure")
	}
}
