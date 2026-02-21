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
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	defer metaNode.Shutdown()
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()

	// Create a custom handler to count Inode GET requests
	var getInodeCount uint64
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
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
	})

	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()
	registerNode(t, tsMeta.URL, "testsecret", metadata.Node{
		ID: "d1", Address: tsData.URL, Status: metadata.NodeStatusActive,
	})

	c := NewClient(tsMeta.URL)
	c = c.WithIdentity(userID, dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// We MUST initialize root with signer info if we want to bypass EnsureRoot's check later
	// But EnsureRoot uses createInode which signs it.
	// The problem is that TestPathCache might be seeing an UNSIGNED root if it was pre-created.
	// Actually EnsureRoot is called below.
	if err := c.EnsureRoot(); err != nil {
		t.Fatal(err)
	}

	// 2. Create deep hierarchy
	if err := c.Mkdir("/a"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir("/a/b"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir("/a/b/c"); err != nil {
		t.Fatal(err)
	}
	content := []byte("cached-data")
	if err := c.CreateFile("/a/b/c/f.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}

	// 3. First Resolution (Sequential)
	// Clear cache to force sequential resolution
	c.pathMu.Lock()
	c.pathCache = make(map[string]pathCacheEntry)
	c.pathMu.Unlock()

	atomic.StoreUint64(&getInodeCount, 0)
	t.Log("Starting first resolution (sequential)...")
	_, _, err := c.ResolvePath("/a/b/c/f.txt")
	if err != nil {
		t.Fatalf("First resolve failed: %v", err)
	}
	count1 := atomic.LoadUint64(&getInodeCount)
	t.Logf("First resolution took %d Inode fetches", count1)

	// Expect root + a + b + c + f.txt = 5 fetches?
	// ResolvePath("/") caches root.
	// a caches /a, etc.
	if count1 < 4 {
		t.Errorf("Expected multiple Inode fetches for sequential resolution, got %d", count1)
	}

	// 4. Second Resolution (Cached)
	// Expect exactly 1 Inode fetch (f.txt) because of the cache hit + validation.
	atomic.StoreUint64(&getInodeCount, 0)
	t.Log("Starting second resolution (cached)...")
	_, _, err = c.ResolvePath("/a/b/c/f.txt")
	if err != nil {
		t.Fatalf("Second resolve failed: %v", err)
	}
	count2 := atomic.LoadUint64(&getInodeCount)
	t.Logf("Second resolution took %d Inode fetches", count2)

	if count2 != 1 {
		t.Errorf("Expected 1 Inode fetch for cached resolution, got %d", count2)
	}

	// 5. Invalidation on Remove
	if err := c.Remove("/a/b/c/f.txt"); err != nil {
		t.Fatal(err)
	}
	_, ok := c.getPathCache("/a/b/c/f.txt")
	if ok {
		t.Error("Cache entry should have been invalidated after Remove")
	}

	// 6. Invalidation on Rename
	if err := c.CreateFile("/a/b/c/f2.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ResolvePath("/a/b/c/f2.txt"); err != nil {
		t.Fatal(err)
	}
	_, ok = c.getPathCache("/a/b/c/f2.txt")
	if !ok {
		t.Fatal("Cache not populated")
	}

	if err := c.Rename("/a/b/c/f2.txt", "/a/b/c/f3.txt"); err != nil {
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
	_, _, err = c.ResolvePath("/stale")
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
	_, ok = c.getPathCache("/stale")
	if ok {
		t.Error("Stale cache entry should have been invalidated after validation failure")
	}
}
