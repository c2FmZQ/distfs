//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func TestWriteConsistency_SynchronousReplication(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()

	ctx := t.Context()
	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// Provision User while cluster is healthy (only data1 active)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")
	c.ClearNodeCache()

	// Admin: Provision user home
	if err := adminClient.MkdirExtended(ctx, "/users/user-1", 0755, MkdirOptions{OwnerID: "user-1"}); err != nil {
		t.Fatalf("Mkdir /users/user-1 failed: %v", err)
	}

	// 1. Setup 3 Data Nodes
	tsList := make([]*httptest.Server, 3)
	for i := 0; i < 3; i++ {
		tmpDir := t.TempDir()
		mk, _ := storage_crypto.CreateAESMasterKeyForTest()
		st := storage.New(tmpDir, mk)
		ds, _ := data.NewDiskStore(st)
		srv := data.NewServer(ds, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
		tsList[i] = httptest.NewServer(srv)
		defer tsList[i].Close()

		nodeInfo := metadata.Node{ID: fmt.Sprintf("n%d", i+1), Address: tsList[i].URL, Status: metadata.NodeStatusActive, LastHeartbeat: time.Now().Unix()}
		nb, _ := json.Marshal(nodeInfo)
		nbb, _ := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
		if err := metaNode.Raft.Apply(nbb, 5*time.Second).Error(); err != nil {
			t.Fatalf("failed to register node n%d: %v", i+1, err)
		}
	}

	// Deactivate default node
	oldNode, _ := metaNode.FSM.GetNode("data1")
	nb, _ := json.Marshal(metadata.Node{ID: "data1", Address: oldNode.Address, Status: metadata.NodeStatusDead})
	nbb, _ := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
	metaNode.Raft.Apply(nbb, 5*time.Second).Error()

	// 2. Write a file
	content := bytes.Repeat([]byte("consistency test"), 1000)
	if err := c.CreateFile(ctx, "/users/user-1/consistent-file", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 3. Verify it exists on all 3 nodes
	inode, _, err := c.resolvePath(ctx, "/users/user-1/consistent-file")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}
	chunkID := ""
	if len(inode.ChunkManifest) > 0 {
		chunkID = inode.ChunkManifest[0].ID
	}

	// Fetch token for verification
	token, err := c.issueToken(ctx, inode.ID, []string{chunkID}, "R")
	if err != nil {
		t.Fatalf("issueToken failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", tsList[i].URL+"/v1/data/"+chunkID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		c.sessionMu.RLock()
		sess := c.sessionToken
		c.sessionMu.RUnlock()
		if sess != "" {
			req.Header.Set("Session-Token", sess)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Errorf("Chunk missing on node %d (status %d)", i+1, resp.StatusCode)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}

func TestWriteConsistency_QuorumSuccess(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()

	ctx := t.Context()
	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// Provision User while cluster is healthy (only data1 active)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")
	c.ClearNodeCache()

	// Admin: Provision user home
	if err := adminClient.MkdirExtended(ctx, "/users/user-1", 0755, MkdirOptions{OwnerID: "user-1"}); err != nil {
		t.Fatalf("Mkdir /users/user-1 failed: %v", err)
	}

	// 1. Setup 3 Data Nodes, but shut down one
	tsList := make([]*httptest.Server, 3)
	for i := 0; i < 3; i++ {
		tmpDir := t.TempDir()
		mk, _ := storage_crypto.CreateAESMasterKeyForTest()
		st := storage.New(tmpDir, mk)
		ds, _ := data.NewDiskStore(st)
		srv := data.NewServer(ds, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
		tsList[i] = httptest.NewServer(srv)
		defer tsList[i].Close()

		nodeInfo := metadata.Node{ID: fmt.Sprintf("n%d", i+1), Address: tsList[i].URL, Status: metadata.NodeStatusActive, LastHeartbeat: time.Now().Unix()}
		nb, _ := json.Marshal(nodeInfo)
		nbb, _ := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
		metaNode.Raft.Apply(nbb, 5*time.Second).Error()
	}

	// Deactivate default node
	oldNode, _ := metaNode.FSM.GetNode("data1")
	nb, _ := json.Marshal(metadata.Node{ID: "data1", Address: oldNode.Address, Status: metadata.NodeStatusDead})
	nbb, _ := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
	metaNode.Raft.Apply(nbb, 5*time.Second).Error()

	// Shut down node 3
	tsList[2].Close()

	// 2. Write a file
	content := bytes.Repeat([]byte("quorum test"), 1000)
	if err := c.CreateFile(ctx, "/users/user-1/quorum-file", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("Expected CreateFile to succeed with 2/3 nodes, but failed: %v", err)
	}
}

func TestWriteConsistency_QuorumFailure(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()

	ctx := t.Context()
	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// Provision User while cluster is healthy (only data1 active)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")
	c.ClearNodeCache()

	// Admin: Provision user home
	if err := adminClient.MkdirExtended(ctx, "/users/user-1", 0755, MkdirOptions{OwnerID: "user-1"}); err != nil {
		t.Fatalf("Mkdir /users/user-1 failed: %v", err)
	}

	// 1. Setup 3 Data Nodes, but shut down two
	for i := 0; i < 3; i++ {
		addr := "http://127.0.0.1:1"
		if i == 0 {
			tmpDir := t.TempDir()
			mk, _ := storage_crypto.CreateAESMasterKeyForTest()
			st := storage.New(tmpDir, mk)
			ds, _ := data.NewDiskStore(st)
			srv := data.NewServer(ds, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
			ts1 := httptest.NewServer(srv)
			defer ts1.Close()
			addr = ts1.URL
		} else {
			addr = fmt.Sprintf("http://127.0.0.1:%d", i+1)
		}

		nodeInfo := metadata.Node{ID: fmt.Sprintf("n%d", i+1), Address: addr, Status: metadata.NodeStatusActive, LastHeartbeat: time.Now().Unix()}
		nb, _ := json.Marshal(nodeInfo)
		nbb, _ := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
		metaNode.Raft.Apply(nbb, 5*time.Second).Error()
	}

	// Deactivate default node
	oldNode, _ := metaNode.FSM.GetNode("data1")
	nb, _ := json.Marshal(metadata.Node{ID: "data1", Address: oldNode.Address, Status: metadata.NodeStatusDead})
	nbb, _ := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
	metaNode.Raft.Apply(nbb, 5*time.Second).Error()

	// 2. Write a file
	content := bytes.Repeat([]byte("fail test"), 1000)

	// Use a shorter timeout to avoid hanging the test suite
	shortCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := c.CreateFile(shortCtx, "/users/user-1/fail-file", bytes.NewReader(content), int64(len(content))); err == nil {
		t.Errorf("Expected WriteFile to fail because quorum (2/3) not reached")
	}
}

func TestFailureRecovery_CleanupOrphans(t *testing.T) {
	adminClient, metaNode, _, ts, adminID, adminSK := setupTestClient(t)
	defer ts.Close()

	ctx := t.Context()
	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// Provision User while cluster is healthy (only data1 active)
	c, _, _ := provisionUser(t, ts, metaNode, adminClient, adminID, adminSK, "user-1")
	c.ClearNodeCache()

	// Admin: Provision user home
	if err := adminClient.MkdirExtended(ctx, "/users/user-1", 0755, MkdirOptions{OwnerID: "user-1"}); err != nil {
		t.Fatalf("Mkdir /users/user-1 failed: %v", err)
	}

	// 1. Setup 1 Data Node
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st1 := storage.New(tmpDir, mk)
	ds1, _ := data.NewDiskStore(st1)
	srv1 := data.NewServer(ds1, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	ts1 := httptest.NewServer(srv1)
	defer ts1.Close()

	nodeInfo := metadata.Node{ID: "n1", Address: ts1.URL, Status: metadata.NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	nb, _ := json.Marshal(nodeInfo)
	nbb, _ := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
	metaNode.Raft.Apply(nbb, 5*time.Second).Error()

	// Deactivate default node
	oldNode, _ := metaNode.FSM.GetNode("data1")
	nb, _ = json.Marshal(metadata.Node{ID: "data1", Address: oldNode.Address, Status: metadata.NodeStatusDead})
	nbb, _ = metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
	metaNode.Raft.Apply(nbb, 5*time.Second).Error()

	// 2. Create an initial file
	if err := c.CreateFile(ctx, "/users/user-1/orphan-test", bytes.NewReader([]byte("initial")), 7); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 3. Update the file but MOCK metadata update failure
	// We'll use a short timeout context to force failure during WriteFile without infinite retries
	largeContent := bytes.Repeat([]byte("B"), 2*1024*1024)

	// Close metadata server to force failure
	ts.Close()

	writeCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if _, err := c.writeFile(writeCtx, "/users/user-1/orphan-test", nil, bytes.NewReader(largeContent), int64(len(largeContent)), 0644); err == nil {
		t.Errorf("Expected WriteFile to fail due to metadata server closure")
	}

	// 4. Verify that chunks were cleaned up
	time.Sleep(1 * time.Second)

	count := 0
	for range ds1.ListChunks() {
		count++
	}

	if count > 1 {
		t.Errorf("Expected at most 1 chunk on data node after cleanup, got %d", count)
	}
}
