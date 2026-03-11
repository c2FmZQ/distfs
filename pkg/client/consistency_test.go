// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func TestWriteConsistency_SynchronousReplication(t *testing.T) {
	ctx := context.Background()
	c, metaNode, _, ts := SetupTestClient(t)
	defer ts.Close()

	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// 1. Setup 3 Data Nodes manually to have control
	createNode := func(id string) (*httptest.Server, data.Store) {
		tmpDir := t.TempDir()
		mk, _ := storage_crypto.CreateAESMasterKeyForTest()
		st := storage.New(tmpDir, mk)
		ds, _ := data.NewDiskStore(st)
		srv := data.NewServer(ds, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
		ts := httptest.NewServer(srv)
		
		nodeInfo := metadata.Node{ID: id, Address: ts.URL, Status: metadata.NodeStatusActive}
		nb, _ := json.Marshal(nodeInfo)
		metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second)
		
		return ts, ds
	}

	ts1, _ := createNode("n1")
	defer ts1.Close()
	ts2, _ := createNode("n2")
	defer ts2.Close()
	ts3, _ := createNode("n3")
	defer ts3.Close()

	// 2. Write a file
	content := bytes.Repeat([]byte("A"), 2*1024*1024) // 2 chunks
	err := c.CreateFile(ctx, "/test-file", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 3. Immediately shut down the primary node (assuming n1 was primary)
	ts1.Close()

	// 4. Try to read the file
	f, err := c.Open(ctx, "/test-file", 0, 0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer f.Close()

	readContent, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(readContent, content) {
		t.Errorf("Content mismatch")
	}
}

func TestWriteConsistency_QuorumSuccess(t *testing.T) {
	ctx := context.Background()
	c, metaNode, _, ts := SetupTestClient(t)
	defer ts.Close()

	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// 1. Setup 3 Data Nodes
	createNode := func(id string) (*httptest.Server, data.Store) {
		tmpDir := t.TempDir()
		mk, _ := storage_crypto.CreateAESMasterKeyForTest()
		st := storage.New(tmpDir, mk)
		ds, _ := data.NewDiskStore(st)
		srv := data.NewServer(ds, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
		ts := httptest.NewServer(srv)
		
		nodeInfo := metadata.Node{ID: id, Address: ts.URL, Status: metadata.NodeStatusActive}
		nb, _ := json.Marshal(nodeInfo)
		metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second)
		
		return ts, ds
	}

	ts1, _ := createNode("n1")
	defer ts1.Close()
	ts2, _ := createNode("n2")
	defer ts2.Close()
	ts3, _ := createNode("n3")
	// WE CLOSE n3 IMMEDIATELY. It is registered but down.
	ts3.Close()

	// 2. Write a file
	content := bytes.Repeat([]byte("quorum test"), 1000) 
	
	var err error
	for i := 0; i < 5; i++ {
		err = c.CreateFile(ctx, "/quorum-file", bytes.NewReader(content), int64(len(content)))
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		t.Fatalf("Expected CreateFile to succeed with 2/3 nodes, but failed: %v", err)
	}
}

func TestWriteConsistency_QuorumFailure(t *testing.T) {
	ctx := context.Background()
	c, metaNode, _, ts := SetupTestClient(t)
	defer ts.Close()

	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// 1. Setup 1 Data Node that is UP, and 2 that are DOWN
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st1 := storage.New(tmpDir, mk)
	ds1, _ := data.NewDiskStore(st1)
	srv1 := data.NewServer(ds1, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	ts1 := httptest.NewServer(srv1)
	defer ts1.Close()

	register := func(id, addr string) {
		nodeInfo := metadata.Node{ID: id, Address: addr, Status: metadata.NodeStatusActive}
		nb, _ := json.Marshal(nodeInfo)
		metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second)
	}

	register("n1", ts1.URL)
	register("n2", "http://127.0.0.1:1") // DOWN
	register("n3", "http://127.0.0.1:2") // DOWN

	// 2. Write a file
	content := bytes.Repeat([]byte("fail test"), 1000) 
	
	err := c.CreateFile(ctx, "/fail-file", bytes.NewReader(content), int64(len(content)))
	if err == nil {
		t.Errorf("Expected WriteFile to fail because quorum (2/3) not reached")
	} else {
		t.Logf("Caught expected failure: %v", err)
	}
}

func TestFailureRecovery_CleanupOrphans(t *testing.T) {
	ctx := context.Background()
	c, metaNode, _, ts := SetupTestClient(t)
	defer ts.Close()

	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()

	// 1. Setup 1 Data Node
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st1 := storage.New(tmpDir, mk)
	ds1, _ := data.NewDiskStore(st1)
	srv1 := data.NewServer(ds1, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	ts1 := httptest.NewServer(srv1)
	defer ts1.Close()

	nodeInfo := metadata.Node{ID: "n1", Address: ts1.URL, Status: metadata.NodeStatusActive}
	nb, _ := json.Marshal(nodeInfo)
	metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second)

	// 2. Create an initial file
	err := c.CreateFile(ctx, "/orphan-test", bytes.NewReader([]byte("initial")), 14)
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 3. Update the file but MOCK metadata update failure
	// We'll close the metadata server to simulate failure
	ts.Close()

	largeContent := bytes.Repeat([]byte("B"), 2*1024*1024)
	_, err = c.WriteFile(ctx, "/orphan-test", nil, bytes.NewReader(largeContent), int64(len(largeContent)), 0644)
	if err == nil {
		t.Errorf("Expected WriteFile to fail due to metadata server closure")
	}

	// 4. Verify that chunks were cleaned up
	// Give it a second for the background cleanup to run
	time.Sleep(1 * time.Second)

	// Since the data server is still up, we can check if it has any chunks.
	count := 0
	for range ds1.ListChunks() {
		count++
	}

	if count > 0 {
		t.Errorf("Expected 0 chunks on data node after cleanup, got %d", count)
	}
}
