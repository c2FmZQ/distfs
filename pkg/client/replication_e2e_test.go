//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	bolt "go.etcd.io/bbolt"
)

func createDataNode(t *testing.T, metaNode *metadata.RaftNode, id string) (*httptest.Server, data.Store) {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)
	ds, _ := data.NewDiskStore(st)

	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()
	srv := data.NewServer(ds, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	ts := httptest.NewServer(srv)

	nodeInfo := metadata.Node{
		ID:            id,
		Address:       ts.URL,
		Status:        metadata.NodeStatusActive,
		LastHeartbeat: time.Now().Unix(),
	}
	nb, _ := json.Marshal(nodeInfo)
	nbb, err := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal register node command: %v", err)
	}
	if err := metaNode.Raft.Apply(nbb, 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to register node: %v", err)
	}

	return ts, ds
}

func markNodeOffline(t *testing.T, metaNode *metadata.RaftNode, id, address string) {
	nodeInfo := metadata.Node{
		ID:            id,
		Address:       address,
		Status:        metadata.NodeStatusDead,
		LastHeartbeat: time.Now().Add(-10 * time.Minute).Unix(), // Old heartbeat
	}
	nb, _ := json.Marshal(nodeInfo)
	nbb, err := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal node offline command: %v", err)
	}
	if err := metaNode.Raft.Apply(nbb, 5*time.Second).Error(); err != nil {
		t.Fatalf("Failed to mark node offline: %v", err)
	}
}

func TestReplication_UnderReplicationRepair(t *testing.T) {
	ctx := context.Background()
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Setup 2 EXTRA Data Nodes (Along with n1 from setup, that's 3 total)
	ts1, _ := createDataNode(t, metaNode, "repair-n1")
	defer ts1.Close()
	ts2, _ := createDataNode(t, metaNode, "repair-n2")
	defer ts2.Close()

	// Small sleep to ensure Raft apply to FSM
	time.Sleep(200 * time.Millisecond)

	// 2. Write a file (USE 1MB CONTENT to ensure chunking)
	content := bytes.Repeat([]byte("R"), 1024*1024)
	err := c.CreateFile(ctx, "/repair-test", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// Verify it has 3 replicas
	inode, _, _ := c.ResolvePath(ctx, "/repair-test")
	if len(inode.ChunkManifest) == 0 {
		t.Fatal("File was inlined, test won't work")
	}
	t.Logf("Initial nodes: %v", inode.ChunkManifest[0].Nodes)
	if len(inode.ChunkManifest[0].Nodes) < 3 {
		t.Fatalf("Initial replication factor too low: %d", len(inode.ChunkManifest[0].Nodes))
	}

	// 3. Kill one node (repair-n2)
	targetID := "repair-n2"
	targetURL := ts2.URL
	ts2.Close()
	markNodeOffline(t, metaNode, targetID, targetURL)

	// Register a new healthy node (repair-n3)
	ts3, _ := createDataNode(t, metaNode, "repair-n3")
	defer ts3.Close()
	time.Sleep(100 * time.Millisecond)

	// 4. Force a replication scan
	metaServer.ForceReplicationScan()

	// Give it some time to detect and repair
	time.Sleep(3 * time.Second)

	// 5. Fresh client
	c2 := NewClient(ts.URL).WithIdentity(c.userID, c.decKey).WithSignKey(c.signKey).WithServerKey(c.serverKey)
	c2.Login(ctx)

	inode2, _, err := c2.ResolvePath(ctx, "/repair-test")
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	nodes := inode2.ChunkManifest[0].Nodes
	t.Logf("Nodes after repair: %v", nodes)

	found := false
	for _, n := range nodes {
		if n == "repair-n3" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Repair didn't add node repair-n3 to manifest. Current nodes: %v", nodes)
	}
}

func TestReplication_OverReplicationPruning(t *testing.T) {
	ctx := context.Background()
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Setup 2 EXTRA Data Nodes (3 total)
	ts1, _ := createDataNode(t, metaNode, "prune-n1")
	defer ts1.Close()
	ts2, _ := createDataNode(t, metaNode, "prune-n2")
	defer ts2.Close()
	time.Sleep(200 * time.Millisecond)

	// 2. Write a file
	content := bytes.Repeat([]byte("P"), 1024*1024)
	err := c.CreateFile(ctx, "/prune-test", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 3. MANUALLY add a 4th replica
	inode, _, _ := c.ResolvePath(ctx, "/prune-test")
	if len(inode.ChunkManifest) == 0 {
		t.Fatal("File was inlined, test won't work")
	}
	chunkID := inode.ChunkManifest[0].ID

	ts3, _ := createDataNode(t, metaNode, "prune-n3")
	defer ts3.Close()
	time.Sleep(100 * time.Millisecond)

	req := metadata.AddReplicaRequest{
		InodeID: inode.ID,
		ChunkID: chunkID,
		NodeIDs: []string{"prune-n3"},
	}
	rb, _ := json.Marshal(req)
	rbb, err := metadata.LogCommand{Type: metadata.CmdAddChunkReplica, Data: rb}.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal add replica command: %v", err)
	}
	if err := metaNode.Raft.Apply(rbb, 5*time.Second).Error(); err != nil {
		t.Fatalf("AddReplica failed: %v", err)
	}

	// Verify it now has 4 replicas
	time.Sleep(200 * time.Millisecond)
	c2 := NewClient(ts.URL).WithIdentity(c.userID, c.decKey).WithSignKey(c.signKey).WithServerKey(c.serverKey)
	c2.Login(ctx)
	inode2, _, _ := c2.ResolvePath(ctx, "/prune-test")
	t.Logf("Nodes before pruning: %v", inode2.ChunkManifest[0].Nodes)
	if len(inode2.ChunkManifest[0].Nodes) != 4 {
		t.Fatalf("Expected 4 replicas, got %d", len(inode2.ChunkManifest[0].Nodes))
	}

	// 4. Force Pruning Scan
	metaServer.ForceReplicationScan()
	time.Sleep(3 * time.Second)

	// 5. Verify back to 3 replicas
	c3 := NewClient(ts.URL).WithIdentity(c.userID, c.decKey).WithSignKey(c.signKey).WithServerKey(c.serverKey)
	c3.Login(ctx)
	inode3, _, _ := c3.ResolvePath(ctx, "/prune-test")
	finalNodes := inode3.ChunkManifest[0].Nodes
	t.Logf("Nodes after pruning: %v", finalNodes)
	if len(finalNodes) != 3 {
		t.Errorf("Pruning failed: expected 3 replicas, got %d: %v", len(finalNodes), finalNodes)
	}
}

func TestIntegrity_ContentSwapAttack(t *testing.T) {
	ctx := context.Background()
	c, metaNode, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Setup Data Node
	createDataNode(t, metaNode, "attack-n1")

	// 2. Write File A
	contentA := bytes.Repeat([]byte("FILE_A"), 1000) // 6000 bytes
	err := c.CreateFile(ctx, "/file-a", bytes.NewReader(contentA), int64(len(contentA)))
	if err != nil {
		t.Fatalf("CreateFile A failed: %v", err)
	}

	// 3. Write File B
	contentB := bytes.Repeat([]byte("FILE_B"), 1000) // 6000 bytes
	err = c.CreateFile(ctx, "/file-b", bytes.NewReader(contentB), int64(len(contentB)))
	if err != nil {
		t.Fatalf("CreateFile B failed: %v", err)
	}

	// 4. MALICIOUS SERVER ATTACK: Swap ChunkID of File A with ChunkID of File B
	var inodeA, inodeB *metadata.Inode
	var errA, errB error
	inodeA, _, errA = c.ResolvePath(ctx, "/file-a")
	if errA != nil {
		t.Fatalf("ResolvePath A failed: %v", errA)
	}
	inodeB, _, errB = c.ResolvePath(ctx, "/file-b")
	if errB != nil {
		t.Fatalf("ResolvePath B failed: %v", errB)
	}

	if len(inodeA.ChunkManifest) == 0 || len(inodeB.ChunkManifest) == 0 {
		t.Fatalf("Files were inlined, test won't work. Size A: %d, Size B: %d", inodeA.Size, inodeB.Size)
	}

	t.Logf("File A Size: %d, ChunkID: %s", inodeA.Size, inodeA.ChunkManifest[0].ID)
	t.Logf("File B Size: %d, ChunkID: %s", inodeB.Size, inodeB.ChunkManifest[0].ID)

	if inodeA.ChunkManifest[0].ID == inodeB.ChunkManifest[0].ID {
		t.Fatal("CHUNK IDs ARE SAME! Content swap attack test is invalid.")
	}

	// Swap!
	maliciousInode := *inodeA
	maliciousManifest := make([]metadata.ChunkEntry, len(inodeA.ChunkManifest))
	copy(maliciousManifest, inodeA.ChunkManifest)
	maliciousManifest[0].ID = inodeB.ChunkManifest[0].ID
	maliciousInode.ChunkManifest = maliciousManifest
	// Increment version so FSM accepts the update
	maliciousInode.Version++

	mb, _ := json.Marshal(maliciousInode)
	err = metaNode.FSM.DB().Update(func(tx *bolt.Tx) error {
		return metaNode.FSM.Put(tx, []byte("inodes"), []byte(maliciousInode.ID), mb)
	})
	if err != nil {
		t.Fatalf("Malicious db update failed: %v", err)
	}

	// 5. Fresh client
	c2 := NewClient(ts.URL).WithIdentity(c.userID, c.decKey).WithSignKey(c.signKey).WithServerKey(c.serverKey)
	c2.Login(ctx)

	// Attempt to read File A
	_, _, err = c2.ResolvePath(ctx, "/file-a")
	if err == nil {
		t.Error("Expected error when reading tampered Inode (content swap), but it succeeded")
	} else {
		t.Logf("Caught expected integrity error: %v", err)
	}
}
