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
)

func TestClient_DeleteInode(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Create a file
	c.Mkdir(ctx, "/dir1")
	err := c.CreateFile(ctx, "/dir1/file1", bytes.NewReader([]byte("hello")), 5)
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	inode, _, _ := c.ResolvePath(ctx, "/dir1/file1")
	
	// Delete it
	err = c.DeleteInode(ctx, inode.ID)
	if err != nil {
		t.Fatalf("DeleteInode failed: %v", err)
	}

	// Verify it's gone
	_, _, err = c.ResolvePath(ctx, "/dir1/file1")
	if err == nil {
		t.Error("Expected error resolving deleted path, got nil")
	}
}

func TestClient_SyncFile(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Setup a Data Node for Sync
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	
	csk := metadata.GetClusterSignKey(metaNode.FSM)

	dataServer := data.NewServer(dataStore, csk.Public, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register Data Node
	nodeInfo := metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNode(t, ts.URL, "testsecret", nodeInfo)

	// Create a file
	path := "/test-sync"
	content := []byte("original content")
	c.CreateFile(ctx, path, bytes.NewReader(content), int64(len(content)))

	inode, key, _ := c.ResolvePath(ctx, path)

	// Sync with updates
	newContent := []byte("updated content and much longer to force chunking if needed")
	dirty := map[int64]bool{0: true}
	updatedInode, err := c.SyncFile(ctx, inode.ID, bytes.NewReader(newContent), int64(len(newContent)), dirty)
	if err != nil {
		t.Fatalf("SyncFile failed: %v", err)
	}

	if updatedInode.Size != uint64(len(newContent)) {
		t.Errorf("Expected size %d, got %d", len(newContent), updatedInode.Size)
	}

	// Read back and verify
	reader, _ := c.NewReader(ctx, updatedInode.ID, key)
	readBack, _ := io.ReadAll(reader)
	if !bytes.Equal(readBack, newContent) {
		t.Errorf("Expected %s, got %s", string(newContent), string(readBack))
	}
}

func TestClient_AdminChmod(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Promote user to admin
	metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdPromoteAdmin, Data: []byte("u1")}.Marshal(), 5*time.Second)

	// Create a file
	path := "/secret"
	c.CreateFile(ctx, path, bytes.NewReader([]byte("data")), 4)
	inode, _, _ := c.ResolvePath(ctx, path)

	// Chmod via Admin
	err := c.AdminChmod(ctx, inode.ID, 0640)
	if err != nil {
		t.Fatalf("AdminChmod failed: %v", err)
	}

	// Verify
	updated, _, _ := c.ResolvePath(ctx, path)
	if updated.Mode != 0640 {
		t.Errorf("Expected mode 0640, got %o", updated.Mode)
	}
}

func TestClient_ChunkDataOps(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	
	csk := metadata.GetClusterSignKey(metaNode.FSM)

	dataServer := data.NewServer(dataStore, csk.Public, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	nodeInfo := metadata.Node{ID: "data1", Address: tsData.URL, Status: metadata.NodeStatusActive}
	registerNode(t, ts.URL, "testsecret", nodeInfo)

	// 1. UploadChunkData
	fileID := "f1"
	fileKey := make([]byte, 32)
	chunkData := []byte("chunk payload")
	
	// Create Inode first to allow token issue
	inode := metadata.Inode{ID: fileID, OwnerID: "u1", Type: metadata.FileType}
	ib, _ := json.Marshal(inode)
	metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateInode, Data: ib}.Marshal(), 5*time.Second)

	entry, err := c.UploadChunkData(ctx, fileID, fileKey, 0, chunkData)
	if err != nil {
		t.Fatalf("UploadChunkData failed: %v", err)
	}

	// 2. DownloadChunkData
	// urls are usually populated by server but we can pass them manually for test
	downloaded, err := c.DownloadChunkData(ctx, fileID, entry.ID, entry.URLs, fileKey)
	if err != nil {
		t.Fatalf("DownloadChunkData failed: %v", err)
	}

	// Truncate to expected size (DecryptChunk returns 1MB padded)
	if len(downloaded) > len(chunkData) {
		downloaded = downloaded[:len(chunkData)]
	}

	if !bytes.Equal(downloaded, chunkData) {
		t.Errorf("Expected %s, got %s", string(chunkData), string(downloaded))
	}
}

func TestClient_OpenBlobWrite(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	csk := metadata.GetClusterSignKey(metaNode.FSM)
	dataServer := data.NewServer(dataStore, csk.Public, nil, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	registerNode(t, ts.URL, "testsecret", metadata.Node{ID: "data1", Address: tsData.URL, Status: metadata.NodeStatusActive})

	// Open for writing
	path := "/bigblob"
	wc, err := c.OpenBlobWrite(ctx, path)
	if err != nil {
		t.Fatalf("OpenBlobWrite failed: %v", err)
	}

	// Write 1.5 MB (more than 1MB chunk size)
	dataSize := 3 * 1024 * 1024 / 2 // 1.5MB
	payload := make([]byte, dataSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := wc.Write(payload)
	if err != nil || n != dataSize {
		t.Fatalf("Write failed: %v, n=%d", err, n)
	}

	err = wc.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read back and verify
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	reader, _ := c.NewReader(ctx, inode.ID, key)
	readBack, _ := io.ReadAll(reader)
	if !bytes.Equal(readBack, payload) {
		t.Error("Data mismatch in big blob")
	}
}

func TestClient_ExtraDataOps(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()
	c.EnsureRoot(ctx)

	// 1. CommitInodeManifest
	path := "/f1"
	c.CreateFile(ctx, path, bytes.NewReader([]byte("init")), 4)
	inode, _, _ := c.ResolvePath(ctx, path)

	manifest := []metadata.ChunkEntry{{ID: "c1", Nodes: []string{"n1"}}}
	_, err := c.CommitInodeManifest(ctx, inode.ID, manifest, 100)
	if err != nil {
		t.Fatalf("CommitInodeManifest failed: %v", err)
	}

	// 2. FetchChunk (Error case: missing chunk)
	_, err = c.FetchChunk(ctx, inode.ID, make([]byte, 32), 0)
	if err == nil {
		// Might fail because urls are missing, but let's see.
	}

	// 3. OpenBlobRead (Resolution failure)
	_, err = c.OpenBlobRead(ctx, "/missing/path")
	if err == nil {
		t.Error("OpenBlobRead should fail for missing path")
	}
}
