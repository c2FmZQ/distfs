//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestOfflineFallback(t *testing.T) {
	// 1. Setup Cluster and Client
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, []byte("test-cluster-secret"))
	defer metaNode.Shutdown()
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, _ := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	// We'll close this later to simulate "down"

	// Register a data node
	tsData, _ := createDataNode(t, metaNode, "data1")
	defer tsData.Close()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	userID := "user-offline"
	metadata.BootstrapBackbone(t, metaNode, userID, dk, userSignKey)
	createUser(t, metaNode, metadata.User{
		ID: userID, SignKey: userSignKey.Public(), EncKey: dk.EncapsulationKey().Bytes(),
	}, userSignKey, userID, userSignKey)

	// Setup Client with Cache
	cacheDir := t.TempDir()
	native, _ := NewNativeStore(cacheDir, 0)
	cacheKey := make([]byte, 32)

	c := NewClient(tsMeta.URL).
		withIdentity(userID, dk).
		withSignKey(userSignKey).
		withServerKey(serverEK).
		WithSecureStore(native, cacheKey).
		WithAdmin(true)

	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := c.BootstrapFileSystem(context.Background()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// 2. Populate Cache (Online)
	filePath := "/testfile"
	content := []byte("hello offline world")
	if err := c.CreateFile(context.Background(), filePath, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}

	// Read it once to ensure it's in cache (metadata and chunks)
	rc, err := c.OpenBlobRead(context.Background(), filePath)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, rc)
	rc.Close()

	// 3. Go Offline (Simulate server down)
	tsMeta.Close()
	c.SetOffline(true)

	// 4. Verify Read from Cache
	rc, err = c.OpenBlobRead(context.Background(), filePath)
	if err != nil {
		t.Fatalf("OpenBlobRead failed in offline mode: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("expected %s, got %s", content, got)
	}

	// 5. Verify Mutation Fails
	err = c.Mkdir(context.Background(), "/offline-dir", 0755)
	if err == nil {
		t.Error("expected Mkdir to fail in offline mode")
	}
}
