//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
	"net/http/httptest"
)

func TestAddEntryRegression(t *testing.T) {
	// 1. Setup Infrastructure
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, serverDK, metaSignPK := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      "user-test",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	metadata.BootstrapBackbone(t, metaNode, "user-test", dk, userSignKey)
	createUser(t, metaNode, user, userSignKey, "user-test", userSignKey)

	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// Register data node
	node := metadata.Node{
		ID:            "data1",
		Address:       tsData.URL,
		Status:        metadata.NodeStatusActive,
		LastHeartbeat: time.Now().Unix(),
	}
	nodeBytes, _ := json.Marshal(node)
	cmdBytes, _ := json.Marshal(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nodeBytes})
	metaNode.Raft.Apply(cmdBytes, 5*time.Second)

	c := NewClient(tsMeta.URL)
	c = c.withIdentity("user-test", dk)
	c = c.withSignKey(userSignKey)
	c = c.withServerKey(serverEK)
	c = c.WithAdmin(true) // Bootstrap requires admin

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if err := c.BootstrapFileSystem(context.Background()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// Capture initial count after bootstrap (likely 2: /users, /registry)
	rootInit, _ := c.getInode(context.Background(), metadata.RootID)
	initialCount := len(rootInit.Children)

	// 2. CONCURRENT ADD ENTRY
	const numFiles = 50
	var wg sync.WaitGroup
	errs := make(chan error, numFiles*2)

	for i := 0; i < numFiles; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Small random sleep to jitter starts
			time.Sleep(time.Duration(idx%5) * 10 * time.Millisecond)

			// Create a fresh client per goroutine to simulate separate sessions
			ci := NewClient(tsMeta.URL)
			ci = ci.withIdentity("user-test", dk)
			ci = ci.withSignKey(userSignKey)
			ci = ci.withServerKey(serverEK)

			name := fmt.Sprintf("dir-%d", idx)
			if err := ci.Mkdir(context.Background(), "/"+name, 0755); err != nil {
				errs <- fmt.Errorf("Mkdir %s failed: %w", name, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("Concurrent AddEntry error: %v", err)
	}

	// 3. VERIFY
	root, err := c.getInode(context.Background(), metadata.RootID)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Final Root Version: %d", root.Version)
	t.Logf("Final Root Children: %d (Initial: %d)", len(root.Children), initialCount)

	if len(root.Children)-initialCount != numFiles {
		t.Fatalf("LOST CHILDREN! Expected %d added, got %d (Final=%d, Initial=%d)", numFiles, len(root.Children)-initialCount, len(root.Children), initialCount)
	}
}
