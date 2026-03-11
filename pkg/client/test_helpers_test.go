// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
)

func SetupTestClient(t *testing.T) (*Client, *metadata.RaftNode, *metadata.Server, *httptest.Server) {
	metaDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	metaSt := storage.New(metaDir, mk)

	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, []byte("test-cluster-secret"))

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})

	// Wait for leader
	for i := 0; i < 50; i++ {
		if metaNode.Raft.State() == raft.Leader {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Bootstrap cluster keys
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	keyID := "key-1"
	key := metadata.ClusterKey{ID: keyID, EncKey: ek.Bytes(), DecKey: nil, CreatedAt: time.Now().Unix()}
	kb, _ := json.Marshal(key)
	if err := metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRotateKey, Data: kb}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Raft apply RotateKey failed: %v", err)
	}

	csk, _ := crypto.GenerateIdentityKey()
	cskData := metadata.ClusterSignKey{Public: csk.Public(), EncryptedPrivate: csk.MarshalPrivate()}
	cb, _ := json.Marshal(cskData)
	if err := metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdSetClusterSignKey, Data: cb}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Raft apply SetClusterSignKey failed: %v", err)
	}

	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	metaServer.RegisterEpochKey(keyID, dk)
	ts := httptest.NewServer(metaServer)

	// User
	userID := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := metadata.User{ID: userID, SignKey: usk.Public(), EncKey: udk.EncapsulationKey().Bytes()}
	metadata.CreateUser(t, metaNode, user)

	// Data Node Setup
	dataDir := t.TempDir()
	dataSt := storage.New(dataDir, mk)
	dataStore, _ := data.NewDiskStore(dataSt)

	metaSignPK, err := metaNode.FSM.GetClusterSignPublicKey()
	if err != nil {
		t.Fatalf("failed to fetch cluster sign pk: %v", err)
	}
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	dataTS := httptest.NewServer(dataServer)

	// Register real data node
	nodeInfo := metadata.Node{ID: "n1", Address: dataTS.URL, Status: metadata.NodeStatusActive}
	nb, _ := json.Marshal(nodeInfo)
	if err := metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Raft apply RegisterNode failed: %v", err)
	}

	c := NewClient(ts.URL).WithIdentity(userID, udk).WithSignKey(usk).WithServerKey(ek)
	c.Login(context.Background())
	if _, err := c.EnsureRoot(context.Background()); err != nil {
		t.Fatalf("Failed to ensure root: %v", err)
	}

	return c, metaNode, metaServer, ts
}

func createExtraClient(t *testing.T, ts *httptest.Server, metaNode *metadata.RaftNode, original *Client) *Client {
	ctx := context.Background()

	// Use same identity but it will get a new session on Login
	c := NewClient(ts.URL).WithIdentity(original.userID, original.decKey).WithSignKey(original.signKey).WithServerKey(original.serverKey)
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Extra client login failed: %v", err)
	}
	return c
}
