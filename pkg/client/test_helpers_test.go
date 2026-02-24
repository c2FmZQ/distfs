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
	
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key")
	metaNode, _ := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	
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
	key := metadata.ClusterKey{ID: "key-1", EncKey: ek.Bytes(), DecKey: dk.Bytes(), CreatedAt: time.Now().Unix()}
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
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
	ts := httptest.NewServer(metaServer)

	// User
	userID := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := metadata.User{ID: userID, SignKey: usk.Public(), EncKey: udk.EncapsulationKey().Bytes()}
	ub, _ := json.Marshal(user)
	if err := metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdCreateUser, Data: ub}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Raft apply CreateUser failed: %v", err)
	}

	// Data Node Setup
	dataDir := t.TempDir()
	dataSt := storage.New(dataDir, mk)
	dataStore, _ := data.NewDiskStore(dataSt)
	
	metaSignPK, _ := metaNode.FSM.GetClusterSignPublicKey()
	dataServer := data.NewServer(dataStore, metaSignPK, nil, data.NoopValidator{})
	dataTS := httptest.NewServer(dataServer)

	// Register real data node
	nodeInfo := metadata.Node{ID: "n1", Address: dataTS.URL, Status: metadata.NodeStatusActive}
	nb, _ := json.Marshal(nodeInfo)
	if err := metaNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Raft apply RegisterNode failed: %v", err)
	}

	c := NewClient(ts.URL).WithIdentity(userID, udk).WithSignKey(usk).WithServerKey(ek)
	c.Login(context.Background())

	return c, metaNode, metaServer, ts
}
