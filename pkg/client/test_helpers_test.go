//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"crypto/mlkem"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func setupTestClient(t *testing.T) (*Client, *metadata.RaftNode, *metadata.Server, *httptest.Server, string, *crypto.IdentityKey) {
	tc := metadata.SetupRawCluster(t)

	// 2. Setup Data Node
	dataDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	dataSt := storage.New(dataDir, mk)
	dataStore, _ := data.NewDiskStore(dataSt)

	csk := metadata.GetClusterSignKey(tc.Node.FSM)
	dataServer := data.NewServer(dataStore, csk.Public, tc.Node.FSM, data.NoopValidator{}, true, true)
	dataTS := httptest.NewServer(dataServer)
	t.Cleanup(func() { dataTS.Close() })

	registerNode(t, tc.TS.URL, "testsecret", metadata.Node{
		ID:      "data1",
		Address: dataTS.URL,
		Status:  metadata.NodeStatusActive,
	})

	// 3. Client
	svKey, _ := crypto.UnmarshalEncapsulationKey(tc.EpochEK)
	c := NewClient(tc.TS.URL).
		withIdentity(tc.AdminID, tc.AdminDK).
		withSignKey(tc.AdminSK).
		WithAdmin(true).
		withServerKey(svKey).
		WithRegistry("/registry")

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("setupTestClient login failed: %v", err)
	}

	// 4. Secure Backbone Initialization (Phase 69 style)
	if err := c.BootstrapFileSystem(context.Background()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	return c, tc.Node, tc.Server, tc.TS, tc.AdminID, tc.AdminSK
}

func provisionUser(t *testing.T, ts *httptest.Server, metaNode *metadata.RaftNode, adminClient *Client, adminID string, adminSK *crypto.IdentityKey, userID string) (*Client, *mlkem.DecapsulationKey768, *crypto.IdentityKey) {
	ctx := t.Context()
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      userID,
		SignKey: sk.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	metadata.CreateUser(t, metaNode, user, sk, adminID, adminSK)

	// Fetch actual users group ID
	info, err := adminClient.Stat(ctx, "/users")
	if err != nil {
		t.Fatalf("Stat /users failed: %v", err)
	}
	usersGID := info.Sys().(*InodeInfo).GroupID

	// Create ContactInfo
	cTemp := NewClient(ts.URL).withIdentity(userID, dk).withSignKey(sk)
	cTemp.sessionToken = "fake"
	contactStr, _ := cTemp.GenerateContactString()
	contact, _ := adminClient.ParseContactString(contactStr)

	if err := adminClient.AddUserToGroup(ctx, usersGID, userID, "test", contact); err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}
	if err := adminClient.AnchorUserInRegistry(ctx, userID, user.ID, adminID); err != nil {
		t.Fatalf("AnchorUserInRegistry failed: %v", err)
	}

	c := NewClient(ts.URL).
		withIdentity(userID, dk).
		withSignKey(sk).
		withServerKey(adminClient.serverKey).
		WithRegistry("/registry")

	if err := c.Login(ctx); err != nil {
		t.Fatalf("provisionUser: login failed for %s: %v", userID, err)
	}

	return c, dk, sk
}

func createExtraClient(t *testing.T, ts *httptest.Server, metaNode *metadata.RaftNode, original *Client) *Client {
	ctx := context.Background()

	// Use same identity but it will get a new session on Login
	c := NewClient(ts.URL).withIdentity(original.userID, original.decKey).withSignKey(original.signKey).withServerKey(original.serverKey)
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Extra client login failed: %v", err)
	}
	return c
}

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
		t.Fatalf("failed to register data node: %v", err)
	}

	return ts, ds
}
