//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func SetupTestClient(t *testing.T) (*client.Client, *metadata.RaftNode, *metadata.Server, *httptest.Server, string, *crypto.IdentityKey) {
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

	RegisterNode(t, tc.TS.URL, "testsecret", metadata.Node{
		ID:      "data1",
		Address: dataTS.URL,
		Status:  metadata.NodeStatusActive,
	})

	// 3. Client
	c, err := client.NewClient(tc.TS.URL).
		WithIdentityBytes(tc.AdminID, tc.AdminDK.Bytes())
	if err != nil {
		t.Fatalf("WithIdentityBytes failed: %v", err)
	}
	c, err = c.WithSignKeyBytes(tc.AdminSK.MarshalPrivate())
	if err != nil {
		t.Fatalf("WithSignKeyBytes failed: %v", err)
	}
	c, err = c.WithServerKeyBytes(tc.EpochEK)
	if err != nil {
		t.Fatalf("WithServerKeyBytes failed: %v", err)
	}
	c = c.WithAdmin(true).
		WithRegistry("/registry")

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("SetupTestClient login failed: %v", err)
	}

	// 4. Secure Backbone Initialization (Phase 69 style)
	if err := c.BootstrapFileSystem(context.Background()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	return c, tc.Node, tc.Server, tc.TS, tc.AdminID, tc.AdminSK
}

func RegisterNode(t *testing.T, serverURL string, secret string, node metadata.Node) {
	b, _ := json.Marshal(node)
	req, _ := http.NewRequest("POST", serverURL+"/v1/node", bytes.NewReader(b))
	req.Header.Set("X-Raft-Secret", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to register node: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("failed to register node: status %d", resp.StatusCode)
	}
}
