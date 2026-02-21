// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestClientSessionManagement(t *testing.T) {
	// 1. Setup Server
	metaDir := t.TempDir()
	metaSt, _ := createTestStorage(t, metaDir)
	nodeKey, _ := crypto.GenerateIdentityKey()
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeader(t, metaNode.Raft)

	serverEK, _ := bootstrapCluster(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	// 2. Setup User
	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      "session-user",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUser(t, metaNode, user)

	// 3. Client
	c := NewClient(tsMeta.URL) // dataAddr not needed for meta test
	c = c.WithIdentity(user.ID, dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	// 4. Trigger first request (should trigger Login)
	_, err = c.GetUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}

	c.sessionMu.RLock()
	token1 := c.sessionToken
	c.sessionMu.RUnlock()

	if token1 == "" {
		t.Fatal("session token not established")
	}

	// 5. Trigger second request (should reuse token)
	_, err = c.GetUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}

	c.sessionMu.RLock()
	token2 := c.sessionToken
	c.sessionMu.RUnlock()

	if token1 != token2 {
		t.Fatal("session token changed unnecessarily")
	}

	// 6. Force expiry and check refresh
	c.sessionMu.Lock()
	c.sessionExpiry = time.Now().Add(-1 * time.Minute)
	c.sessionMu.Unlock()

	_, err = c.GetUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("Third request failed: %v", err)
	}

	c.sessionMu.RLock()
	token3 := c.sessionToken
	c.sessionMu.RUnlock()

	if token1 == token3 {
		t.Fatal("session token did not refresh after expiry")
	}

	if token3 == "" {
		t.Fatal("session token lost after refresh")
	}
}
