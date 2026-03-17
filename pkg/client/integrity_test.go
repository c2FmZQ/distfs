//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestManifestIntegrity(t *testing.T) {
	// 1. Setup Node & Server
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(st, "node.key", nil)
	nodeID := "node1"

	raftNode, err := metadata.NewRaftNode(nodeID, "127.0.0.1:0", "", tmpDir, st, nodeKey, []byte("test-cluster-secret"))
	if err != nil {
		t.Fatalf("NewRaftNode failed: %v", err)
	}
	defer raftNode.Shutdown()

	cfg := raft.Configuration{
		Servers: []raft.Server{{ID: raft.ServerID(nodeID), Address: raftNode.Transport.LocalAddr()}},
	}
	raftNode.Raft.BootstrapCluster(cfg)
	waitLeader(t, raftNode.Raft)
	ek, epochDK, _ := bootstrapCluster(t, raftNode)

	serverSignKey, _ := crypto.GenerateIdentityKey()
	raftSecret := "supersecret"
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	server := metadata.NewServer(nodeID, raftNode.Raft, raftNode.FSM, "", serverSignKey, raftSecret, nil, 0, metadata.NewNodeVault(st), nodeDecKey, true)
	server.RegisterEpochKey("key-1", epochDK)
	ts := httptest.NewServer(server)
	defer ts.Close()

	// 2. Setup Identities
	// 2.1 Admin
	adminID := "admin-user"
	dkA, _ := crypto.GenerateEncryptionKey()
	skA, _ := crypto.GenerateIdentityKey()
	uA := metadata.User{ID: adminID, SignKey: skA.Public(), EncKey: dkA.EncapsulationKey().Bytes()}
	createUser(t, raftNode, uA)
	// Promote to Admin
	uAIDBytes, _ := json.Marshal(adminID)
	raftNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdPromoteAdmin, Data: uAIDBytes}.Marshal(), 5*time.Second)

	// 2.2 User B
	userID := "user-b"
	dkB, _ := crypto.GenerateEncryptionKey()
	skB, _ := crypto.GenerateIdentityKey()
	uB := metadata.User{ID: userID, SignKey: skB.Public(), EncKey: dkB.EncapsulationKey().Bytes()}
	createUser(t, raftNode, uB)

	time.Sleep(1 * time.Second) // Allow FSM to catch up

	// 3. Client Operations
	// 3.1 User B login
	clientB := NewClient(ts.URL).WithIdentity(userID, dkB).WithSignKey(skB).WithServerKey(ek)
	if err := clientB.Login(t.Context()); err != nil {
		t.Fatalf("User B login failed: %v", err)
	}

	// 3.2 Admin initializes Root
	clientA := NewClient(ts.URL).WithIdentity(adminID, dkA).WithSignKey(skA).WithServerKey(ek).WithAdmin(true)
	if err := clientA.Login(t.Context()); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}
	if _, err := clientA.EnsureRoot(t.Context()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// 3.3 Create a system group for root access and add User B
	rootGroup, err := clientA.CreateGroup(t.Context(), "root-managers", true)
	if err != nil {
		t.Fatalf("Create root group failed: %v", err)
	}
	if err := clientA.AddUserToGroup(t.Context(), rootGroup.ID, userID, "test", nil); err != nil {
		t.Fatalf("Add User B to root group failed: %v", err)
	}

	// 3.4 Grant Group Write access to Root
	if err := clientA.SetAttr(t.Context(), "/", metadata.SetAttrRequest{
		Mode:    ptr(uint32(0770)),
		GroupID: ptr(rootGroup.ID),
		OwnerID: ptr(adminID),
	}); err != nil {
		t.Fatalf("Chgrp root failed: %v", err)
	}

	filePath := "/secret.txt"
	content := []byte("top secret data")
	if err := clientB.CreateFile(t.Context(), filePath, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 4. Verify Signing
	inode, _, err := clientB.ResolvePath(t.Context(), filePath)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	if inode.GetSignerID() != userID {
		t.Errorf("Expected SignerID %s, got %s", userID, inode.GetSignerID())
	}
	if len(inode.UserSig) == 0 {
		t.Error("Missing UserSig on inode")
	}
	// Version 1 because of atomic creation in Phase 43
	if inode.Version != 1 {
		t.Errorf("Expected version 1, got %d", inode.Version)
	}

	// 7. Group Signing & Member Mutation
	// 7.1 Create Group
	group, err := clientA.CreateGroup(t.Context(), "test-group", false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	if err := clientA.AddUserToGroup(t.Context(), group.ID, userID, "User B (Test)", nil); err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	// Phase 31: User B must re-login to pick up new group membership in session
	if err := clientB.Login(t.Context()); err != nil {
		t.Fatalf("User B re-login failed: %v", err)
	}

	// 7.2 Admin creates a file in the group
	groupPath := "/group-shared"
	if err := clientA.Mkdir(t.Context(), groupPath, 0755); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	if err := clientA.SetAttr(t.Context(), groupPath, metadata.SetAttrRequest{GroupID: &group.ID}); err != nil {
		t.Fatalf("Chgrp failed: %v", err)
	}
	mode := uint32(0770)
	if err := clientA.SetAttr(t.Context(), groupPath, metadata.SetAttrRequest{Mode: &mode}); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	groupFile := groupPath + "/shared.txt"
	if err := clientA.CreateFile(t.Context(), groupFile, bytes.NewReader([]byte("initial")), 7); err != nil {
		t.Fatalf("Create group file failed: %v", err)
	}
	// Default CreateFile is 0600, member needs 0660
	modeShared := uint32(0660)
	if err := clientA.SetAttr(t.Context(), groupFile, metadata.SetAttrRequest{Mode: &modeShared}); err != nil {
		t.Fatalf("Chmod shared file failed: %v", err)
	}

	// 7.3 User B (Member) modifies the group file
	clientB.ClearCache()
	if err := clientB.CreateFile(t.Context(), groupFile, bytes.NewReader([]byte("member updated")), 14); err != nil {
		t.Fatalf("Member update failed: %v", err)
	}

	// 7.4 Verify Member's signature and Group signature
	inodeG, _, err := clientA.ResolvePath(t.Context(), groupFile)
	if err != nil {
		t.Fatalf("Resolve group file failed: %v", err)
	}
	if inodeG.GetSignerID() != userID {
		t.Errorf("Expected member %s to be signer, got %s", userID, inodeG.GetSignerID())
	}
	if len(inodeG.GroupSig) == 0 {
		t.Error("Missing GroupSig on shared file")
	}
	if err := clientA.VerifyInode(t.Context(), inodeG); err != nil {
		t.Errorf("Group file verification failed: %v", err)
	}

	// 8. ADVERSARIAL: Rollback Detection
	// Get current state
	currentVersion := inodeG.Version
	err = raftNode.FSM.DB().Update(func(tx *bolt.Tx) error {
		v, err := raftNode.FSM.Get(tx, []byte("inodes"), []byte(inodeG.ID))
		if err != nil {
			return err
		}
		var i metadata.Inode
		json.Unmarshal(v, &i)
		i.Version = currentVersion - 1 // ROLLBACK
		data, _ := json.Marshal(i)
		return raftNode.FSM.Put(tx, []byte("inodes"), []byte(inodeG.ID), data)
	})
	if err != nil {
		t.Fatalf("DB rollback failed: %v", err)
	}

	_, err = clientA.GetInode(t.Context(), inodeG.ID)
	if err == nil {
		t.Error("Expected error when fetching rolled-back inode, but got nil")
	} else {
		t.Logf("Caught expected rollback error: %v", err)
	}
}

func TestGroupIntegrity(t *testing.T) {
	// 1. Setup Node & Server
	tmpDir := t.TempDir()
	st, _ := createTestStorage(t, tmpDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(st, "node.key", nil)
	nodeID := "node1"

	raftNode, err := metadata.NewRaftNode(nodeID, "127.0.0.1:0", "", tmpDir, st, nodeKey, []byte("test-cluster-secret"))
	if err != nil {
		t.Fatalf("NewRaftNode failed: %v", err)
	}
	defer raftNode.Shutdown()

	cfg := raft.Configuration{
		Servers: []raft.Server{{ID: raft.ServerID(nodeID), Address: raftNode.Transport.LocalAddr()}},
	}
	raftNode.Raft.BootstrapCluster(cfg)
	waitLeader(t, raftNode.Raft)
	ek, epochDK, _ := bootstrapCluster(t, raftNode)

	serverSignKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	server := metadata.NewServer(nodeID, raftNode.Raft, raftNode.FSM, "", serverSignKey, "testsecret", nil, 0, metadata.NewNodeVault(st), nodeDecKey, true)
	server.RegisterEpochKey("key-1", epochDK)
	ts := httptest.NewServer(server)
	defer ts.Close()

	// 2. Setup Identity
	userID := "alice"
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	u := metadata.User{ID: userID, SignKey: sk.Public(), EncKey: dk.EncapsulationKey().Bytes()}
	createUser(t, raftNode, u)

	client := NewClient(ts.URL).WithIdentity(userID, dk).WithSignKey(sk).WithServerKey(ek)
	if err := client.Login(t.Context()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 3. Create Group (Verified initial signature)
	group, err := client.CreateGroup(t.Context(), "integrity-group", false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	if group.SignerID != userID {
		t.Errorf("Expected SignerID %s, got %s", userID, group.SignerID)
	}
	if len(group.Signature) == 0 {
		t.Error("Missing Signature on group")
	}

	// 4. Verify Fetching
	fetched, err := client.GetGroup(t.Context(), group.ID)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if fetched.ID != group.ID {
		t.Error("Group ID mismatch")
	}

	// 5. ADVERSARIAL: Evil Server Tampering
	// Manually modify the group owner in the DB without updating signature
	err = raftNode.FSM.DB().Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(group.ID))
		var g metadata.Group
		plain, err := raftNode.FSM.DecryptValue([]byte("inodes"), v)
		if err != nil {
			return err
		}
		json.Unmarshal(plain, &g)
		g.OwnerID = "malicious-user" // TAMPERED metadata
		// We DO NOT update the Signature here.
		data, _ := json.Marshal(g)
		enc, _ := raftNode.FSM.EncryptValue([]byte("inodes"), data)
		return b.Put([]byte(group.ID), enc)
	})
	if err != nil {
		t.Fatalf("DB tamper failed: %v", err)
	}

	_, err = client.GetGroupUnverified(t.Context(), group.ID)
	if err == nil {
		t.Error("Expected error when fetching tampered group, but got nil")
	} else {
		t.Logf("Caught expected group tampering error: %v", err)
	}
}
