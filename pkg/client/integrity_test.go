// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
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
	nodeKey, _ := crypto.GenerateIdentityKey()
	nodeID := "node1"

	raftNode, err := metadata.NewRaftNode(nodeID, "127.0.0.1:0", "", tmpDir, st, nodeKey)
	if err != nil {
		t.Fatalf("NewRaftNode failed: %v", err)
	}
	defer raftNode.Shutdown()

	cfg := raft.Configuration{
		Servers: []raft.Server{{ID: raft.ServerID(nodeID), Address: raftNode.Transport.LocalAddr()}},
	}
	raftNode.Raft.BootstrapCluster(cfg)
	waitLeader(t, raftNode.Raft)
	ek := bootstrapCluster(t, raftNode)

	// Phase 31: Initialize Cluster Secret (required for Group creation)
	clusterSecret := make([]byte, 32)
	crypto.NewHash().Write([]byte("testsecret"))
	raftNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdInitSecret, Data: clusterSecret}.Marshal(), 5*time.Second)

	serverSignKey, _ := crypto.GenerateIdentityKey()
	raftSecret := "supersecret"
	server := metadata.NewServer(nodeID, raftNode.Raft, raftNode.FSM, "", serverSignKey, raftSecret, nil, 0)
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
	raftNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdPromoteAdmin, Data: []byte(adminID)}.Marshal(), 5*time.Second)

	// 2.2 User B
	userID := "user-b"
	dkB, _ := crypto.GenerateEncryptionKey()
	skB, _ := crypto.GenerateIdentityKey()
	uB := metadata.User{ID: userID, SignKey: skB.Public(), EncKey: dkB.EncapsulationKey().Bytes()}
	createUser(t, raftNode, uB)

	time.Sleep(1 * time.Second) // Allow FSM to catch up

	// 3. Client Operations
	// 3.1 User B creates a file
	clientB := NewClient(ts.URL).WithIdentity(userID, dkB).WithSignKey(skB).WithServerKey(ek)
	if err := clientB.Login(); err != nil {
		t.Fatalf("User B login failed: %v", err)
	}

	ctx := context.Background()
	if err := clientB.EnsureRoot(); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	filePath := "/secret.txt"
	content := []byte("top secret data")
	if err := clientB.CreateFile(filePath, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	// 4. Verify Signing
	inode, _, err := clientB.ResolvePath(filePath)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	if inode.SignerID != userID {
		t.Errorf("Expected SignerID %s, got %s", userID, inode.SignerID)
	}
	if len(inode.UserSig) == 0 {
		t.Error("Missing UserSig on inode")
	}
	// Version 2 because: createInode(1) -> updateInodeContent(2)
	if inode.Version != 2 {
		t.Errorf("Expected version 2, got %d", inode.Version)
	}

	// 5. Admin Operations (Client-side Signing)
	clientA := NewClient(ts.URL).WithIdentity(adminID, dkA).WithSignKey(skA).WithServerKey(ek).WithAdmin(true)
	if err := clientA.Login(); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}

	// Admin changes ownership to User B (re-signing by Admin)
	chownReq := metadata.AdminChownRequest{OwnerID: &userID}
	if err := clientA.AdminChown(ctx, inode.ID, chownReq); err != nil {
		t.Fatalf("AdminChown failed: %v", err)
	}

	inode2, err := clientA.GetInode(ctx, inode.ID)
	if err != nil {
		t.Fatalf("GetInode failed: %v", err)
	}
	if inode2.OwnerID != userID {
		t.Errorf("Expected owner %s, got %s", userID, inode2.OwnerID)
	}
	if inode2.SignerID != adminID {
		t.Errorf("Expected Admin to be the signer after chown, got %s", inode2.SignerID)
	}

	if err := clientA.VerifyInode(inode2); err != nil {
		t.Errorf("Admin-signed inode failed verification: %v", err)
	}

	// 6. ADVERSARIAL: Evil Server Tampering
	// Manually modify the size in the DB without updating signature
	err = raftNode.FSM.DB().Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(inode2.ID))
		var i metadata.Inode
		json.Unmarshal(v, &i)
		i.Size = 99999 // TAMPERED
		data, _ := json.Marshal(i)
		return b.Put([]byte(inode2.ID), data)
	})
	if err != nil {
		t.Fatalf("DB tamper failed: %v", err)
	}

	_, err = clientA.GetInode(ctx, inode2.ID)
	if err == nil {
		t.Error("Expected error when fetching tampered inode, but got nil")
	} else {
		t.Logf("Caught expected tampering error: %v", err)
	}

	// 7. Group Signing & Member Mutation
	// 7.1 Create Group
	group, err := clientA.CreateGroup("test-group")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	if err := clientA.AddUserToGroup(group.ID, userID, "User B (Test)", nil); err != nil {
		t.Fatalf("AddUserToGroup failed: %v", err)
	}

	// Phase 31: User B must re-login to pick up new group membership in session
	if err := clientB.Login(); err != nil {
		t.Fatalf("User B re-login failed: %v", err)
	}

	// 7.2 Admin creates a file in the group
	groupPath := "/group-shared"
	if err := clientA.Mkdir(groupPath); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	if err := clientA.SetAttr(groupPath, metadata.SetAttrRequest{GroupID: &group.ID}); err != nil {
		t.Fatalf("Chgrp failed: %v", err)
	}
	mode := uint32(0770)
	if err := clientA.SetAttr(groupPath, metadata.SetAttrRequest{Mode: &mode}); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	groupFile := groupPath + "/shared.txt"
	if err := clientA.CreateFile(groupFile, bytes.NewReader([]byte("initial")), 7); err != nil {
		t.Fatalf("Create group file failed: %v", err)
	}
	// Default CreateFile is 0600, member needs 0660
	modeShared := uint32(0660)
	if err := clientA.SetAttr(groupFile, metadata.SetAttrRequest{Mode: &modeShared}); err != nil {
		t.Fatalf("Chmod shared file failed: %v", err)
	}

	// 7.3 User B (Member) modifies the group file
	if err := clientB.CreateFile(groupFile, bytes.NewReader([]byte("member updated")), 14); err != nil {
		t.Fatalf("Member update failed: %v", err)
	}

	// 7.4 Verify Member's signature and Group signature
	inodeG, _, err := clientA.ResolvePath(groupFile)
	if err != nil {
		t.Fatalf("Resolve group file failed: %v", err)
	}
	if inodeG.SignerID != userID {
		t.Errorf("Expected member %s to be signer, got %s", userID, inodeG.SignerID)
	}
	if len(inodeG.GroupSig) == 0 {
		t.Error("Missing GroupSig on shared file")
	}
	if err := clientA.VerifyInode(inodeG); err != nil {
		t.Errorf("Group file verification failed: %v", err)
	}

	// 8. ADVERSARIAL: Rollback Detection
	// Get current state
	currentVersion := inodeG.Version
	err = raftNode.FSM.DB().Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(inodeG.ID))
		var i metadata.Inode
		json.Unmarshal(v, &i)
		i.Version = currentVersion - 1 // ROLLBACK
		data, _ := json.Marshal(i)
		return b.Put([]byte(inodeG.ID), data)
	})
	if err != nil {
		t.Fatalf("DB rollback failed: %v", err)
	}

	_, err = clientA.GetInode(ctx, inodeG.ID)
	if err == nil {
		t.Error("Expected error when fetching rolled-back inode, but got nil")
	} else {
		t.Logf("Caught expected rollback error: %v", err)
	}
}
