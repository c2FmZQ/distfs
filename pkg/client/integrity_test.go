//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
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
	metadata.WaitLeader(t, raftNode.Raft)
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
	adminID := raftNode.FSM.ComputeUserID("alice")
	dkA, _ := crypto.GenerateEncryptionKey()
	skA, _ := crypto.GenerateIdentityKey()

	// Provision foundations (Buckets, Alice, Groups) - SERVER SIDE
	metadata.BootstrapBackbone(t, raftNode, adminID, dkA, skA)

	// Register a data node so AnchorUserInRegistry (which writes a file) has somewhere to put it
	dataDir := t.TempDir()
	dataSt, _ := createTestStorage(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)

	csk, _ := raftNode.FSM.GetClusterSignPublicKey()
	dataServer := data.NewServer(dataStore, csk, raftNode.FSM, data.NoopValidator{}, true, true)
	dataTS := httptest.NewServer(dataServer)
	defer dataTS.Close()

	registerNode(t, ts.URL, raftSecret, metadata.Node{
		ID:      "n1",
		Address: dataTS.URL,
		Status:  metadata.NodeStatusActive,
	})

	// 3. Client Operations
	// 3.1 Admin initializes Root & Registry Backbone - CLIENT SIDE
	clientA := NewClient(ts.URL).withIdentity(adminID, dkA).withSignKey(skA).withServerKey(ek).WithAdmin(true)
	if err := clientA.Login(t.Context()); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}
	// This will now succeed because BootstrapBackbone didn't create the root!
	if err := clientA.BootstrapFileSystem(t.Context()); err != nil {
		t.Fatalf("BootstrapFileSystem failed: %v", err)
	}

	// 2.2 User B
	userID := raftNode.FSM.ComputeUserID("user-b")
	dkB, _ := crypto.GenerateEncryptionKey()
	skB, _ := crypto.GenerateIdentityKey()
	uB := metadata.User{ID: userID, SignKey: skB.Public(), EncKey: dkB.EncapsulationKey().Bytes()}
	createUser(t, raftNode, uB, skB, adminID, skA)
	clientA.AnchorUserInRegistry(t.Context(), "user-b", uB.ID, adminID)

	// Fetch actual users group ID
	uinfo, _ := clientA.Stat(t.Context(), "/users")
	usersGID := uinfo.Sys().(*InodeInfo).GroupID
	clientA.AddUserToGroup(t.Context(), usersGID, userID, "User B", nil)

	time.Sleep(1 * time.Second) // Allow FSM to catch up

	// 3.2 User B login
	clientB := NewClient(ts.URL).withIdentity(userID, dkB).withSignKey(skB).withServerKey(ek)
	if err := clientB.Login(t.Context()); err != nil {
		t.Fatalf("User B login failed: %v", err)
	}

	// 3.3 Create a system group for root managers and add User B
	rootGroup, err := clientA.createGroup(t.Context(), "root-managers", true)
	if err != nil {
		t.Fatalf("Create root group failed: %v", err)
	}
	clientA.AddUserToGroup(t.Context(), rootGroup.ID, userID, "Manager B", nil)

	// 3.4 Grant root traversal access to the group (READ ONLY, as root must not be group-writable)
	rootACL := ACL{
		Groups: map[string]uint32{
			rootGroup.ID: 0005, // r-x
		},
	}
	if err := clientA.Setfacl(t.Context(), "/", rootACL); err != nil {
		t.Fatalf("Setfacl root failed: %v", err)
	}

	// 4. Verify Integrity (Alice creates a directory for User B)
	err = clientA.MkdirExtended(t.Context(), "/test-dir", 0755, MkdirOptions{OwnerID: userID})
	if err != nil {
		t.Fatalf("Alice failed to Mkdir in root: %v", err)
	}

	// User B should be able to create something inside /test-dir (since they own it)
	err = clientB.Mkdir(t.Context(), "/test-dir/child", 0755)
	if err != nil {
		t.Fatalf("User B failed to Mkdir in delegated dir: %v", err)
	}

	// 5. Tamper with the inode signature in FSM (User B's signature instead of Admin's)
	raftNode.FSM.DB().Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(metadata.RootID))
		var inode metadata.Inode
		json.Unmarshal(v, &inode)

		// Change something and re-sign with User B's key
		inode.Mode = 0755 // Keep same mode to avoid FSM check, but change signature
		inode.SignerID = userID
		inode.UserSig = skB.Sign(inode.ManifestHash())

		vb, _ := json.Marshal(inode)
		return b.Put([]byte(metadata.RootID), vb)
	})

	// 6. Verify that Client A detects the tampering
	clientA.ClearNodeCache()
	_, _, err = clientA.resolvePath(t.Context(), "/")
	if err == nil {
		t.Errorf("Expected Client A to detect tampered root inode signature")
	}
}
