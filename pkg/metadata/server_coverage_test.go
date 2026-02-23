// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestServer_SetAttr(t *testing.T) {
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "alice"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := User{
		ID:      u1,
		SignKey: usk.Public(),
		EncKey:  udk.EncapsulationKey().Bytes(),
	}
	CreateUser(t, node, user)
	token := LoginSessionForTest(t, ts, u1, usk)

	// Create an inode
	inodeID := "file1"
	inode := Inode{
		ID:      inodeID,
		OwnerID: u1,
		Type:    FileType,
		Mode:    0644,
	}
	inode.SignInodeForTest(u1, usk)
	ib, _ := json.Marshal(inode)
	server.ApplyRaftCommandInternal(CmdCreateInode, ib)

	// Update attributes via handleSetAttr
	setAttrReq := SetAttrRequest{
		InodeID: inodeID,
		Mode:    ptr(uint32(0755)),
	}
	sab, _ := json.Marshal(setAttrReq)
	sealed := SealTestRequest(t, u1, usk, ek, sab)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/setattr", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleSetAttr failed: %d", resp.StatusCode)
	}

	// Verify change in FSM
	var updatedInode Inode
	err = server.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := server.fsm.Get(tx, []byte("inodes"), []byte(inodeID))
		if err != nil {
			return err
		}
		return json.Unmarshal(plain, &updatedInode)
	})
	if err != nil {
		t.Fatal(err)
	}
	if updatedInode.Mode != 0755 {
		t.Errorf("expected mode 0755, got %o", updatedInode.Mode)
	}

	// Test unauthorized (different user)
	u2 := "bob"
	usk2, _ := crypto.GenerateIdentityKey()
	user2 := User{ID: u2, SignKey: usk2.Public()}
	CreateUser(t, node, user2)
	token2 := LoginSessionForTest(t, ts, u2, usk2)

	sealed2 := SealTestRequest(t, u2, usk2, ek, sab)
	req2, _ := http.NewRequest("POST", ts.URL+"/v1/meta/setattr", bytes.NewReader(sealed2))
	req2.Header.Set("Session-Token", token2)
	req2.Header.Set("X-DistFS-Sealed", "true")
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unauthorized SetAttr, got %d", resp2.StatusCode)
	}
}

func TestServer_AddChild(t *testing.T) {
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "alice"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := User{
		ID:      u1,
		SignKey: usk.Public(),
		EncKey:  udk.EncapsulationKey().Bytes(),
	}
	CreateUser(t, node, user)
	token := LoginSessionForTest(t, ts, u1, usk)

	// Create directory
	dirID := "dir1"
	dir := Inode{
		ID:      dirID,
		OwnerID: u1,
		Type:    DirType,
		Mode:    0755,
	}
	dir.SignInodeForTest(u1, usk)
	db, _ := json.Marshal(dir)
	server.ApplyRaftCommandInternal(CmdCreateInode, db)

	// Add child via handleAddChild
	update := ChildUpdate{
		Name:    "file1",
		ChildID: "f1",
	}
	ub, _ := json.Marshal(update)
	sealed := SealTestRequest(t, u1, usk, ek, ub)

	req, _ := http.NewRequest("PUT", ts.URL+"/v1/meta/directory/dir1/entry", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAddChild failed: %d", resp.StatusCode)
	}

	// Verify in FSM
	var updatedDir Inode
	server.fsm.db.View(func(tx *bolt.Tx) error {
		plain, _ := server.fsm.Get(tx, []byte("inodes"), []byte(dirID))
		return json.Unmarshal(plain, &updatedDir)
	})
	if updatedDir.Children["file1"] != "f1" {
		t.Errorf("expected entry file1 -> f1, got %v", updatedDir.Children)
	}
}

func TestServer_HealthAndStatus(t *testing.T) {
	node, ts, usk, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// Health
	req, _ := http.NewRequest("GET", ts.URL+"/v1/health", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health check failed: %d", resp.StatusCode)
	}

	// Cluster Status (under Admin)
	u1 := "admin"
	user := User{ID: u1, SignKey: usk.Public()}
	CreateUser(t, node, user)
	server.ApplyRaftCommandInternal(CmdPromoteAdmin, []byte(u1))
	token := LoginSessionForTest(t, ts, u1, usk)

	sealed := SealTestRequest(t, u1, usk, ek, nil)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/admin/status", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cluster status failed: %d", resp.StatusCode)
	}
}

func TestServer_Forwarding(t *testing.T) {
	// Node 1 (Leader)
	n1, ts1, _, _, s1 := SetupCluster(t)
	defer n1.Shutdown()
	defer ts1.Close()

	// Node 2 (Follower)
	tmpDir2 := t.TempDir()
	st2, _ := createTestStorage(t, tmpDir2)
	nodeKey2, _ := LoadOrGenerateNodeKey(st2, "node.key")
	nodeID2 := NodeIDFromKey(nodeKey2)
	n2, _ := NewRaftNode(nodeID2, "127.0.0.1:0", "", tmpDir2, st2, nodeKey2)
	defer n2.Shutdown()

	// Add n2 to n1 cluster
	f := n1.Raft.AddVoter(raft.ServerID(nodeID2), n2.Transport.LocalAddr(), 0, 0)
	if err := f.Error(); err != nil {
		t.Fatalf("failed to add voter: %v", err)
	}

	// Wait for n2 to see leader
	var leader raft.ServerAddress
	for i := 0; i < 50; i++ {
		leader, _ = n2.Raft.LeaderWithID()
		if leader != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if leader == "" {
		t.Fatal("n2 never saw leader")
	}
	t.Logf("n2 saw leader: %v", leader)
	t.Logf("n1 NodeID: %s, RaftAddr: %s", n1.NodeID, n1.Transport.LocalAddr())

	signKey2, _ := crypto.GenerateIdentityKey()
	// Set the API URL of s1 so s2 knows where to forward
	s1.apiURL = ts1.URL
	
	// Register Node 1 in FSM via Raft so Node 2 gets it
	node1 := Node{
		ID:          n1.NodeID,
		Address:     ts1.URL,
		RaftAddress: string(n1.Transport.LocalAddr()),
		Status:      NodeStatusActive,
	}
	n1b, _ := json.Marshal(node1)
	s1.ApplyRaftCommandInternal(CmdRegisterNode, n1b)

	s2 := NewServer(nodeID2, n2.Raft, n2.FSM, "", signKey2, "testsecret", nil, 0)
	ts2 := httptest.NewServer(s2)
	defer ts2.Close()

	// Wait for replication
	time.Sleep(500 * time.Millisecond)

	// Make request to s2 (Follower)
	// /v1/health should be forwarded? 
	// Actually, health is not forwarded in ServeHTTP because it's before forwardIfNecessary.
	// But /v1/node is after forwardIfNecessary.
	req, _ := http.NewRequest("GET", ts2.URL+"/v1/node", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// It should be forwarded to s1 and return OK
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200 OK via forwarding, got %d: %s", resp.StatusCode, string(body))
	}
}
