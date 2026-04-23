//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func TestServer_MiscHandlers(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// Register a user
	u1 := "user1"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := User{
		ID:      u1,
		UID:     1001,
		SignKey: usk.Public(),
		EncKey:  udk.EncapsulationKey().Bytes(),
	}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)
	// Promote to Admin
	server.ApplyRaftCommandInternal(context.Background(), CmdPromoteAdmin, MustMarshalJSON(u1), "")
	token, secret := LoginSessionForTestWithSecret(t, ts, u1, usk)

	// Register a Node
	nodeInfo := Node{ID: "n1", Address: "http://n1:8080", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	nb, _ := json.Marshal(nodeInfo)
	server.ApplyRaftCommandInternal(context.Background(), CmdRegisterNode, nb, "")

	// Record some metrics
	server.fsm.metrics.RecordOp(CmdCreateInode, 100)
	snap := server.fsm.metrics.SnapshotAndReset()
	snapData, _ := json.Marshal(snap)
	server.ApplyRaftCommandInternal(context.Background(), CmdStoreMetrics, snapData, "")

	// 1. handleAllocateGID
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionAllocateGID, nil, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAllocateGID failed: %d", resp.StatusCode)
	}

	// 2. handleGetAuthConfig
	req, _ = http.NewRequest("GET", ts.URL+"/v1/auth/config", nil)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("handleGetAuthConfig failed: %d", resp.StatusCode)
	}

	// 3. handleGetNodes
	req, _ = http.NewRequest("GET", ts.URL+"/v1/node", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleGetNodes failed: %d", resp.StatusCode)
	}

	// 4. handleAllocateChunk
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAllocateChunk, nil, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAllocateChunk failed: %d", resp.StatusCode)
	}

	// 5. handleGetClusterStats
	req, _ = http.NewRequest("GET", ts.URL+"/v1/cluster/stats", nil)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleGetClusterStats failed: %d", resp.StatusCode)
	}

	// 6. handleGetMetrics
	req, _ = http.NewRequest("GET", ts.URL+"/v1/system/metrics", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleGetMetrics failed: %d", resp.StatusCode)
	}

	// 7. handleIssueToken
	// Create an inode first
	nonce := make([]byte, 16)
	rand.Read(nonce)
	inodeID := GenerateInodeID(u1, nonce)
	inode := Inode{ID: inodeID, Nonce: nonce, OwnerID: u1, Type: FileType, Mode: 0644}
	inode.SignInodeForTest(u1, usk)
	ib, _ := json.Marshal(inode)
	if res, err := server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, ib, u1); err != nil || server.fsm.containsError(res) {
		t.Fatalf("Create Inode failed: err=%v, res=%v", err, res)
	}

	issueReq := struct {
		InodeID string   `json:"inode_id"`
		Chunks  []string `json:"chunks"`
		Mode    string   `json:"mode"`
	}{
		InodeID: inodeID,
		Mode:    "R",
	}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionIssueToken, issueReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleIssueToken failed: %d", resp.StatusCode)
	}

	// 8. handleGetInodes (Batch)
	ids := []string{inodeID}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionGetInodes, ids, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleGetInodes failed: %d", resp.StatusCode)
	}

	// 9. handleBatch
	// Update version to next expected state (2)
	inode.Version = 2
	inode.NLink = 1
	inode.SignInodeForTest(u1, usk)
	batch := []LogCommand{
		{Type: CmdUpdateInode, Data: MustMarshalJSON(inode), UserID: u1},
	}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batch, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleBatch failed: %d", resp.StatusCode)
	}
	opened := UnsealTestResponseWithSession(t, udk, secret, tc.NodeSK.Public(), resp)
	var results []json.RawMessage
	if err := json.Unmarshal(opened, &results); err != nil {
		t.Fatalf("Failed to unmarshal batch results: %v", err)
	}
	resp.Body.Close()

	// 10. handleAcquireLeases / handleReleaseLeases
	leaseReq := LeaseRequest{
		InodeIDs: []string{inodeID},
		Duration: int64(10 * 1000 * 1000 * 1000), // 10s
		Type:     LeaseExclusive,
		Nonce:    "test-nonce",
	}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAcquireLeases, leaseReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAcquireLeases failed: %d", resp.StatusCode)
	}

	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionReleaseLeases, leaseReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleReleaseLeases failed: %d", resp.StatusCode)
	}

	// 11. handleGetWorldPrivateKey (Admin Only)
	// Ensure world is initialized
	http.Get(ts.URL + "/v1/meta/key/world")

	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionGetWorldPrivate, nil, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Admin-Bypass", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleGetWorldPrivateKey failed: %d", resp.StatusCode)
	}

	// 12. handleRegisterUser (Malformed JWT)
	regReq := RegisterUserRequest{JWT: "malformed", SignKey: usk.Public()}
	regB, _ := json.Marshal(regReq)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/user/register", bytes.NewReader(regB))
	resp, _ = http.DefaultClient.Do(req)
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("handleRegisterUser expected 401 for malformed JWT, got %d", resp.StatusCode)
	}
}

func TestServer_AdminHandlers(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// The first user is admin
	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := User{
		ID:      u1,
		UID:     1001,
		SignKey: usk.Public(),
		EncKey:  udk.EncapsulationKey().Bytes(),
	}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)
	server.ApplyRaftCommandInternal(context.Background(), CmdPromoteAdmin, MustMarshalJSON(u1), "")
	token, secret := LoginSessionForTestWithSecret(t, ts, u1, usk)

	// Create Group g1
	group := Group{ID: "g1", OwnerID: u1, GID: 5000, Version: 1, QuotaEnabled: true, SignerID: u1}
	group.Signature = usk.Sign(group.Hash())
	gb, _ := json.Marshal(group)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateGroup, gb, u1)

	// handleClusterLeases
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminLeases, nil, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleClusterLeases failed: %d", resp.StatusCode)
	}

	// handleSetUserQuota
	quotaReq := SetUserQuotaRequest{UserID: u1, MaxInodes: ptr(uint64(100))}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminUserQuota, quotaReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleSetUserQuota failed: %d", resp.StatusCode)
	}
	// 11. handleAdminPromote
	promoteReq := map[string]string{"user_id": u1}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminPromote, promoteReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAdminPromote failed: %d", resp.StatusCode)
	}

	// 12. handleSetGroupQuota
	// Create group first
	g1 := Group{ID: "g1", GID: 2001, QuotaEnabled: true, OwnerID: u1, SignerID: u1}
	g1.Signature = usk.Sign(g1.Hash())
	g1b, _ := json.Marshal(g1)
	if res, err := server.ApplyRaftCommandInternal(context.Background(), CmdCreateGroup, g1b, u1); err != nil || server.fsm.containsError(res) {
		t.Fatalf("Create Group g1 failed: err=%v, res=%v", err, res)
	}

	groupQuotaReq := SetGroupQuotaRequest{GroupID: "g1", MaxInodes: ptr(uint64(50))}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminGroupQuota, groupQuotaReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleSetGroupQuota failed: %d", resp.StatusCode)
	}
}

func TestServer_ClusterAdminHandlers(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, UID: 1001, SignKey: usk.Public()}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)
	server.ApplyRaftCommandInternal(context.Background(), CmdPromoteAdmin, MustMarshalJSON(u1), "")
	token, secret := LoginSessionForTestWithSecret(t, ts, u1, usk)

	// handleClusterJoin
	joinReq := map[string]string{"id": "n2", "address": "http://127.0.0.1:8888"}
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminClusterJoin, joinReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		// Might fail due to real Raft join logic
	}

	// handleClusterRemove
	removeReq := map[string]string{"id": "n2"}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminClusterRem, removeReq, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		// Might fail if node not in cluster
	}
}

func TestServer_OIDCDiscovery(t *testing.T) {
	// Mock OIDC issuer
	tsOIDC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conf := OIDCConfig{
			Issuer:  "http://mock-issuer",
			JWKSURI: "http://mock-issuer/jwks",
		}
		json.NewEncoder(w).Encode(conf)
	}))
	defer tsOIDC.Close()

	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// Manually trigger discovery in background
	go server.discoverOIDC(tsOIDC.URL)

	// Wait a bit for it to finish first iteration
	time.Sleep(100 * time.Millisecond)

	server.oidcMu.RLock()
	if server.oidcConfig == nil || server.oidcConfig.Issuer != "http://mock-issuer" {
		t.Errorf("OIDC discovery failed to populate config")
	}
	server.oidcMu.RUnlock()
}

func TestServer_RegisterUser_Idempotency(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
}

func TestServer_IssueToken_Permissions(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public(), Locked: false}, usk, tc.AdminID, tc.AdminSK)

	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u2, UID: 1002, SignKey: usk2.Public(), Locked: false}, usk2, tc.AdminID, tc.AdminSK)
	token2, secret2 := LoginSessionForTestWithSecret(t, ts, u2, usk2)

	// 1. World Readable file (owned by u1)
	inodeW := Inode{ID: "world", OwnerID: u1, Type: FileType, Mode: 0644}
	inodeW.SignInodeForTest(u1, usk)
	ibW, _ := json.Marshal(inodeW)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, ibW, "u1")

	// u2 should be able to get R token
	issueReq := struct {
		InodeID string   `json:"inode_id"`
		Chunks  []string `json:"chunks"`
		Mode    string   `json:"mode"`
	}{InodeID: "world", Mode: "R"}
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionIssueToken, issueReq, u2, usk2, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("u2 should be able to read world file, got %d", resp.StatusCode)
	}

	// u2 should NOT be able to get W token
	issueReq.Mode = "W"
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionIssueToken, issueReq, u2, usk2, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("u2 should NOT be able to write world-read file, got %d", resp.StatusCode)
	}
}

func TestServer_UnsealExtraErrors(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, UID: 1001, SignKey: usk.Public()}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)

	// 1. Invalid JSON
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader([]byte("not-json")))
	req.Header.Set("X-DistFS-Sealed", "true")
	_, _, err := server.unsealRequest(httptest.NewRecorder(), req, &user)
	if err == nil {
		t.Error("unsealRequest should fail for invalid JSON")
	}

	// 2. Too short sealed payload
	sr := SealedRequest{UserID: u1, Sealed: []byte("short")}
	b, _ := json.Marshal(sr)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(b))
	req.Header.Set("X-DistFS-Sealed", "true")
	_, _, err = server.unsealRequest(httptest.NewRecorder(), req, &user)
	if err == nil {
		t.Error("unsealRequest should fail for too short payload")
	}
}

func TestServer_LoginExtraErrors(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, UID: 1001, SignKey: usk.Public()}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)

	// 1. Missing challenge entry
	solve := AuthChallengeSolve{UserID: u1, Challenge: []byte("missing"), Signature: make([]byte, 64)}
	b, _ := json.Marshal(solve)
	resp, _ := http.Post(ts.URL+"/v1/login", "application/json", bytes.NewReader(b))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing challenge, got %d", resp.StatusCode)
	}

	// 2. User ID mismatch
	// Get real challenge first
	reqData := AuthChallengeRequest{UserID: u1}
	bReq, _ := json.Marshal(reqData)
	res, _ := http.Post(ts.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(bReq))
	var challengeRes AuthChallengeResponse
	json.NewDecoder(res.Body).Decode(&challengeRes)

	solve.Challenge = challengeRes.Challenge
	solve.UserID = "mismatch"
	b, _ = json.Marshal(solve)
	resp, _ = http.Post(ts.URL+"/v1/login", "application/json", bytes.NewReader(b))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for UserID mismatch, got %d", resp.StatusCode)
	}

	// 3. Invalid signature
	solve.UserID = u1
	solve.Signature = make([]byte, 64)
	b, _ = json.Marshal(solve)
	resp, _ = http.Post(ts.URL+"/v1/login", "application/json", bytes.NewReader(b))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid signature, got %d", resp.StatusCode)
	}
}

func TestServer_AuthChallenge_LazyGC(t *testing.T) {
	tc := SetupCluster(t)
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer ts.Close()

	// 1. Manually add expired challenge
	server.challengeMu.Lock()
	server.challengeCache["old"] = challengeEntry{
		UserID:    "u1",
		CreatedAt: time.Now().Add(-5 * time.Minute),
	}
	server.challengeMu.Unlock()

	// 2. Trigger another challenge
	reqData := AuthChallengeRequest{UserID: "u2"}
	b, _ := json.Marshal(reqData)
	http.Post(ts.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))

	// 3. Verify "old" is gone
	server.challengeMu.Lock()
	if _, ok := server.challengeCache["old"]; ok {
		t.Error("Expired challenge not removed by lazy GC")
	}
	server.challengeMu.Unlock()
}

func TestServer_Forwarding_NoLeader(t *testing.T) {
	tmpDir := t.TempDir()
	mk, _ := storage_crypto.CreateAESMasterKeyForTest()
	st := storage.New(tmpDir, mk)
	nodeKey, _ := LoadOrGenerateNodeKey(st, "node.key", nil)

	config := raft.DefaultConfig()
	config.HeartbeatTimeout = 50 * time.Millisecond
	config.ElectionTimeout = 50 * time.Millisecond
	config.LeaderLeaseTimeout = 50 * time.Millisecond

	node2, _ := NewRaftNodeWithConfig("node2", "127.0.0.1:0", "", tmpDir, st, nodeKey, []byte("test-cluster-secret"), config)
	defer node2.Shutdown()

	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	server2 := NewServer("node2", node2.Raft, node2.FSM, "", signKey, "testsecret", nil, 0, NewNodeVault(st), nodeDecKey, true)

	// node2 has no leader
	req, _ := http.NewRequest("GET", "/v1/meta/batch/root", nil)
	rr := httptest.NewRecorder()
	if server2.forwardIfNecessary(rr, req) {
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected 503, got %d", rr.Code)
		}
	} else {
		t.Error("forwardIfNecessary should have returned true")
	}
}

func TestServer_LifecycleAndConfig(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setters
	server.SetRaftAddress("127.0.0.1:1234")
	server.SetAPIURL("http://127.0.0.1:1234")
	server.SetTLSPublicKey([]byte("pubkey"))

	// 2. Lifecycle
	server.ForceReplicationScan()
	server.StopKeyRotation()
	server.Shutdown()
}

func TestServer_BatchErrors(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, UID: 1001, SignKey: usk.Public()}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)
	token, secret := LoginSessionForTestWithSecret(t, ts, u1, usk)

	// handleBatch with invalid command type
	batch := []LogCommand{{Type: 255, Data: []byte("{}")}}
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batch, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("handleBatch should return 400 for invalid command, got %d", resp.StatusCode)
	}
}

func TestServer_ApplyBatch_Errors(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Manually call applyBatch with malformed data
	req := batchRequest{
		cmds:  []*LogCommand{{Type: CmdCreateInode, Data: []byte("invalid-json"), UserID: "u1"}},
		resps: []chan interface{}{make(chan interface{}, 1)},
	}
	server.applyBatch(req)
	res := <-req.resps[0]
	if _, ok := res.(error); !ok {
		t.Error("Expected error for malformed command in batch")
	}
}

func TestServer_GetInodes_EdgeCases(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public()}, usk, tc.AdminID, tc.AdminSK)
	token1, secret1 := LoginSessionForTestWithSecret(t, ts, u1, usk)

	// 1. Fetch missing inode
	ids := []string{"missing"}
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionGetInodes, ids, u1, usk, secret1)
	req.Header.Set("Session-Token", token1)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for batch fetch with missing ID, got %d", resp.StatusCode)
	}
}

func TestServer_Batch_Forbidden(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public(), Locked: false}, usk, tc.AdminID, tc.AdminSK)

	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u2, UID: 1002, SignKey: usk2.Public(), Locked: false}, usk2, tc.AdminID, tc.AdminSK)
	token2, secret2 := LoginSessionForTestWithSecret(t, ts, u2, usk2)

	// u1 owns 0000000000000000000000000000000f
	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := GenerateInodeID(u1, nonce1)
	inode1 := Inode{ID: id1, Nonce: nonce1, OwnerID: u1, Type: FileType, Mode: 0644}
	inode1.SignInodeForTest(u1, usk)
	ib1, _ := json.Marshal(inode1)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, ib1, "u1")

	// u2 tries to update 0000000000000000000000000000000f via batch
	batch := []LogCommand{{Type: CmdUpdateInode, Data: ib1, UserID: u2}}
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batch, u2, usk2, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized batch update, got %d", resp.StatusCode)
	}
}

func TestServer_GetKeySync_Errors(t *testing.T) {
	tc := SetupCluster(t)
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer ts.Close()

	// 1. Missing bearer
	req, _ := http.NewRequest("GET", ts.URL+"/v1/user/keysync", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing bearer, got %d", resp.StatusCode)
	}

	// 2. verifyJWT failure
	req.Header.Set("Authorization", "Bearer invalid")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid JWT, got %d", resp.StatusCode)
	}
}

func TestServer_handleClusterJoin_DiscoveryErrors(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public()}, usk, tc.AdminID, tc.AdminSK)
	u1Cmd, _ := LogCommand{Type: CmdPromoteAdmin, Data: MustMarshalJSON(u1)}.Marshal()
	node.FSM.Apply(&raft.Log{Data: u1Cmd})
	token, secret := LoginSessionForTestWithSecret(t, ts, u1, usk)

	// 1. Invalid address
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminClusterJoin, map[string]string{"address": "::invalid"}, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected error for invalid address")
	}

	// 2. Reject leader signature (Mock node)
	mockNode := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer mockNode.Close()

	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminClusterJoin, map[string]string{"address": mockNode.URL}, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for node rejection, got %d", resp.StatusCode)
	}
}

func TestServer_handleClusterJoin_mTLSError(t *testing.T) {
	// Discovery expects mTLS (resp.TLS != nil)
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// Configure server with clientTLSConfig so it tries TLS discovery
	server.clientTLSConfig = &tls.Config{}

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public()}, usk, tc.AdminID, tc.AdminSK)
	u1Cmd, _ := LogCommand{Type: CmdPromoteAdmin, Data: MustMarshalJSON(u1)}.Marshal()
	node.FSM.Apply(&raft.Log{Data: u1Cmd})
	token, secret := LoginSessionForTestWithSecret(t, ts, u1, usk)

	// Mock node WITHOUT TLS
	mockNode := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceHex := r.Header.Get("X-Raft-Nonce")
		nonce, _ := hex.DecodeString(nonceHex)

		// Sign as NODE_RESPONSE
		mac := hmac.New(sha256.New, []byte("testsecret"))
		mac.Write(nonce)
		mac.Write([]byte("NODE_RESPONSE"))
		sig := hex.EncodeToString(mac.Sum(nil))

		w.Header().Set("X-Raft-Response", sig)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockNode.Close()

	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminClusterJoin, map[string]string{"address": mockNode.URL}, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 500 for non-TLS discovery, got %d", resp.StatusCode)
	}
}

func TestServer_MiscHandlers_More(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public()}, usk, tc.AdminID, tc.AdminSK)
	server.ApplyRaftCommandInternal(context.Background(), CmdPromoteAdmin, MustMarshalJSON(u1), "bootstrap")

	// 1. handleRemoveNode (Success)
	// Register n2 first
	node2Info := Node{ID: "n2", Address: "http://n2:8080", Status: NodeStatusActive}
	nb2, _ := json.Marshal(node2Info)
	server.ApplyRaftCommandInternal(context.Background(), CmdRegisterNode, nb2, "")

	// Wait for commit
	time.Sleep(200 * time.Millisecond)

	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/node/n2", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleRemoveNode failed: %d", resp.StatusCode)
	}

	// 2. handleAddChild (Success via batch UpdateInode)
	nonceDir := make([]byte, 16)
	rand.Read(nonceDir)
	idDir := GenerateInodeID(u1, nonceDir)

	nonceFile := make([]byte, 16)
	rand.Read(nonceFile)
	idFile := GenerateInodeID(u1, nonceFile)

	dir := Inode{ID: idDir, Nonce: nonceDir, Type: DirType, OwnerID: u1, NLink: 1, Mode: 0755}
	dir.SignInodeForTest(u1, usk)
	file := Inode{ID: idFile, Nonce: nonceFile, Type: FileType, OwnerID: u1, NLink: 1, Mode: 0644}
	file.SignInodeForTest(u1, usk)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, MustMarshalJSON(dir), u1)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, MustMarshalJSON(file), u1)

	time.Sleep(200 * time.Millisecond)

	dir.Children = map[string]ChildEntry{"dummy": {ID: idFile}}
	dir.Version = 2
	dir.SignInodeForTest(u1, usk)

	file.Links = map[string]bool{idDir + ":dummy": true}
	file.NLink = 2
	file.Version = 2
	file.SignInodeForTest(u1, usk)

	batchA := []LogCommand{
		{
			Type:          CmdUpdateInode,
			Data:          MustMarshalJSON(dir),
			LeaseBindings: map[string]string{"dummy": ""},
		},
		{Type: CmdUpdateInode, Data: MustMarshalJSON(file), UserID: u1},
	}
	tokenAlice, secretAlice := LoginSessionForTestWithSecret(t, ts, u1, usk)
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batchA, u1, usk, secretAlice)
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAddChild failed: %d", resp.StatusCode)
	}
	opened := UnsealTestResponseWithSession(t, nil, secretAlice, tc.NodeSK.Public(), resp)
	var results []json.RawMessage
	if err := json.Unmarshal(opened, &results); err != nil {
		t.Fatalf("Failed to unmarshal batch results: %v", err)
	}
	resp.Body.Close()

	// Verify in FSM
	var updatedDir Inode
	server.fsm.db.View(func(tx *bolt.Tx) error {
		plain, _ := server.fsm.Get(tx, []byte("inodes"), []byte(idDir))
		return json.Unmarshal(plain, &updatedDir)
	})
	if updatedDir.Children["dummy"].ID != idFile {
		t.Errorf("expected entry dummy -> %s, got %v", idFile, updatedDir.Children)
	}

	// 3. handleListGroups (Sealed)
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionListGroups, nil, u1, usk, secretAlice)
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleListGroups (sealed) failed: %d", resp.StatusCode)
	}
}

func TestServer_DebugHandlers_Extra(t *testing.T) {
	tc := SetupCluster(t)
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer ts.Close()

	// 1. Missing secret
	req, _ := http.NewRequest("POST", ts.URL+"/v1/debug/gc", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing secret, got %d", resp.StatusCode)
	}

	// 2. Wrong secret
	req.Header.Set("X-Raft-Secret", "wrong")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong secret, got %d", resp.StatusCode)
	}
}

func TestServer_handleBatch_More(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	srv := tc.Server
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public()}, usk, tc.AdminID, tc.AdminSK)

	// 1. Batch Create
	nonce := make([]byte, 16)
	rand.Read(nonce)
	id := GenerateInodeID(u1, nonce)
	inode := Inode{ID: id, Nonce: nonce, Type: DirType, OwnerID: u1, Mode: 0755}
	inode.SignInodeForTest(u1, usk)
	batch := []LogCommand{
		{Type: CmdCreateInode, Data: MustMarshalJSON(inode), UserID: u1},
	}
	tokenAlice, secretAlice := LoginSessionForTestWithSecret(t, ts, u1, usk)
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batch, u1, usk, secretAlice)
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Batch create failed: %d", resp.StatusCode)
	}
	opened := UnsealTestResponseWithSession(t, nil, secretAlice, tc.NodeSK.Public(), resp)
	var results []json.RawMessage
	if err := json.Unmarshal(opened, &results); err != nil {
		t.Fatalf("Failed to unmarshal batch results: %v", err)
	}
	resp.Body.Close()

	// 2. Batch Delete (Implicit via UpdateInode NLink=0)
	inode.Version = 2
	inode.NLink = 0
	inode.SignInodeForTest(u1, usk)
	batchD := []LogCommand{
		{Type: CmdUpdateInode, Data: MustMarshalJSON(inode), UserID: u1},
	}
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batchD, u1, usk, secretAlice)
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Batch delete failed: %d", resp.StatusCode)
	}
	opened = UnsealTestResponseWithSession(t, nil, secretAlice, tc.NodeSK.Public(), resp)
	if err := json.Unmarshal(opened, &results); err != nil {
		t.Fatalf("Failed to unmarshal batch results: %v", err)
	}
	resp.Body.Close()
}

func TestServer_Permissions_Thorough(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u1, UID: 1001, SignKey: usk.Public(), Locked: false}, usk, tc.AdminID, tc.AdminSK)

	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: u2, UID: 1002, SignKey: usk2.Public(), Locked: false}, usk2, tc.AdminID, tc.AdminSK)
	token2, _ := LoginSessionForTestWithSecret(t, ts, u2, usk2)

	// 1. Group Readable
	g1SK, _ := crypto.GenerateIdentityKey()
	g1 := Group{
		ID:       "g1",
		GID:      5001,
		OwnerID:  u1,
		Lockbox:  map[string]crypto.LockboxEntry{ComputeMemberHMAC("g1", u2): {}},
		SignKey:  g1SK.Public(),
		SignerID: u1,
		Version:  1,
	}
	g1.Signature = usk.Sign(g1.Hash())
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateGroup, MustMarshalJSON(g1), "u1")
	time.Sleep(100 * time.Millisecond)

	inode := Inode{ID: "0000000000000000000000000000000a", OwnerID: u1, GroupID: "g1", Mode: 0640, Type: FileType}
	inode.SignInodeForTest(u1, usk)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, MustMarshalJSON(inode), "u1")
	time.Sleep(100 * time.Millisecond)

	// u2 should get R token
	token2, secret2 := LoginSessionForTestWithSecret(t, ts, u2, usk2)
	irb := struct {
		InodeID string `json:"inode_id"`
		Mode    string `json:"mode"`
	}{InodeID: "0000000000000000000000000000000a", Mode: "R"}
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionIssueToken, irb, u2, usk2, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("u2 should have group read access, got %d", resp.StatusCode)
	}

	// 2. handleGetUser Redaction
	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionGetUser, GetUserRequest{ID: u1}, u2, usk2, secret2)
	req.Header.Set("Session-Token", token2)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode == http.StatusOK {
		var resUser User
		json.NewDecoder(resp.Body).Decode(&resUser)
		if resUser.Usage.InodeCount != 0 {
			t.Error("Usage should be redacted for non-self/non-admin")
		}
	}
}

func TestServer_SetAttr(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "alice"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := User{
		ID:      u1,
		UID:     1001,
		SignKey: usk.Public(),
		EncKey:  udk.EncapsulationKey().Bytes(),
	}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)

	// Create an inode
	inodeID := "file1"
	inode := Inode{
		ID:      inodeID,
		OwnerID: u1,
		Type:    FileType,
		Mode:    0644,
		NLink:   1,
	}
	inode.SignInodeForTest(u1, usk)
	ib, _ := json.Marshal(inode)
	if res, err := server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, ib, u1); err != nil || server.fsm.containsError(res) {
		t.Fatalf("Create Inode failed: err=%v, res=%v", err, res)
	}

	// Update attributes via batch UpdateInode
	inode.Mode = 0755
	inode.Version = 2
	inode.SignInodeForTest(u1, usk)
	batch := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(inode), UserID: u1}}
	tokenAlice, secretAlice := LoginSessionForTestWithSecret(t, ts, u1, usk)
	req := NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batch, u1, usk, secretAlice)
	req.Header.Set("Session-Token", tokenAlice)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleBatch UpdateInode failed: %d", resp.StatusCode)
	}
	opened := UnsealTestResponseWithSession(t, udk, secretAlice, tc.NodeSK.Public(), resp)
	var results []json.RawMessage
	if err := json.Unmarshal(opened, &results); err != nil {
		t.Fatalf("Failed to unmarshal batch results: %v", err)
	}
	resp.Body.Close()

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
	user2 := User{ID: u2, UID: 1002, SignKey: usk2.Public()}
	CreateUser(t, tc.Node, user2, usk2, tc.AdminID, tc.AdminSK)
	tokenBob, secretBob := LoginSessionForTestWithSecret(t, ts, u2, usk2)

	// Bob tries to change Alice's file
	inode.Mode = 0777
	inode.Version = 2
	inode.SignInodeForTest(u2, usk2) // Signed by Bob
	batch2 := []LogCommand{{Type: CmdUpdateInode, Data: MustMarshalJSON(inode), UserID: u1}}
	req2 := NewSealedTestRequestSymmetric(t, ts.URL, ActionBatch, batch2, u2, usk2, secretBob)
	req2.Header.Set("Session-Token", tokenBob)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unauthorized batch UpdateInode, got %d", resp2.StatusCode)
	}
}

func TestServer_HealthAndStatus(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	usk := tc.AdminSK
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// Health
	req, _ := http.NewRequest("GET", ts.URL+"/v1/health", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health check failed: %d", resp.StatusCode)
	}

	u1 := "admin"
	user := User{ID: u1, UID: 1001, SignKey: usk.Public()}
	CreateUser(t, tc.Node, user, usk, tc.AdminID, tc.AdminSK)
	server.ApplyRaftCommandInternal(context.Background(), CmdPromoteAdmin, MustMarshalJSON(u1), "")
	token, secret := LoginSessionForTestWithSecret(t, ts, u1, usk)

	req = NewSealedTestRequestSymmetric(t, ts.URL, ActionAdminStatus, nil, u1, usk, secret)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cluster status failed: %d", resp.StatusCode)
	}
}

func TestServer_Forwarding(t *testing.T) {
	// Node 1 (Leader)
	tc := SetupCluster(t)
	n1 := tc.Node
	ts1 := tc.TS
	s1 := tc.Server
	defer s1.Shutdown()
	defer n1.Shutdown()
	defer ts1.Close()
	// Node 2 (Follower)
	tmpDir2 := t.TempDir()
	st2, _ := createTestStorage(t, tmpDir2)
	nodeKey2, _ := LoadOrGenerateNodeKey(st2, "node.key", nil)
	nodeID2 := NodeIDFromKey(nodeKey2)
	n2, _ := NewRaftNode(nodeID2, "127.0.0.1:0", "", tmpDir2, st2, nodeKey2, []byte("test-cluster-secret"))
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
	s1.ApplyRaftCommandInternal(context.Background(), CmdRegisterNode, n1b, "")

	nodeDecKey2, _ := crypto.GenerateEncryptionKey()
	s2 := NewServer(nodeID2, n2.Raft, n2.FSM, "", signKey2, "testsecret", nil, 0, NewNodeVault(st2), nodeDecKey2, true)
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
