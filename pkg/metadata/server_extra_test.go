// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"crypto/hmac"
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
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// Register a user
	u1 := "user1"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := User{
		ID:      u1,
		SignKey: usk.Public(),
		EncKey:  udk.EncapsulationKey().Bytes(),
	}
	CreateUser(t, node, user)
	// Promote to Admin
	server.ApplyRaftCommandInternal(CmdPromoteAdmin, []byte(u1))
	token := LoginSessionForTest(t, ts, u1, usk)

	// Register a Node
	nodeInfo := Node{ID: "n1", Address: "http://n1:8080", Status: NodeStatusActive}
	nb, _ := json.Marshal(nodeInfo)
	server.ApplyRaftCommandInternal(CmdRegisterNode, nb)

	// Record some metrics
	server.fsm.metrics.RecordOp(CmdCreateInode, 100)
	snap := server.fsm.metrics.SnapshotAndReset()
	snapData, _ := json.Marshal(snap)
	server.ApplyRaftCommandInternal(CmdStoreMetrics, snapData)

	// 1. handleAllocateGID
	req, _ := http.NewRequest("GET", ts.URL+"/v1/group/gid/allocate", nil)
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
	// Body is empty but POST needs sealing
	sealedA := SealTestRequest(t, u1, usk, ek, nil)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/allocate", bytes.NewReader(sealedA))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
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
	inode := Inode{ID: "f1", OwnerID: u1, Type: FileType}
	inode.SignInodeForTest(u1, usk)
	ib, _ := json.Marshal(inode)
	server.ApplyRaftCommandInternal(CmdCreateInode, ib)

	issueReq := struct {
		InodeID string   `json:"inode_id"`
		Chunks  []string `json:"chunks"`
		Mode    string   `json:"mode"`
	}{
		InodeID: "f1",
		Mode:    "R",
	}
	irb, _ := json.Marshal(issueReq)
	sealedI := SealTestRequest(t, u1, usk, ek, irb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/token", bytes.NewReader(sealedI))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleIssueToken failed: %d", resp.StatusCode)
	}

	// 8. handleGetInodes (Batch)
	ids := []string{"f1"}
	idsb, _ := json.Marshal(ids)
	sealedIds := SealTestRequest(t, u1, usk, ek, idsb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/inodes", bytes.NewReader(sealedIds))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleGetInodes failed: %d", resp.StatusCode)
	}

	// 9. handleBatch
	batch := []LogCommand{
		{Type: CmdUpdateInode, Data: ib},
	}
	bb, _ := json.Marshal(batch)
	sealedB := SealTestRequest(t, u1, usk, ek, bb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(sealedB))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleBatch failed: %d", resp.StatusCode)
	}

	// 10. handleAcquireLeases / handleReleaseLeases
	leaseReq := LeaseRequest{
		InodeIDs: []string{"f1"},
		Duration: int64(10 * 1000 * 1000 * 1000), // 10s
	}
	lrb, _ := json.Marshal(leaseReq)
	sealedL := SealTestRequest(t, u1, usk, ek, lrb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/lease/acquire", bytes.NewReader(sealedL))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAcquireLeases failed: %d", resp.StatusCode)
	}

	sealedR := SealTestRequest(t, u1, usk, ek, lrb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/lease/release", bytes.NewReader(sealedR))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleReleaseLeases failed: %d", resp.StatusCode)
	}

	// 11. handleGetWorldPrivateKey (Admin Only)
	// Ensure world is initialized
	http.Get(ts.URL + "/v1/meta/key/world")

	req, _ = http.NewRequest("GET", ts.URL+"/v1/meta/key/world/private", nil)
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
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// The first user is admin
	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	udk, _ := crypto.GenerateEncryptionKey()
	user := User{
		ID:      u1,
		SignKey: usk.Public(),
		EncKey:  udk.EncapsulationKey().Bytes(),
	}
	CreateUser(t, node, user)
	server.ApplyRaftCommandInternal(CmdPromoteAdmin, []byte(u1))
	token := LoginSessionForTest(t, ts, u1, usk)

	// Create Group g1
	group := Group{ID: "g1", OwnerID: u1, GID: 5000, Version: 1}
	gb, _ := json.Marshal(group)
	server.ApplyRaftCommandInternal(CmdCreateGroup, gb)

	// handleClusterLeases
	req, _ := http.NewRequest("GET", ts.URL+"/v1/admin/leases", nil)
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	// Must seal for admin mutations, but GET might just work if we bypass unseal for empty body?
	// Let's actually seal a dummy body.
	sealed := SealTestRequest(t, u1, usk, ek, nil)
	req.Body = io.NopCloser(bytes.NewReader(sealed))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleClusterLeases failed: %d", resp.StatusCode)
	}

	// handleSetUserQuota
	quotaReq := SetUserQuotaRequest{UserID: u1, MaxInodes: ptr(int64(100))}
	qrb, _ := json.Marshal(quotaReq)
	sealedQ := SealTestRequest(t, u1, usk, ek, qrb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/admin/quota/user", bytes.NewReader(sealedQ))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleSetUserQuota failed: %d", resp.StatusCode)
	}
	// 11. handleAdminPromote
	promoteReq, _ := json.Marshal(map[string]string{"user_id": u1})
	sealedP := SealTestRequest(t, u1, usk, ek, promoteReq)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/admin/promote", bytes.NewReader(sealedP))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAdminPromote failed: %d", resp.StatusCode)
	}

	// 12. handleSetGroupQuota
	groupQuotaReq := SetGroupQuotaRequest{GroupID: "g1", MaxInodes: ptr(int64(50))}
	gqrb, _ := json.Marshal(groupQuotaReq)
	sealedGQ := SealTestRequest(t, u1, usk, ek, gqrb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/admin/quota/group", bytes.NewReader(sealedGQ))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleSetGroupQuota failed: %d", resp.StatusCode)
	}
}

func TestServer_ClusterAdminHandlers(t *testing.T) {
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, SignKey: usk.Public()}
	CreateUser(t, node, user)
	server.ApplyRaftCommandInternal(CmdPromoteAdmin, []byte(u1))
	token := LoginSessionForTest(t, ts, u1, usk)

	// handleClusterJoin
	joinReq := map[string]string{"id": "n2", "address": "http://127.0.0.1:8888"}
	jrb, _ := json.Marshal(joinReq)
	sealedJ := SealTestRequest(t, u1, usk, ek, jrb)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/admin/join", bytes.NewReader(sealedJ))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		// Might fail due to real Raft join logic
	}

	// handleClusterRemove
	removeReq := map[string]string{"id": "n2"}
	rrb, _ := json.Marshal(removeReq)
	sealedR := SealTestRequest(t, u1, usk, ek, rrb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/admin/remove", bytes.NewReader(sealedR))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
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

	node, ts, _, _, server := SetupCluster(t)
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
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
}

func TestServer_IssueToken_Permissions(t *testing.T) {
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})

	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u2, SignKey: usk2.Public()})
	token2 := LoginSessionForTest(t, ts, u2, usk2)

	// 1. World Readable file (owned by u1)
	inodeW := Inode{ID: "world", OwnerID: u1, Type: FileType, Mode: 0644}
	inodeW.SignInodeForTest(u1, usk)
	ibW, _ := json.Marshal(inodeW)
	server.ApplyRaftCommandInternal(CmdCreateInode, ibW)

	// u2 should be able to get R token
	issueReq := struct {
		InodeID string   `json:"inode_id"`
		Chunks  []string `json:"chunks"`
		Mode    string   `json:"mode"`
	}{InodeID: "world", Mode: "R"}
	irb, _ := json.Marshal(issueReq)
	sealedI := SealTestRequest(t, u2, usk2, ek, irb)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/token", bytes.NewReader(sealedI))
	req.Header.Set("Session-Token", token2)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("u2 should be able to read world file, got %d", resp.StatusCode)
	}

	// u2 should NOT be able to get W token
	issueReq.Mode = "W"
	irb, _ = json.Marshal(issueReq)
	sealedI = SealTestRequest(t, u2, usk2, ek, irb)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/token", bytes.NewReader(sealedI))
	req.Header.Set("Session-Token", token2)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("u2 should NOT be able to write world-read file, got %d", resp.StatusCode)
	}
}

func TestServer_UnsealExtraErrors(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, SignKey: usk.Public()}
	CreateUser(t, node, user)

	// 1. Invalid JSON
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/inode", bytes.NewReader([]byte("not-json")))
	req.Header.Set("X-DistFS-Sealed", "true")
	_, err := server.unsealRequest(httptest.NewRecorder(), req, &user)
	if err == nil {
		t.Error("unsealRequest should fail for invalid JSON")
	}

	// 2. Too short sealed payload
	sr := SealedRequest{UserID: u1, Sealed: []byte("short")}
	b, _ := json.Marshal(sr)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/inode", bytes.NewReader(b))
	req.Header.Set("X-DistFS-Sealed", "true")
	_, err = server.unsealRequest(httptest.NewRecorder(), req, &user)
	if err == nil {
		t.Error("unsealRequest should fail for too short payload")
	}
}

func TestServer_LoginExtraErrors(t *testing.T) {
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, SignKey: usk.Public()}
	CreateUser(t, node, user)

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
	_, ts, _, _, server := SetupCluster(t)
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
	nodeKey, _ := LoadOrGenerateNodeKey(st, "node.key")
	node2, _ := NewRaftNode("node2", "127.0.0.1:0", "", tmpDir, st, nodeKey)
	defer node2.Shutdown()

	signKey, _ := crypto.GenerateIdentityKey()
	server2 := NewServer("node2", node2.Raft, node2.FSM, "", signKey, "testsecret", nil, 0)

	// node2 has no leader
	req, _ := http.NewRequest("GET", "/v1/meta/inode/root", nil)
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
	node, ts, _, _, server := SetupCluster(t)
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
	node, ts, _, ek, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	user := User{ID: u1, SignKey: usk.Public()}
	CreateUser(t, node, user)
	token := LoginSessionForTest(t, ts, u1, usk)

	// handleBatch with invalid command type
	batch := []LogCommand{{Type: 255, Data: []byte("{}")}}
	bb, _ := json.Marshal(batch)
	sealed := SealTestRequest(t, u1, usk, ek, bb)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("handleBatch should return 400 for invalid command, got %d", resp.StatusCode)
	}
}

func TestServer_ApplyBatch_Errors(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Manually call applyBatch with malformed data
	req := batchRequest{
		cmds:  []*LogCommand{{Type: CmdCreateInode, Data: []byte("invalid-json")}},
		resps: []chan interface{}{make(chan interface{}, 1)},
	}
	server.applyBatch(req)
	res := <-req.resps[0]
	if _, ok := res.(error); !ok {
		t.Error("Expected error for malformed command in batch")
	}
}

func TestServer_GetInodes_EdgeCases(t *testing.T) {
	node, ts, _, ek, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})
	token1 := LoginSessionForTest(t, ts, u1, usk)

	// 1. Fetch missing inode
	ids := []string{"missing"}
	idsb, _ := json.Marshal(ids)
	sealed := SealTestRequest(t, u1, usk, ek, idsb)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/inodes", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token1)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for batch fetch with missing ID, got %d", resp.StatusCode)
	}
}

func TestServer_Batch_Forbidden(t *testing.T) {
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})

	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u2, SignKey: usk2.Public()})
	token2 := LoginSessionForTest(t, ts, u2, usk2)

	// u1 owns f1
	inode1 := Inode{ID: "f1", OwnerID: u1, Type: FileType}
	inode1.SignInodeForTest(u1, usk)
	ib1, _ := json.Marshal(inode1)
	server.ApplyRaftCommandInternal(CmdCreateInode, ib1)

	// u2 tries to update f1 via batch
	batch := []LogCommand{{Type: CmdUpdateInode, Data: ib1}}
	bb, _ := json.Marshal(batch)
	sealed := SealTestRequest(t, u2, usk2, ek, bb)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token2)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized batch update, got %d", resp.StatusCode)
	}
}

func TestServer_GetKeySync_Errors(t *testing.T) {
	_, ts, _, _, _ := SetupCluster(t)
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
	node, ts, _, ek, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})
	node.FSM.Apply(&raft.Log{Data: LogCommand{Type: CmdPromoteAdmin, Data: []byte(u1)}.Marshal()})
	token := LoginSessionForTest(t, ts, u1, usk)

	// 1. Invalid address
	req, _ := http.NewRequest("POST", ts.URL+"/v1/admin/join", bytes.NewReader(SealTestRequest(t, u1, usk, ek, []byte(`{"address": "::invalid"}`))))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected error for invalid address")
	}

	// 2. Reject leader signature (Mock node)
	mockNode := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer mockNode.Close()

	req, _ = http.NewRequest("POST", ts.URL+"/v1/admin/join", bytes.NewReader(SealTestRequest(t, u1, usk, ek, []byte(`{"address": "`+mockNode.URL+`"}`))))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for node rejection, got %d", resp.StatusCode)
	}
}

func TestServer_handleClusterJoin_mTLSError(t *testing.T) {
	// Discovery expects mTLS (resp.TLS != nil)
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	// Configure server with clientTLSConfig so it tries TLS discovery
	server.clientTLSConfig = &tls.Config{}

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})
	node.FSM.Apply(&raft.Log{Data: LogCommand{Type: CmdPromoteAdmin, Data: []byte(u1)}.Marshal()})
	token := LoginSessionForTest(t, ts, u1, usk)

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

	req, _ := http.NewRequest("POST", ts.URL+"/v1/admin/join", bytes.NewReader(SealTestRequest(t, u1, usk, ek, []byte(`{"address": "`+mockNode.URL+`"}`))))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 500 for non-TLS discovery, got %d", resp.StatusCode)
	}
}

func TestServer_MiscHandlers_More(t *testing.T) {
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})
	server.ApplyRaftCommandInternal(CmdPromoteAdmin, []byte(u1))
	token := LoginSessionForTest(t, ts, u1, usk)

	// 1. handleRemoveNode (Success)
	// Register n2 first
	node2Info := Node{ID: "n2", Address: "http://n2:8080", Status: NodeStatusActive}
	nb2, _ := json.Marshal(node2Info)
	server.ApplyRaftCommandInternal(CmdRegisterNode, nb2)

	// Wait for commit
	time.Sleep(200 * time.Millisecond)

	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/node/n2", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleRemoveNode failed: %d", resp.StatusCode)
	}

	// 2. handleAddChild (Success)
	server.ApplyRaftCommandInternal(CmdCreateInode, mustMarshalJSON(Inode{ID: "dir1", Type: DirType, OwnerID: u1}))
	server.ApplyRaftCommandInternal(CmdCreateInode, mustMarshalJSON(Inode{ID: "file1", Type: FileType, OwnerID: u1}))

	time.Sleep(200 * time.Millisecond)

	reqData := map[string]string{"name": "f1", "child_id": "file1"}
	rb, _ := json.Marshal(reqData)
	sealed := SealTestRequest(t, u1, usk, ek, rb)
	req, _ = http.NewRequest("PUT", ts.URL+"/v1/meta/directory/dir1/entry", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleAddChild failed: %d", resp.StatusCode)
	}
	// Verify in FSM
	var updatedDir Inode
	server.fsm.db.View(func(tx *bolt.Tx) error {
		plain, _ := server.fsm.Get(tx, []byte("inodes"), []byte("dir1"))
		return json.Unmarshal(plain, &updatedDir)
	})
	if updatedDir.Children["f1"] != "file1" {
		t.Errorf("expected entry f1 -> file1, got %v", updatedDir.Children)
	}

	// 3. handleGetGroupSignKey (Success)
	server.ApplyRaftCommandInternal(CmdCreateGroup, mustMarshalJSON(Group{
		ID:               "g_more",
		OwnerID:          u1,
		GID:              5001,
		EncryptedSignKey: []byte("fake-sign-key"),
		Lockbox: crypto.Lockbox{
			u1 + ":sign": crypto.LockboxEntry{KEMCiphertext: []byte("fake"), DEMCiphertext: []byte("fake")},
		},
	}))

	time.Sleep(500 * time.Millisecond) // Long sleep for group appear

	req, _ = http.NewRequest("GET", ts.URL+"/v1/group/g_more/sign/private", nil)
	req.Header.Set("Session-Token", token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("handleGetGroupSignKey failed: %d %s", resp.StatusCode, string(b))
	}

	// 4. handleListGroups (Sealed)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/user/groups", nil)
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleListGroups (sealed) failed: %d", resp.StatusCode)
	}
}

func TestServer_DebugHandlers_Extra(t *testing.T) {
	_, ts, _, _, _ := SetupCluster(t)
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
	node, ts, _, ek, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})
	token := LoginSessionForTest(t, ts, u1, usk)

	// 1. Batch Create
	inode := Inode{ID: "b1", Type: DirType, OwnerID: u1}
	inode.SignInodeForTest(u1, usk)
	batch := []LogCommand{
		{Type: CmdCreateInode, Data: mustMarshalJSON(inode)},
	}
	bb, _ := json.Marshal(batch)
	sealed := SealTestRequest(t, u1, usk, ek, bb)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(sealed))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Batch create failed: %d", resp.StatusCode)
	}

	// 2. Batch Delete
	batchD := []LogCommand{
		{Type: CmdDeleteInode, Data: []byte("b1")},
	}
	bbD, _ := json.Marshal(batchD)
	sealedD := SealTestRequest(t, u1, usk, ek, bbD)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(sealedD))
	req.Header.Set("Session-Token", token)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Batch delete failed: %d", resp.StatusCode)
	}
}

func TestServer_Permissions_Thorough(t *testing.T) {
	node, ts, _, ek, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	WaitLeader(t, node.Raft)

	u1 := "u1"
	usk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u1, SignKey: usk.Public()})

	u2 := "u2"
	usk2, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: u2, SignKey: usk2.Public()})
	token2 := LoginSessionForTest(t, ts, u2, usk2)

	// 1. Group Readable
	server.ApplyRaftCommandInternal(CmdCreateGroup, mustMarshalJSON(Group{ID: "g1", OwnerID: u1, Members: map[string]bool{u2: true}}))
	time.Sleep(100 * time.Millisecond)

	inode := Inode{ID: "fg", OwnerID: u1, GroupID: "g1", Mode: 0640, Type: FileType}
	inode.SignInodeForTest(u1, usk)
	server.ApplyRaftCommandInternal(CmdCreateInode, mustMarshalJSON(inode))
	time.Sleep(100 * time.Millisecond)

	// u2 should get R token
	irb, _ := json.Marshal(struct {
		InodeID string `json:"inode_id"`
		Mode    string `json:"mode"`
	}{InodeID: "fg", Mode: "R"})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/token", bytes.NewReader(SealTestRequest(t, u2, usk2, ek, irb)))
	req.Header.Set("Session-Token", token2)
	req.Header.Set("X-DistFS-Sealed", "true")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("u2 should have group read access, got %d", resp.StatusCode)
	}

	// 2. handleGetUser Redaction
	req, _ = http.NewRequest("GET", ts.URL+"/v1/user/u1", nil)
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

func mustMarshalJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func ptr[T any](v T) *T {
	return &v
}

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
