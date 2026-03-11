// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

func UnsealTestResponse(t *testing.T, userDecKey *mlkem.DecapsulationKey768, serverSignPK []byte, resp *http.Response) []byte {
	if resp.Header.Get("X-DistFS-Sealed") != "true" {
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	var sealed SealedResponse
	json.NewDecoder(resp.Body).Decode(&sealed)
	_, payload, err := crypto.OpenResponse(userDecKey, serverSignPK, sealed.Sealed)
	if err != nil {
		t.Fatalf("OpenResponse failed: %v", err)
	}
	return payload
}

func SealTestRequest(t *testing.T, userID string, userSignKey *crypto.IdentityKey, serverPKBytes []byte, payload []byte) []byte {
	serverPK, err := crypto.UnmarshalEncapsulationKey(serverPKBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal server PK: %v", err)
	}
	sealed, err := crypto.SealRequest(serverPK, userSignKey, payload)
	if err != nil {
		t.Fatalf("SealRequest failed: %v", err)
	}
	sr := SealedRequest{
		UserID: userID,
		Sealed: sealed,
	}
	b, _ := json.Marshal(sr)
	return b
}

type NoopValidator struct{}

func (n NoopValidator) ValidateNode(address string) error {
	return nil
}

func CreateUser(t *testing.T, raftNode *RaftNode, user User) {
	for user.UID == 0 {
		user.UID = generateID32()
	}
	userBytes, _ := json.Marshal(user)
	cmd := LogCommand{Type: CmdCreateUser, Data: userBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := raftNode.Raft.Apply(cmdBytes, 10*time.Second)
	err := future.Error()
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if resp := future.Response(); resp != nil {
		if err, ok := resp.(error); ok {
			t.Fatalf("Create user fsm failed: %v", err)
		}
	}

	// Explicitly unlock if the test specified Locked: false
	if !user.Locked {
		req := AdminSetUserLockRequest{UserID: user.ID, Locked: false}
		reqBytes, _ := json.Marshal(req)
		unlockCmd := LogCommand{Type: CmdAdminSetUserLock, Data: reqBytes}
		unlockBytes, _ := json.Marshal(unlockCmd)
		raftNode.Raft.Apply(unlockBytes, 10*time.Second)
	}
}

func createTestStorage(t *testing.T, dir string) (*storage.Storage, storage_crypto.MasterKey) {
	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(dir, mk)
	return st, mk
}

func SetupCluster(t *testing.T) (*RaftNode, *httptest.Server, *crypto.IdentityKey, []byte, *Server) {
	tmpDir := t.TempDir()

	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(tmpDir, mk)

	nodeKey, err := LoadOrGenerateNodeKey(st, "node.key", nil)
	if err != nil {
		t.Fatalf("failed to generate node key: %v", err)
	}
	nodeID := NodeIDFromKey(nodeKey)

	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	node, err := NewRaftNode(nodeID, "127.0.0.1:0", "", tmpDir, st, nodeKey, clusterSecret)
	if err != nil {
		t.Fatalf("NewRaftNode failed: %v", err)
	}

	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:      raft.ServerID(nodeID),
				Address: node.Transport.LocalAddr(),
			},
		},
	}
	f := node.Raft.BootstrapCluster(cfg)
	if err := f.Error(); err != nil {
		node.Shutdown()
		t.Fatalf("Bootstrap failed: %v", err)
	}

	WaitLeader(t, node.Raft)

	// Bootstrap cluster key
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	keyID := "key-1"

	key := ClusterKey{
		ID:        keyID,
		EncKey:    ek.Bytes(),
		DecKey:    nil, // DO NOT store private key in FSM
		CreatedAt: time.Now().Unix(),
	}
	keyBytes, _ := json.Marshal(key)
	cmd := LogCommand{Type: CmdRotateKey, Data: keyBytes}
	cmdBytes, _ := json.Marshal(cmd)
	f = node.Raft.Apply(cmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Bootstrap key apply failed: %v", err)
	}

	// Register the bootstrapped node in FSM
	nodeInfo := Node{
		ID:          nodeID,
		RaftAddress: string(node.Transport.LocalAddr()),
		Status:      NodeStatusActive,
	}
	nb, _ := json.Marshal(nodeInfo)
	f = node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: nb}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Bootstrap RegisterNode failed: %v", err)
	}

	// Bootstrap cluster sign key
	csk, _ := crypto.GenerateIdentityKey()
	cskData := ClusterSignKey{
		Public:           csk.Public(),
		EncryptedPrivate: csk.MarshalPrivate(),
	}
	cskBytes, _ := json.Marshal(cskData)
	f = node.Raft.Apply(LogCommand{Type: CmdSetClusterSignKey, Data: cskBytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Bootstrap sign key apply failed: %v", err)
	}

	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	server := NewServer(nodeID, node.Raft, node.FSM, "", signKey, "testsecret", nil, 0, NewNodeVault(st), nodeDecKey, true, true)
	ts := httptest.NewServer(server)

	server.RegisterEpochKey(keyID, dk)

	return node, ts, signKey, ek.Bytes(), server
}

func LoginSessionForTest(t *testing.T, ts *httptest.Server, userID string, userSignKey *crypto.IdentityKey) string {
	// 1. Get Challenge
	reqData := AuthChallengeRequest{UserID: userID}
	b, _ := json.Marshal(reqData)
	resp, err := http.Post(ts.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge request status: %d", resp.StatusCode)
	}

	var challengeRes AuthChallengeResponse
	json.NewDecoder(resp.Body).Decode(&challengeRes)

	// 2. Solve Challenge
	sig := userSignKey.Sign(challengeRes.Challenge)
	solve := AuthChallengeSolve{
		UserID:    userID,
		Challenge: challengeRes.Challenge,
		Signature: sig,
	}
	b, _ = json.Marshal(solve)
	resp, err = http.Post(ts.URL+"/v1/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login request status: %d", resp.StatusCode)
	}

	var sessionRes SessionResponse
	json.NewDecoder(resp.Body).Decode(&sessionRes)
	return sessionRes.Token
}

func WaitLeader(t *testing.T, r *raft.Raft) {
	leader := false
	for i := 0; i < 50; i++ {
		if r.State() == raft.Leader {
			leader = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !leader {
		t.Fatal("Node did not become leader")
	}
}

func GetClusterSignKey(fsm *MetadataFSM) ClusterSignKey {
	var csk ClusterSignKey
	err := fsm.db.View(func(tx *bolt.Tx) error {
		v, err := fsm.Get(tx, []byte("system"), []byte("cluster_sign_key"))
		if err != nil {
			return err
		}
		if v == nil {
			return fmt.Errorf("cluster_sign_key missing")
		}
		return json.Unmarshal(v, &csk)
	})
	if err != nil {
		log.Printf("GetClusterSignKey failed: %v", err)
	}
	return csk
}

func MustMarshalJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func CreateSessionTokenForTest(userID string) string {
	st := SignedSessionToken{
		Token: SessionToken{
			UserID: userID,
			Expiry: time.Now().Add(time.Hour).Unix(),
			Nonce:  "test-nonce",
		},
	}
	b, _ := json.Marshal(st)
	return base64.StdEncoding.EncodeToString(b)
}
