//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func ptr[T any](v T) *T {
	return &v
}

func computeTestHMAC(signKey []byte, userID string) string {
	mac := hmac.New(sha256.New, signKey)
	mac.Write([]byte(userID))
	return hex.EncodeToString(mac.Sum(nil))
}

func UnsealTestResponse(t *testing.T, userDecKey *mlkem.DecapsulationKey768, serverSignPK []byte, resp *http.Response) []byte {
	return UnsealTestResponseWithSession(t, userDecKey, nil, serverSignPK, resp)
}

func UnsealTestResponseWithSession(t *testing.T, userDecKey *mlkem.DecapsulationKey768, sessionKey []byte, serverSignPK []byte, resp *http.Response) []byte {
	if resp.Header.Get("X-DistFS-Sealed") != "true" {
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	var sealed SealedResponse
	json.NewDecoder(resp.Body).Decode(&sealed)

	if len(sessionKey) > 0 {
		_, payload, err := crypto.OpenResponseSymmetric(sessionKey, serverSignPK, sealed.Sealed)
		if err == nil {
			return payload
		}
	}

	_, payload, err := crypto.OpenResponse(userDecKey, serverSignPK, sealed.Sealed)
	if err != nil {
		t.Fatalf("OpenResponse failed: %v", err)
	}
	return payload
}

func SealTestRequest(t *testing.T, userID string, userSignKey *crypto.IdentityKey, serverPKBytes []byte, payload []byte) []byte {
	b, _ := SealTestRequestWithSecret(t, userID, userSignKey, serverPKBytes, payload)
	return b
}

func SealTestRequestWithSecret(t *testing.T, userID string, userSignKey *crypto.IdentityKey, serverPKBytes []byte, payload []byte) ([]byte, []byte) {
	serverPK, err := crypto.UnmarshalEncapsulationKey(serverPKBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal server PK: %v", err)
	}
	// Use crypto.SealRequest but it doesn't return the secret.
	// We'll reimplement it slightly to get the secret.
	ts := time.Now().UnixNano()
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts))
	toSign := make([]byte, 8+len(payload))
	copy(toSign[0:8], tsBytes)
	copy(toSign[8:], payload)
	sig := userSignKey.Sign(toSign)
	sigSize := crypto.SignatureSize()
	inner := make([]byte, 8+sigSize+len(payload))
	copy(inner[0:8], tsBytes)
	copy(inner[8:8+sigSize], sig)
	copy(inner[8+sigSize:], payload)

	sharedSecret, kemCT := crypto.Encapsulate(serverPK)
	demCT, _ := crypto.EncryptDEM(sharedSecret, inner)
	sealed := make([]byte, len(kemCT)+len(demCT))
	copy(sealed[0:len(kemCT)], kemCT)
	copy(sealed[len(kemCT):], demCT)

	sr := SealedRequest{
		UserID: userID,
		Sealed: sealed,
	}
	b, _ := json.Marshal(sr)
	return b, sharedSecret
}

type NoopValidator struct{}

func (n NoopValidator) ValidateNode(address string) error {
	return nil
}

func CreateUser(t *testing.T, raftNode *RaftNode, user User, userSK *crypto.IdentityKey, adminID string, adminSK *crypto.IdentityKey) {
	for user.UID == 0 {
		user.UID = generateID32()
	}
	user.Locked = false
	user.Signature = userSK.Sign(user.Hash())
	userBytes, _ := json.Marshal(user)
	cmd := LogCommand{Type: CmdCreateUser, Data: userBytes, UserID: user.ID}
	cmdBytes, _ := cmd.Marshal()

	future := raftNode.Raft.Apply(cmdBytes, 10*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if resp := future.Response(); resp != nil {
		if err, ok := resp.(error); ok && err != nil {
			t.Fatalf("Create user fsm failed: %v", err)
		}
	}

	// 1. Unlock account (via admin)
	req := AdminSetUserLockRequest{UserID: user.ID, Locked: false}
	reqBytes, _ := json.Marshal(req)
	unlockCmd := LogCommand{
		Type:   CmdAdminSetUserLock,
		Data:   reqBytes,
		UserID: adminID,
	}
	ub, _ := unlockCmd.Marshal()
	if err := raftNode.Raft.Apply(ub, 10*time.Second).Error(); err != nil {
		t.Fatalf("UnlockUser failed: %v", err)
	}
}

// BootstrapBackbone provisions ONLY server-side foundations: buckets, admin user, and system groups.
// It DOES NOT create any inodes, as directory structure is a client concern.
func BootstrapBackbone(t *testing.T, raftNode *RaftNode, adminID string, adminDK *mlkem.DecapsulationKey768, adminSK *crypto.IdentityKey) {
	adminUPK := adminDK.EncapsulationKey()

	apply := func(cmdType CommandType, data interface{}) {
		b, _ := json.Marshal(data)
		cmd := LogCommand{
			Type:   cmdType,
			Data:   b,
			UserID: adminID,
		}
		cb, _ := cmd.Marshal()
		future := raftNode.Raft.Apply(cb, 10*time.Second)
		if err := future.Error(); err != nil {
			t.Fatalf("BootstrapBackbone apply %v failed (raft): %v", cmdType, err)
		}
		if resp := future.Response(); resp != nil {
			if err, ok := resp.(error); ok && err != nil {
				// Allow "already exists" for idempotency
				if strings.Contains(err.Error(), "already exists") {
					return
				}
				t.Fatalf("BootstrapBackbone apply %v failed (fsm): %v", cmdType, err)
			}
		}
	}

	// 1. Ensure Buckets
	raftNode.FSM.db.Update(func(tx *bolt.Tx) error {
		buckets := []string{"users", "admins", "groups", "gids", "owner_groups", "inodes", "nodes", "system"}
		for _, b := range buckets {
			tx.CreateBucketIfNotExists([]byte(b))
		}
		return nil
	})

	// 2. Create Admin User (Self-Signed)
	adminUser := User{
		ID:      adminID,
		UID:     1000,
		SignKey: adminSK.Public(),
		EncKey:  adminDK.EncapsulationKey().Bytes(),
		Locked:  false,
	}
	adminUser.Signature = adminSK.Sign(adminUser.Hash())
	apply(CmdCreateUser, adminUser)

	// Also mark as admin in the admins bucket
	raftNode.FSM.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("admins"))
		return b.Put([]byte(adminID), []byte("true"))
	})

	// 3. Create foundational groups
	createGroup := func(id string, gid uint32, ownerID string) (Group, []byte) {
		masterSeed := make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, masterSeed); err != nil {
			panic("entropy failure in test: " + err.Error())
		}
		epochSeed, err := crypto.DeriveEpochKey(masterSeed, MaxEpochs, 0)
		if err != nil {
			panic(err)
		}
		keys, _ := crypto.DeriveGroupKeys(epochSeed)

		nonce := GenerateNonce()
		derivedID := GenerateGroupID(ownerID, nonce)
		if id == "" {
			id = derivedID
		}

		lb := crypto.NewLockbox()
		target := ComputeMemberHMAC(id, adminID)
		lb.AddRecipient(target, adminUPK, epochSeed, 0)

		rk := make([]byte, 32)
		encMasterSeed, _ := crypto.EncryptDEM(rk, masterSeed)

		g := Group{
			ID:                 id,
			GID:                gid,
			OwnerID:            ownerID,
			Nonce:              nonce,
			Version:            1,
			QuotaEnabled:       true,
			EncKey:             keys.EncKey.EncapsulationKey().Bytes(),
			SignKey:            keys.SignKey.Public(),
			SignerID:           adminID,
			Lockbox:            lb,
			Epoch:              0,
			EncryptedEpochSeed: encMasterSeed,
		}
		g.Signature = adminSK.Sign(g.Hash())
		apply(CmdCreateGroup, g)

		if id == "users" {
			raftNode.FSM.db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("system"))
				b.Put([]byte("test_users_seed"), epochSeed)
				return nil
			})
		}

		return g, epochSeed
	}

	adminG, _ := createGroup("admin", 1000, SelfOwnedGroup)
	_, _ = createGroup("users", 1001, adminG.ID)
	_, _ = createGroup("registry", 1002, adminG.ID)
}

func createTestStorage(t *testing.T, dir string) (*storage.Storage, storage_crypto.MasterKey) {
	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(dir, mk)
	return st, mk
}

func BootstrapClusterKeys(t *testing.T, raftNode *RaftNode) (*mlkem.EncapsulationKey768, *mlkem.DecapsulationKey768, *crypto.IdentityKey, string, *crypto.IdentityKey, *mlkem.DecapsulationKey768) {
	// 1. Bootstrap cluster key (Epoch Key)
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	keyID := "key-1"

	key := ClusterKey{
		ID:        keyID,
		EncKey:    ek.Bytes(),
		DecKey:    nil, // DO NOT store private key in FSM
		CreatedAt: time.Now().Unix(),
	}

	// 2. Bootstrap cluster sign key
	csk, _ := crypto.GenerateIdentityKey()
	// Foundational keys must be encrypted with the FSM system key
	sk, err := raftNode.FSM.SystemKey()
	if err != nil {
		t.Fatalf("failed to get system key for bootstrap: %v", err)
	}
	encPriv, _ := crypto.EncryptDEM(sk, csk.MarshalPrivate())
	cskData := ClusterSignKey{
		Public:           csk.Public(),
		EncryptedPrivate: encPriv,
	}
	// 3. Server-specific keys (Identity + Decryption)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()

	// 4. Directly initialize state in FSM to avoid Raft deadlocks during bootstrap
	raftNode.FSM.db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("system"))
		raftNode.FSM.Put(tx, []byte("system"), []byte("epoch_key_"+keyID), MustMarshalJSON(key))
		raftNode.FSM.Put(tx, []byte("system"), []byte("active_epoch_key"), []byte(keyID))
		raftNode.FSM.Put(tx, []byte("system"), []byte("cluster_sign_key"), MustMarshalJSON(cskData))
		return nil
	})

	return ek, dk, csk, keyID, signKey, nodeDecKey
}

var (
	TestAdminID string
	TestAdminSK *crypto.IdentityKey
)

type TestCluster struct {
	Node          *RaftNode
	TS            *httptest.Server
	NodeSK        *crypto.IdentityKey
	ClusterSecret []byte
	Server        *Server
	AdminID       string
	AdminSK       *crypto.IdentityKey
	AdminDK       *mlkem.DecapsulationKey768
	EpochEK       []byte
	EpochID       string
}

func SetupCluster(t *testing.T) *TestCluster {
	return setupClusterInternal(t, true)
}

func SetupRawCluster(t *testing.T) *TestCluster {
	return setupClusterInternal(t, false)
}

func setupClusterInternal(t *testing.T, bootstrapBackbone bool) *TestCluster {
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

	// Bootstrap Keys
	ek, dk, _, keyID, signKey, nodeDecKey := BootstrapClusterKeys(t, node)

	WaitLeader(t, node.Raft)

	server := NewServer(nodeID, node.Raft, node.FSM, "", signKey, "testsecret", nil, 0, NewNodeVault(st), nodeDecKey, true)
	server.RegisterEpochKey(keyID, dk) // Register the bootstrapped key
	ts := httptest.NewServer(server)

	// Register the bootstrapped node in FSM
	fsm := node.FSM
	err = fsm.DB().Update(func(tx *bolt.Tx) error {
		buckets := []string{"users", "admins", "groups", "gids", "owner_groups", "inodes", "nodes", "system"}
		for _, b := range buckets {
			tx.CreateBucketIfNotExists([]byte(b))
		}

		fsm.Put(tx, []byte("admins"), []byte("system"), []byte("true"))

		// --- CRITICAL: Initialize Tier 2 Trust Anchor (KeyRing) ---
		fsm.Put(tx, []byte("system"), []byte("fsm_keyring"), node.FSM.GetFSMKeyRing())

		// Bootstrap World Identity
		wdk, _ := crypto.GenerateEncryptionKey()
		world := WorldIdentity{
			Public:  wdk.EncapsulationKey().Bytes(),
			Private: crypto.MarshalDecapsulationKey(wdk),
		}
		fsm.Put(tx, []byte("system"), []byte("world_identity"), MustMarshalJSON(world))
		return nil
	})
	if err != nil {
		t.Fatalf("Direct bootstrap failed: %v", err)
	}

	// --- Phase 69: Registry Backbone Bootstrapping ---
	adminID := node.FSM.ComputeUserID("alice")
	adminSK, _ := crypto.GenerateIdentityKey()
	adminDK, _ := crypto.GenerateEncryptionKey()

	if bootstrapBackbone {
		// 1. Provision Backbone (Groups + Directories) using Alice's signature
		// This also creates the admin user record in FSM
		BootstrapBackbone(t, node, adminID, adminDK, adminSK)
	} else {
		// Just create the admin user so we can login
		admin := User{
			ID:      adminID,
			UID:     1000,
			SignKey: adminSK.Public(),
			EncKey:  adminDK.EncapsulationKey().Bytes(),
		}
		admin.Signature = adminSK.Sign(admin.Hash())
		b, _ := json.Marshal(admin)
		cmd, _ := LogCommand{Type: CmdCreateUser, Data: b}.Marshal()
		if err := node.Raft.Apply(cmd, 5*time.Second).Error(); err != nil {
			t.Fatalf("Failed to create admin user: %v", err)
		}
		// Also mark as admin
		aid, _ := json.Marshal(adminID)
		acmd, _ := LogCommand{Type: CmdPromoteAdmin, Data: aid}.Marshal()
		if err := node.Raft.Apply(acmd, 5*time.Second).Error(); err != nil {
			t.Fatalf("Failed to promote admin: %v", err)
		}
	}

	t.Cleanup(func() {
		ts.Close()
		server.Shutdown()
		node.Shutdown()
	})

	return &TestCluster{
		Node:          node,
		TS:            ts,
		NodeSK:        signKey,
		ClusterSecret: clusterSecret,
		Server:        server,
		AdminID:       adminID,
		AdminSK:       adminSK,
		AdminDK:       adminDK,
		EpochEK:       ek.Bytes(),
		EpochID:       keyID,
	}
}

func LoginSessionForTest(t *testing.T, ts *httptest.Server, userID string, userSignKey *crypto.IdentityKey) string {
	token, _ := LoginSessionForTestWithSecret(t, ts, userID, userSignKey)
	return token
}

func LoginSessionForTestWithSecret(t *testing.T, ts *httptest.Server, userID string, userSignKey *crypto.IdentityKey) (string, []byte) {
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

	// 2. Solve Challenge + Ephemeral Key for Forward Secrecy
	sig := userSignKey.Sign(challengeRes.Challenge)

	// Phase 53.1: Ephemeral PQC-KEM for Forward Secret Session Key
	sessionDK, _ := crypto.GenerateEncryptionKey()

	solve := AuthChallengeSolve{
		UserID:    userID,
		Challenge: challengeRes.Challenge,
		Signature: sig,
		EncKey:    sessionDK.EncapsulationKey().Bytes(),
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

	// Phase 53.1: Derive Shared Secret for session
	var sharedSecret []byte
	if len(sessionRes.KEMCT) > 0 {
		sharedSecret, err = sessionDK.Decapsulate(sessionRes.KEMCT)
		if err != nil {
			t.Fatalf("failed to decapsulate session key: %v", err)
		}
	}

	return sessionRes.Token, sharedSecret
}

func SealTestRequestSymmetric(t *testing.T, userID string, userSignKey *crypto.IdentityKey, sessionKey []byte, payload []byte) []byte {
	// Reimplement logic from client.go sealBody symmetric path
	ts := time.Now().UnixNano()
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts))

	toSign := make([]byte, 8+len(payload))
	copy(toSign[0:8], tsBytes)
	copy(toSign[8:], payload)
	sig := userSignKey.Sign(toSign)

	sigSize := crypto.SignatureSize()
	inner := make([]byte, 8+sigSize+len(payload))
	copy(inner[0:8], tsBytes)
	copy(inner[8:8+sigSize], sig)
	copy(inner[8+sigSize:], payload)

	demCT, err := crypto.EncryptDEM(sessionKey, inner)
	if err != nil {
		t.Fatal(err)
	}

	kemSize := mlkem.CiphertextSize768
	dummyKEM := make([]byte, kemSize)
	rand.Read(dummyKEM)

	sealed := make([]byte, len(dummyKEM)+len(demCT))
	copy(sealed[0:len(dummyKEM)], dummyKEM)
	copy(sealed[len(dummyKEM):], demCT)

	sr := SealedRequest{
		UserID: userID,
		Sealed: sealed,
	}
	b, _ := json.Marshal(sr)
	return b
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

func JoinUsersGroup(t *testing.T, raftNode *RaftNode, groupID string, userID string, adminID string, adminSK *crypto.IdentityKey) {
	// 1. Fetch existing users group
	var g Group
	raftNode.FSM.db.View(func(tx *bolt.Tx) error {
		plain, _ := raftNode.FSM.Get(tx, []byte("groups"), []byte(groupID))
		return json.Unmarshal(plain, &g)
	})

	// 2. Add user
	var user User
	raftNode.FSM.db.View(func(tx *bolt.Tx) error {
		plain, _ := raftNode.FSM.Get(tx, []byte("users"), []byte(userID))
		return json.Unmarshal(plain, &user)
	})

	if g.Lockbox == nil {
		g.Lockbox = make(crypto.Lockbox)
	}

	// Also update Lockbox so the user can actually use the group
	upk, _ := crypto.UnmarshalEncapsulationKey(user.EncKey)

	// We need the group private keys to re-encrypt them for the new member
	// In tests, the admin has access to everything.
	// But wait, JoinUsersGroup doesn't have the group DK.
	// We stored it in 'system' bucket in BootstrapBackbone!
	var seed []byte
	raftNode.FSM.db.View(func(tx *bolt.Tx) error {
		seed, _ = raftNode.FSM.Get(tx, []byte("system"), []byte("test_users_seed"))
		return nil
	})

	target := ComputeMemberHMAC(g.ID, userID)
	g.Lockbox.AddRecipient(target, upk, seed, g.Epoch)

	g.Version++
	g.Nonce = GenerateNonce()
	g.SignerID = adminID
	g.Signature = adminSK.Sign(g.Hash())

	data, _ := json.Marshal(g)
	cmd := LogCommand{
		Type:   CmdUpdateGroup,
		Data:   data,
		UserID: adminID,
	}
	cb, _ := cmd.Marshal()
	if err := raftNode.Raft.Apply(cb, 10*time.Second).Error(); err != nil {
		t.Fatalf("JoinUsersGroup Apply failed: %v", err)
	}
}

func DumpFSM(raftNode *RaftNode) {
	fmt.Printf("\n--- FSM DUMP ---\n")
	raftNode.FSM.db.View(func(tx *bolt.Tx) error {
		// 1. Groups
		fmt.Printf("\n[Groups]\n")
		gb := []byte("groups")
		b := tx.Bucket(gb)
		if b != nil {
			b.ForEach(func(k, v []byte) error {
				plain, err := raftNode.FSM.DecryptValue(gb, v)
				if err != nil {
					fmt.Printf("ID: %s (ENCRYPTED)\n", string(k))
					return nil
				}
				var g Group
				json.Unmarshal(plain, &g)
				lbKeys := []string{}
				for lk, entry := range g.Lockbox {
					status := "KEM"
					if len(entry.KEMCiphertext) == 0 {
						status = "NO-KEM"
					}
					lbKeys = append(lbKeys, fmt.Sprintf("%s(%s)", lk, status))
				}
				fmt.Printf("ID: %s, GID: %d, Owner: %s, Signer: %s, Epoch: %d, Lockbox Size: %d, Recipients: %v\n", g.ID, g.GID, g.OwnerID, g.SignerID, g.Epoch, len(g.Lockbox), lbKeys)
				return nil
			})
		}

		// 2. Inodes
		fmt.Printf("\n[Inodes]\n")
		ib := []byte("inodes")
		b = tx.Bucket(ib)
		if b != nil {
			b.ForEach(func(k, v []byte) error {
				plain, err := raftNode.FSM.DecryptValue(ib, v)
				if err != nil {
					fmt.Printf("ID: %s (ENCRYPTED)\n", string(k))
					return nil
				}
				var i Inode
				json.Unmarshal(plain, &i)
				lbKeys := []string{}
				for lk := range i.Lockbox {
					lbKeys = append(lbKeys, lk)
				}
				// Try to get filename if possible (some inodes are rooted at /)
				name := "???"
				if len(i.Links) > 0 {
					for n := range i.Links {
						name = n
						break
					}
				}
				fmt.Printf("ID: %s, Name: %s, Type: %v, Owner: %s, Group: %s, Mode: %o, Lockbox Size: %d, Recipients: %v\n", i.ID, name, i.Type, i.OwnerID, i.GroupID, i.Mode, len(i.Lockbox), lbKeys)
				return nil
			})
		}
		return nil
	})
	fmt.Printf("--- END FSM DUMP ---\n\n")
}

// NewSealedTestRequest creates a sealed request to the /v1/invoke endpoint.
func NewSealedTestRequest(t *testing.T, tsURL, action string, payload interface{}, uid string, signKey *crypto.IdentityKey, ek []byte) *http.Request {
	var payloadBytes []byte
	if b, ok := payload.([]byte); ok {
		payloadBytes = b
	} else if payload != nil {
		payloadBytes, _ = json.Marshal(payload)
	}

	env := SealedEnvelope{
		Action:  action,
		Payload: payloadBytes,
	}
	envJSON, _ := json.Marshal(env)

	body, _ := SealTestRequestWithSecret(t, uid, signKey, ek, envJSON)
	req, _ := http.NewRequest("POST", tsURL+"/v1/invoke", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Content-Type", "application/json")
	return req
}

// NewSealedTestRequestSymmetric creates a sealed request using a symmetric session key.
func NewSealedTestRequestSymmetric(t *testing.T, tsURL, action string, payload interface{}, uid string, signKey *crypto.IdentityKey, sessionKey []byte) *http.Request {
	var payloadBytes []byte
	if b, ok := payload.([]byte); ok {
		payloadBytes = b
	} else if payload != nil {
		payloadBytes, _ = json.Marshal(payload)
	}

	env := SealedEnvelope{
		Action:  action,
		Payload: payloadBytes,
	}
	envJSON, _ := json.Marshal(env)

	body := SealTestRequestSymmetric(t, uid, signKey, sessionKey, envJSON)
	req, _ := http.NewRequest("POST", tsURL+"/v1/invoke", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Content-Type", "application/json")
	return req
}
