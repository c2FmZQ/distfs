package metadata

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestGroupManagementSecurity(t *testing.T) {
	node, ts, serverSignKey, serverEK, srv := SetupCluster(t)
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setup Users
	// Alice (Victim/Owner)
	uAliceDec, _ := crypto.GenerateEncryptionKey()
	uAliceSign, _ := crypto.GenerateIdentityKey()
	uAlice := User{ID: "alice", UID: 1001, SignKey: uAliceSign.Public(), EncKey: uAliceDec.EncapsulationKey().Bytes()}
	CreateUser(t, node, uAlice)

	// Bob (Helper/Member)
	uBobDec, _ := crypto.GenerateEncryptionKey()
	uBobSign, _ := crypto.GenerateIdentityKey()
	uBob := User{ID: "bob", UID: 1002, SignKey: uBobSign.Public(), EncKey: uBobDec.EncapsulationKey().Bytes()}
	CreateUser(t, node, uBob)

	// Mallory (Attacker/Non-Member)
	uMalloryDec, _ := crypto.GenerateEncryptionKey()
	uMallorySign, _ := crypto.GenerateIdentityKey()
	uMallory := User{ID: "mallory", UID: 1003, SignKey: uMallorySign.Public(), EncKey: uMalloryDec.EncapsulationKey().Bytes()}
	CreateUser(t, node, uMallory)

	// 2. Alice creates Group A
	tokenAlice, secretAlice := LoginSessionForTestWithSecret(t, ts, "alice", uAliceSign)
	groupA := Group{
		ID:       "group-a",
		OwnerID:  "alice",
		SignerID: "alice",
		Members:  map[string]bool{"alice": true},
		Version:  1,
		GID:      10001,
		Lockbox:  crypto.NewLockbox(),
	}
	groupA.Signature = uAliceSign.Sign(groupA.Hash())
	objBytes, _ := json.Marshal(groupA)
	batch := []LogCommand{{Type: CmdCreateGroup, Data: objBytes}}
	payload, _ := json.Marshal(batch)
	body := SealTestRequestSymmetric(t, "alice", uAliceSign, secretAlice, payload)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to create group A: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Read the group with the generated ID from the response
	opened := UnsealTestResponseWithSession(t, uAliceDec, secretAlice, serverSignKey.Public(), resp)
	var results []json.RawMessage
	json.Unmarshal(opened, &results)
	var createdA Group
	json.Unmarshal(results[0], &createdA)
	resp.Body.Close()
	groupID := createdA.ID

	// 3. Mallory attempts to hijack Group A (Should fail)
	tokenMallory, secretMallory := LoginSessionForTestWithSecret(t, ts, "mallory", uMallorySign)
	hijackA := createdA
	hijackA.OwnerID = "mallory"
	hijackA.SignGroupForTest("mallory", uMallorySign)

	objBytes, _ = json.Marshal(hijackA)
	batch = []LogCommand{{Type: CmdUpdateGroup, Data: objBytes}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequestSymmetric(t, "mallory", uMallorySign, secretMallory, payload)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenMallory)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for unauthorized group update, got %d", resp.StatusCode)
	}

	// 4. Self-Managed Group Test
	// Alice makes Group A self-managed (OwnerID = GroupID)
	selfManagedA := createdA
	selfManagedA.OwnerID = groupID
	selfManagedA.Version++ // Must increment version for update
	selfManagedA.SignGroupForTest("alice", uAliceSign)

	objBytes, _ = json.Marshal(selfManagedA)
	batch = []LogCommand{{Type: CmdUpdateGroup, Data: objBytes}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequestSymmetric(t, "alice", uAliceSign, secretAlice, payload)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to make group self-managed: %d", resp.StatusCode)
	}

	// Update Bob to be a member of Group A
	err := node.FSM.db.Update(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("groups"), []byte(groupID))
		if err != nil {
			return err
		}
		var g Group
		json.Unmarshal(plain, &g)
		if g.Members == nil {
			g.Members = make(map[string]bool)
		}
		g.Members["bob"] = true
		encoded, _ := json.Marshal(g)

		// Update the indices since we are bypassing the FSM pipeline
		mb := tx.Bucket([]byte("user_memberships"))
		sub, _ := mb.CreateBucketIfNotExists([]byte("bob"))
		encOne, _ := node.FSM.EncryptValue([]byte("user_memberships"), []byte("1"))
		sub.Put([]byte(groupID), encOne)

		return node.FSM.Put(tx, []byte("groups"), []byte(groupID), encoded)
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Bob (Member) attempts to update self-managed Group A (Should succeed)
	tokenBob, secretBob := LoginSessionForTestWithSecret(t, ts, "bob", uBobSign)

	// Refresh gA
	req, _ = http.NewRequest("GET", ts.URL+"/v1/group/"+groupID, nil)
	req.Header.Set("Session-Token", tokenBob)
	resp, _ = http.DefaultClient.Do(req)
	var gA Group
	json.NewDecoder(resp.Body).Decode(&gA)
	resp.Body.Close()

	bobUpdate := gA
	if bobUpdate.Members == nil {
		bobUpdate.Members = make(map[string]bool)
	}
	bobUpdate.Members["mallory"] = true // Bob adds mallory
	bobUpdate.Version++
	bobUpdate.SignGroupForTest("bob", uBobSign)

	objBytes, _ = json.Marshal(bobUpdate)
	batch = []LogCommand{{Type: CmdUpdateGroup, Data: objBytes}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequestSymmetric(t, "bob", uBobSign, secretBob, payload)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenBob)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for Bob updating self-managed group, got %d", resp.StatusCode)
	}

	// 6. Delegated Management Test (Group B owns Group C)
	// Alice creates Group B
	groupB := Group{ID: "group-b", OwnerID: "alice", GID: 10002, Lockbox: crypto.NewLockbox()}
	groupB.Version = 1
	bBytes, _ := json.Marshal(groupB)
	// Direct apply to force specific IDs for B and C
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: bBytes, UserID: "alice"}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Apply group B failed: %v", err)
	}

	// Alice creates Group C owned by Group B
	groupC := Group{ID: "group-c", OwnerID: "group-b", GID: 10003, Lockbox: crypto.NewLockbox()}
	groupC.Version = 1
	cBytes, _ := json.Marshal(groupC)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: cBytes, UserID: "alice"}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Apply group C failed: %v", err)
	}

	// Make Bob member of Group B
	err = node.FSM.db.Update(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("groups"), []byte("group-b"))
		if err != nil {
			return err
		}
		var g Group
		json.Unmarshal(plain, &g)
		if g.Members == nil {
			g.Members = make(map[string]bool)
		}
		g.Members["bob"] = true
		encoded, _ := json.Marshal(g)

		// Update the indices since we are bypassing the FSM pipeline
		mb := tx.Bucket([]byte("user_memberships"))
		sub, _ := mb.CreateBucketIfNotExists([]byte("bob"))
		encOne, _ := node.FSM.EncryptValue([]byte("user_memberships"), []byte("1"))
		sub.Put([]byte("group-b"), encOne)

		return node.FSM.Put(tx, []byte("groups"), []byte("group-b"), encoded)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Bob (Member of B) attempts to update Group C (owned by B) (Should succeed)
	req, _ = http.NewRequest("GET", ts.URL+"/v1/group/group-c", nil)
	req.Header.Set("Session-Token", tokenBob)
	resp, _ = http.DefaultClient.Do(req)
	var gC Group
	json.NewDecoder(resp.Body).Decode(&gC)
	resp.Body.Close()

	bobUpdateC := gC
	bobUpdateC.GID = 10099 // Bob changes GID
	bobUpdateC.Version++
	bobUpdateC.SignGroupForTest("bob", uBobSign)

	objBytes, _ = json.Marshal(bobUpdateC)
	batch = []LogCommand{{Type: CmdUpdateGroup, Data: objBytes}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequest(t, "bob", uBobSign, serverEK, payload)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenBob)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for Bob updating delegated group C, got %d", resp.StatusCode)
	}

	// Mallory (Non-member of B) attempts to update Group C (Should fail)
	malloryUpdateC := gC
	malloryUpdateC.Version++ // Try to bypass version check
	malloryUpdateC.SignGroupForTest("mallory", uMallorySign)

	objBytes, _ = json.Marshal(malloryUpdateC)
	batch = []LogCommand{{Type: CmdUpdateGroup, Data: objBytes}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequest(t, "mallory", uMallorySign, serverEK, payload)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenMallory)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for Mallory updating delegated group C, got %d", resp.StatusCode)
	}
}

func TestGroupQuotaEnforcement(t *testing.T) {
	node, ts, _, _, srv := SetupCluster(t)
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	userID := "alice"
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: userID, UID: 1001, SignKey: sk.Public()})

	// 1. Create Group G1
	groupID := "g1"
	g1 := Group{ID: groupID, OwnerID: userID, GID: 5001, Version: 1, QuotaEnabled: true}
	g1Bytes, _ := json.Marshal(g1)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: g1Bytes, UserID: "alice"}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Create group failed: %v", err)
	}

	// 2. Set Group Quota (1 Inode, 500 Bytes)
	maxInodes := uint64(1)
	maxBytes := uint64(500)
	qReq := SetGroupQuotaRequest{
		GroupID:   groupID,
		MaxBytes:  &maxBytes,
		MaxInodes: &maxInodes,
	}
	qBytes, _ := json.Marshal(qReq)
	if err := node.Raft.Apply(LogCommand{Type: CmdSetGroupQuota, Data: qBytes, UserID: "admin"}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Set group quota failed: %v", err)
	}

	// 3. Create Inode 1 in Group G1 (OK)
	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := GenerateInodeID(userID, nonce1)
	inode1 := Inode{ID: id1, Nonce: nonce1, OwnerID: userID, GroupID: groupID, Size: 100, Type: FileType, Mode: 0644}
	inode1.SignInodeForTest(userID, sk)
	i1Bytes, _ := json.Marshal(inode1)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i1Bytes, UserID: userID}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Create file 1 failed: %v", err)
	}

	// 4. Create Inode 2 in Group G1 (Fail: Group Inode Quota)
	nonce2 := make([]byte, 16)
	rand.Read(nonce2)
	id2 := GenerateInodeID(userID, nonce2)
	inode2 := Inode{ID: id2, Nonce: nonce2, OwnerID: userID, GroupID: groupID, Size: 100, Type: FileType, Mode: 0644}
	inode2.SignInodeForTest(userID, sk)
	i2Bytes, _ := json.Marshal(inode2)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i2Bytes, UserID: userID}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %v", f.Response())
	}

	// 5. Increase Quota, but fail storage (2 Inodes, 150 Bytes)
	maxInodes = 2
	maxBytes = 150
	qReq.MaxInodes = &maxInodes
	qReq.MaxBytes = &maxBytes
	qBytes, _ = json.Marshal(qReq)
	if err := node.Raft.Apply(LogCommand{Type: CmdSetGroupQuota, Data: qBytes, UserID: "admin"}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	inode2.SignInodeForTest(userID, sk)
	i2Bytes = marshalInode(t, inode2)
	f = node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i2Bytes, UserID: userID}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %v", f.Response())
	}
}

func TestGroupQuotaFallback(t *testing.T) {
	node, ts, _, _, srv := SetupCluster(t)
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	userID := "alice"
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: userID, UID: 1001, SignKey: sk.Public()})

	// 1. Create Group G1 with NO quota
	groupID := "g1"
	g1 := Group{ID: groupID, OwnerID: userID, GID: 5001, Version: 1}
	g1Bytes, _ := json.Marshal(g1)
	node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: g1Bytes, UserID: "alice"}.Marshal(), 5*time.Second)

	// 2. Set Alice Quota to 1 Inode
	maxInodesFallback := uint64(1)
	uReq := SetUserQuotaRequest{UserID: userID, MaxInodes: &maxInodesFallback}
	uReqBytes, _ := json.Marshal(uReq)
	node.Raft.Apply(LogCommand{Type: CmdSetUserQuota, Data: uReqBytes, UserID: "alice"}.Marshal(), 5*time.Second)

	// 3. Create Inode 1 in Group G1 (OK - falls back to Alice quota 0->1)
	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := GenerateInodeID(userID, nonce1)
	inode1 := Inode{ID: id1, Nonce: nonce1, OwnerID: userID, GroupID: groupID, Size: 100, Type: FileType, Mode: 0644}
	inode1.SignInodeForTest(userID, sk)
	i1Bytes := marshalInode(t, inode1)
	f1 := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i1Bytes, UserID: userID}.Marshal(), 5*time.Second)
	if err := f1.Error(); err != nil {
		t.Fatalf("Raft apply file 1 failed: %v", err)
	}
	if err, ok := f1.Response().(error); ok && err != nil {
		t.Fatalf("Create file 1 fallback failed: %v", err)
	}

	// Verify Alice usage is now 1
	var user User
	node.FSM.db.View(func(tx *bolt.Tx) error {
		plain, _ := node.FSM.Get(tx, []byte("users"), []byte(userID))
		json.Unmarshal(plain, &user)
		return nil
	})
	if user.Usage.InodeCount != 1 {
		t.Errorf("Expected Alice usage 1, got %d", user.Usage.InodeCount)
	}

	// 4. Create Inode 2 in Group G1 (Fail - Alice quota 1->2 > 1)
	nonce2 := make([]byte, 16)
	rand.Read(nonce2)
	id2 := GenerateInodeID(userID, nonce2)
	inode2 := Inode{ID: id2, Nonce: nonce2, OwnerID: userID, GroupID: groupID, Size: 100, Type: FileType, Mode: 0644}
	inode2.SignInodeForTest(userID, sk)
	i2Bytes := marshalInode(t, inode2)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i2Bytes, UserID: userID}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply file 2 failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %v", f.Response())
	}
}

func marshalInode(t *testing.T, i Inode) []byte {
	b, err := json.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGroupQuotaBypassReproduction(t *testing.T) {
	node, ts, _, _, srv := SetupCluster(t)
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	userID := "alice"
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: userID, UID: 1001, SignKey: sk.Public()})

	// 1. Set User Byte Quota (500 Bytes)
	maxBytes := uint64(500)
	uReq := SetUserQuotaRequest{UserID: userID, MaxBytes: &maxBytes}
	uReqBytes, _ := json.Marshal(uReq)
	node.Raft.Apply(LogCommand{Type: CmdSetUserQuota, Data: uReqBytes, UserID: "alice"}.Marshal(), 5*time.Second)

	// 2. Create Group G1 with Inode Quota (10) but NO Byte Quota (0)
	groupID := "g1"
	maxInodes := uint64(10)
	g1 := Group{ID: groupID, OwnerID: userID, GID: 5001, Version: 1, QuotaEnabled: true}
	g1Bytes, _ := json.Marshal(g1)
	node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: g1Bytes, UserID: "alice"}.Marshal(), 5*time.Second)

	qReq := SetGroupQuotaRequest{
		GroupID:   groupID,
		MaxInodes: &maxInodes,
	}
	qReqBytes, _ := json.Marshal(qReq)
	node.Raft.Apply(LogCommand{Type: CmdSetGroupQuota, Data: qReqBytes}.Marshal(), 5*time.Second)

	// 3. Alice uploads 600 Byte file to Group G1.
	// Architectural Decision: When a group has QuotaEnabled=true, we ONLY check the group quota.
	// Alice's personal 500 byte limit does NOT apply to group-charged storage.
	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := GenerateInodeID(userID, nonce1)
	inode := Inode{ID: id1, Nonce: nonce1, OwnerID: userID, GroupID: groupID, Size: 600, Type: FileType, Mode: 0644}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: inodeBytes, UserID: userID}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	res := f.Response()
	if _, ok := res.(*Inode); !ok {
		t.Errorf("Expected success (group quota is independent), got %T: %v", res, res)
	}
}

func TestSetQuotaOnDisabledGroup(t *testing.T) {
	node, ts, _, _, srv := SetupCluster(t)
	defer srv.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	userID := "alice"
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: userID, UID: 1001, SignKey: sk.Public()})

	// 1. Create Group G1 with QuotaEnabled: false
	groupID := "g1"
	g1 := Group{ID: groupID, OwnerID: userID, GID: 5001, Version: 1, QuotaEnabled: false}
	g1Bytes, _ := json.Marshal(g1)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: g1Bytes, UserID: "alice"}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Create group failed: %v", err)
	}

	// 2. Attempt to Set Group Quota (Should Fail)
	maxInodes := uint64(10)
	qReq := SetGroupQuotaRequest{
		GroupID:   groupID,
		MaxInodes: &maxInodes,
	}
	qBytes, _ := json.Marshal(qReq)
	f := node.Raft.Apply(LogCommand{Type: CmdSetGroupQuota, Data: qBytes, UserID: "admin"}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || !errors.Is(err, ErrQuotaDisabled) {
		t.Errorf("Expected ErrQuotaDisabled, got %v", f.Response())
	}
}
