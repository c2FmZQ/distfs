package metadata

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestGroupManagementSecurity(t *testing.T) {
	node, ts, _, serverEK, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Initialize Cluster Secret (needed for Group ID hashing)
	secret := make([]byte, 32)
	rand.Read(secret)
	fSecret := node.Raft.Apply(LogCommand{Type: CmdInitSecret, Data: secret}.Marshal(), 5*time.Second)
	if err := fSecret.Error(); err != nil {
		t.Fatalf("Failed to init secret: %v", err)
	}

	// 1. Setup Users
	// Alice (Victim/Owner)
	uAliceSign, _ := crypto.GenerateIdentityKey()
	uAlice := User{ID: "alice", SignKey: uAliceSign.Public()}
	CreateUser(t, node, uAlice)

	// Bob (Helper/Member)
	uBobSign, _ := crypto.GenerateIdentityKey()
	uBob := User{ID: "bob", SignKey: uBobSign.Public()}
	CreateUser(t, node, uBob)

	// Mallory (Attacker/Non-Member)
	uMallorySign, _ := crypto.GenerateIdentityKey()
	uMallory := User{ID: "mallory", SignKey: uMallorySign.Public()}
	CreateUser(t, node, uMallory)

	// 2. Alice creates Group A
	tokenAlice := loginSession(t, ts, "alice", uAliceSign)
	groupA := Group{
		ID:      "group-a",
		OwnerID: "alice",
		GID:     10001,
		Lockbox: crypto.NewLockbox(),
	}
	payload, _ := json.Marshal(groupA)
	body := sealTestRequest(t, "alice", uAliceSign, serverEK, payload)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/group/", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create group A: %d", resp.StatusCode)
	}

	// Read the group with the generated ID from the response
	var createdA Group
	respBytes, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBytes, &createdA)
	resp.Body.Close()
	groupID := createdA.ID

	// 3. Mallory attempts to hijack Group A (Should fail)
	tokenMallory := loginSession(t, ts, "mallory", uMallorySign)
	hijackA := createdA
	hijackA.OwnerID = "mallory"
	hijackA.SignGroupForTest("mallory", uMallorySign)

	payload, _ = json.Marshal(hijackA)
	body = sealTestRequest(t, "mallory", uMallorySign, serverEK, payload)
	req, _ = http.NewRequest("PUT", ts.URL+"/v1/group/"+groupID, bytes.NewReader(body))
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
	selfManagedA.SignGroupForTest("alice", uAliceSign)

	payload, _ = json.Marshal(selfManagedA)
	body = sealTestRequest(t, "alice", uAliceSign, serverEK, payload)
	req, _ = http.NewRequest("PUT", ts.URL+"/v1/group/"+groupID, bytes.NewReader(body))
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
		return node.FSM.Put(tx, []byte("groups"), []byte(groupID), encoded)
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Bob (Member) attempts to update self-managed Group A (Should succeed)
	tokenBob := loginSession(t, ts, "bob", uBobSign)

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
	bobUpdate.Members["carol"] = true // Bob adds Carol
	bobUpdate.SignGroupForTest("bob", uBobSign)

	payload, _ = json.Marshal(bobUpdate)
	body = sealTestRequest(t, "bob", uBobSign, serverEK, payload)
	req, _ = http.NewRequest("PUT", ts.URL+"/v1/group/"+groupID, bytes.NewReader(body))
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
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: bBytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Apply group B failed: %v", err)
	}

	// Alice creates Group C owned by Group B
	groupC := Group{ID: "group-c", OwnerID: "group-b", GID: 10003, Lockbox: crypto.NewLockbox()}
	groupC.Version = 1
	cBytes, _ := json.Marshal(groupC)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: cBytes}.Marshal(), 5*time.Second).Error(); err != nil {
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
	bobUpdateC.SignGroupForTest("bob", uBobSign)

	payload, _ = json.Marshal(bobUpdateC)
	body = sealTestRequest(t, "bob", uBobSign, serverEK, payload)
	req, _ = http.NewRequest("PUT", ts.URL+"/v1/group/group-c", bytes.NewReader(body))
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

	payload, _ = json.Marshal(malloryUpdateC)
	body = sealTestRequest(t, "mallory", uMallorySign, serverEK, payload)
	req, _ = http.NewRequest("PUT", ts.URL+"/v1/group/group-c", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenMallory)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for Mallory updating delegated group C, got %d", resp.StatusCode)
	}
}

func TestGroupQuotaEnforcement(t *testing.T) {
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	userID := "alice"
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: userID, SignKey: sk.Public()})

	// 1. Create Group G1
	groupID := "g1"
	g1 := Group{ID: groupID, OwnerID: userID, GID: 5001, Version: 1}
	g1Bytes, _ := json.Marshal(g1)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: g1Bytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Create group failed: %v", err)
	}

	// 2. Set Group Quota (1 Inode, 500 Bytes)
	maxInodes := int64(1)
	maxBytes := int64(500)
	qReq := SetGroupQuotaRequest{
		GroupID:   groupID,
		MaxBytes:  &maxBytes,
		MaxInodes: &maxInodes,
	}
	qBytes, _ := json.Marshal(qReq)
	if err := node.Raft.Apply(LogCommand{Type: CmdSetGroupQuota, Data: qBytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Set group quota failed: %v", err)
	}

	// 3. Create Inode 1 in Group G1 (OK)
	inode1 := Inode{ID: "f1", OwnerID: userID, GroupID: groupID, Size: 100}
	inode1.SignInodeForTest(userID, sk)
	i1Bytes, _ := json.Marshal(inode1)
	if err := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i1Bytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatalf("Create file 1 failed: %v", err)
	}

	// 4. Create Inode 2 in Group G1 (Fail: Group Inode Quota)
	inode2 := Inode{ID: "f2", OwnerID: userID, GroupID: groupID, Size: 100}
	inode2.SignInodeForTest(userID, sk)
	i2Bytes, _ := json.Marshal(inode2)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i2Bytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || err.Error() != "group inode quota exceeded" {
		t.Errorf("Expected group inode quota exceeded, got %v", f.Response())
	}

	// 5. Increase Quota, but fail storage (2 Inodes, 150 Bytes)
	maxInodes = 2
	maxBytes = 150
	qReq.MaxInodes = &maxInodes
	qReq.MaxBytes = &maxBytes
	qBytes, _ = json.Marshal(qReq)
	if err := node.Raft.Apply(LogCommand{Type: CmdSetGroupQuota, Data: qBytes}.Marshal(), 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	inode2.SignInodeForTest(userID, sk)
	i2Bytes = marshalInode(t, inode2)
	f = node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i2Bytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || err.Error() != "group storage quota exceeded" {
		t.Errorf("Expected group storage quota exceeded, got %v", f.Response())
	}
}

func TestGroupQuotaFallback(t *testing.T) {
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	userID := "alice"
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: userID, SignKey: sk.Public()})

	// 1. Create Group G1 with NO quota
	groupID := "g1"
	g1 := Group{ID: groupID, OwnerID: userID, GID: 5001, Version: 1}
	g1Bytes, _ := json.Marshal(g1)
	node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: g1Bytes}.Marshal(), 5*time.Second)

	// 2. Set Alice Quota to 1 Inode
	maxInodes := int64(1)
	uReq := SetUserQuotaRequest{UserID: userID, MaxInodes: &maxInodes}
	uReqBytes, _ := json.Marshal(uReq)
	node.Raft.Apply(LogCommand{Type: CmdSetUserQuota, Data: uReqBytes}.Marshal(), 5*time.Second)

	// 3. Create Inode 1 in Group G1 (OK - falls back to Alice quota 0->1)
	inode1 := Inode{ID: "f1", OwnerID: userID, GroupID: groupID, Size: 100}
	inode1.SignInodeForTest(userID, sk)
	i1Bytes := marshalInode(t, inode1)
	f1 := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i1Bytes}.Marshal(), 5*time.Second)
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
	inode2 := Inode{ID: "f2", OwnerID: userID, GroupID: groupID, Size: 100}
	inode2.SignInodeForTest(userID, sk)
	i2Bytes := marshalInode(t, inode2)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: i2Bytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply file 2 failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || err.Error() != "user inode quota exceeded" {
		t.Errorf("Expected user inode quota exceeded, got %v", f.Response())
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
	node, ts, _, _, _ := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	userID := "alice"
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, node, User{ID: userID, SignKey: sk.Public()})

	// 1. Set User Byte Quota (500 Bytes)
	maxBytes := int64(500)
	uReq := SetUserQuotaRequest{UserID: userID, MaxBytes: &maxBytes}
	uReqBytes, _ := json.Marshal(uReq)
	node.Raft.Apply(LogCommand{Type: CmdSetUserQuota, Data: uReqBytes}.Marshal(), 5*time.Second)

	// 2. Create Group G1 with Inode Quota (10) but NO Byte Quota (0)
	groupID := "g1"
	maxInodes := int64(10)
	g1 := Group{ID: groupID, OwnerID: userID, GID: 5001, Version: 1}
	g1Bytes, _ := json.Marshal(g1)
	node.Raft.Apply(LogCommand{Type: CmdCreateGroup, Data: g1Bytes}.Marshal(), 5*time.Second)

	qReq := SetGroupQuotaRequest{
		GroupID:   groupID,
		MaxInodes: &maxInodes,
	}
	qReqBytes, _ := json.Marshal(qReq)
	node.Raft.Apply(LogCommand{Type: CmdSetGroupQuota, Data: qReqBytes}.Marshal(), 5*time.Second)

	// 3. Alice uploads 600 Byte file to Group G1.
	// Current BUG: Because Group has a quota (Inodes), checkQuota returns nil early.
	// Expected: Should fail because 600 > User's 500 Byte quota.
	inode := Inode{ID: "f1", OwnerID: userID, GroupID: groupID, Size: 600}
	inode.SignInodeForTest(userID, sk)
	inodeBytes, _ := json.Marshal(inode)
	f := node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: inodeBytes}.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatal(err)
	}
	if err, ok := f.Response().(error); !ok || err.Error() != "user storage quota exceeded" {
		t.Errorf("Expected user storage quota exceeded (bypass attempt), got %v", f.Response())
	}
}
