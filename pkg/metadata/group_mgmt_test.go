//go:build !wasm

package metadata

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestGroupManagementSecurity(t *testing.T) {
	tc := SetupCluster(t)

	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	// 1. Setup Users
	// Alice (Admin from SetupCluster)
	tokenAlice, secretAlice := LoginSessionForTestWithSecret(t, tc.TS, tc.AdminID, tc.AdminSK)

	// Bob (Helper/Member)
	uBobDec, _ := crypto.GenerateEncryptionKey()
	uBobSign, _ := crypto.GenerateIdentityKey()
	uBobID := tc.Node.FSM.ComputeUserID("bob")
	uBob := User{ID: uBobID, UID: 1002, SignKey: uBobSign.Public(), EncKey: uBobDec.EncapsulationKey().Bytes()}
	uBob.Locked = false // Ensure unlocked for testing
	CreateUser(t, tc.Node, uBob, uBobSign, tc.AdminID, tc.AdminSK)
	JoinUsersGroup(t, tc.Node, "users", uBobID, tc.AdminID, tc.AdminSK)

	// Mallory (Attacker/Non-Member)
	uMalloryDec, _ := crypto.GenerateEncryptionKey()
	uMallorySign, _ := crypto.GenerateIdentityKey()
	uMalloryID := tc.Node.FSM.ComputeUserID("mallory")
	uMallory := User{ID: uMalloryID, UID: 1003, SignKey: uMallorySign.Public(), EncKey: uMalloryDec.EncapsulationKey().Bytes()}
	uMallory.Locked = false // Ensure unlocked for testing
	CreateUser(t, tc.Node, uMallory, uMallorySign, tc.AdminID, tc.AdminSK)

	// 2. Alice creates Group A
	// Alice is the admin from SetupCluster
	nonceA := GenerateNonce()
	groupAID := GenerateGroupID(tc.AdminID, nonceA)
	groupA := Group{
		ID:       groupAID,
		OwnerID:  tc.AdminID,
		Nonce:    nonceA,
		SignerID: tc.AdminID,
		Version:  1,
		GID:      10001,
		Lockbox:  map[string]crypto.LockboxEntry{ComputeMemberHMAC(groupAID, tc.AdminID): {}},
		SignKey:  tc.AdminSK.Public(),
	}
	groupA.Signature = tc.AdminSK.Sign(groupA.Hash())
	objBytes, _ := json.Marshal(groupA)
	batch := []LogCommand{{Type: CmdCreateGroup, Data: objBytes, UserID: tc.AdminID}}
	payload, _ := json.Marshal(batch)
	body := SealTestRequestSymmetric(t, tc.AdminID, tc.AdminSK, secretAlice, payload)
	req, _ := http.NewRequest("POST", tc.TS.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Failed to create group A: got %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(body))
	}

	// Read the group with the generated ID from the response
	opened := UnsealTestResponseWithSession(t, tc.AdminDK, secretAlice, tc.NodeSK.Public(), resp)
	var results []json.RawMessage
	json.Unmarshal(opened, &results)
	var createdA Group
	json.Unmarshal(results[0], &createdA)
	resp.Body.Close()

	// 3. Mallory attempts to hijack Group A (Should fail)
	tokenMallory, secretMallory := LoginSessionForTestWithSecret(t, tc.TS, uMalloryID, uMallorySign)
	hijackA := createdA
	hijackA.OwnerID = uMalloryID // Immutable check should catch this
	hijackA.Nonce = GenerateNonce()
	hijackA.SignGroupForTest(uMalloryID, uMallorySign)

	objBytes, _ = json.Marshal(hijackA)
	batch = []LogCommand{{Type: CmdUpdateGroup, Data: objBytes, UserID: uMalloryID}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequestSymmetric(t, uMalloryID, uMallorySign, secretMallory, payload)
	req, _ = http.NewRequest("POST", tc.TS.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenMallory)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("Expected failure for hijacking immutable group owner, got 200")
	}

	// 4. Self-Managed Group Test
	nonceSelf := GenerateNonce()
	gSelfID := GenerateGroupID(SelfOwnedGroup, nonceSelf)
	gSelf := Group{
		ID:       gSelfID,
		OwnerID:  SelfOwnedGroup,
		SignerID: tc.AdminID,
		Nonce:    nonceSelf,
		Version:  1,
		GID:      10002,
		Lockbox:  map[string]crypto.LockboxEntry{ComputeMemberHMAC(gSelfID, tc.AdminID): {}},
		SignKey:  tc.AdminSK.Public(),
	}
	gSelf.Signature = tc.AdminSK.Sign(gSelf.Hash())
	objBytes, _ = json.Marshal(gSelf)
	batch = []LogCommand{{Type: CmdCreateGroup, Data: objBytes, UserID: tc.AdminID}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequestSymmetric(t, tc.AdminID, tc.AdminSK, secretAlice, payload)
	req, _ = http.NewRequest("POST", tc.TS.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenAlice)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to create self-managed group: %d", resp.StatusCode)
	}

	// Update Bob to be a member of Group Self
	err := tc.Node.FSM.db.Update(func(tx *bolt.Tx) error {
		plain, err := tc.Node.FSM.Get(tx, []byte("groups"), []byte(gSelfID))
		if err != nil {
			return err
		}
		var g Group
		json.Unmarshal(plain, &g)
		if g.Lockbox == nil {
			g.Lockbox = make(crypto.Lockbox)
		}
		target := ComputeMemberHMAC(g.ID, uBobID)
		g.Lockbox[target] = crypto.LockboxEntry{}
		encoded, _ := json.Marshal(g)
		return tc.Node.FSM.Put(tx, []byte("groups"), []byte(gSelfID), encoded)
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Bob (Member) attempts to update self-managed Group (Should succeed)
	tokenBob, secretBob := LoginSessionForTestWithSecret(t, tc.TS, uBobID, uBobSign)

	// Refresh
	req, _ = http.NewRequest("GET", tc.TS.URL+"/v1/group/"+gSelfID, nil)
	req.Header.Set("Session-Token", tokenBob)
	resp, _ = http.DefaultClient.Do(req)
	var gSelfRefreshed Group
	json.NewDecoder(resp.Body).Decode(&gSelfRefreshed)
	resp.Body.Close()

	bobUpdate := gSelfRefreshed
	if bobUpdate.Lockbox == nil {
		bobUpdate.Lockbox = make(crypto.Lockbox)
	}
	targetMallory := ComputeMemberHMAC(bobUpdate.ID, uMalloryID)
	bobUpdate.Lockbox[targetMallory] = crypto.LockboxEntry{}
	bobUpdate.Version++
	bobUpdate.SignGroupForTest(uBobID, uBobSign)

	objBytes, _ = json.Marshal(bobUpdate)
	batch = []LogCommand{{Type: CmdUpdateGroup, Data: objBytes, UserID: uBobID}}
	payload, _ = json.Marshal(batch)
	body = SealTestRequestSymmetric(t, uBobID, uBobSign, secretBob, payload)
	req, _ = http.NewRequest("POST", tc.TS.URL+"/v1/meta/batch", bytes.NewReader(body))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Session-Token", tokenBob)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected 200 for Bob updating self-managed group, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestGroupQuotaEnforcement(t *testing.T) {
	tc := SetupCluster(t)
	defer tc.Server.Shutdown()
	defer tc.Node.Shutdown()
	defer tc.TS.Close()

	userID := tc.Node.FSM.ComputeUserID("alice-quota")
	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: userID, UID: 1001, SignKey: sk.Public()}, sk, tc.AdminID, tc.AdminSK)

	// Bootstrap Admin (already done by SetupCluster for tc.AdminID, but let's make userID an admin for this test if needed, or just use tc.AdminID)
	// Actually, tc.AdminID is derived from "alice".

	// 1. Create Group G1
	nonceG1 := GenerateNonce()
	groupID := GenerateGroupID(userID, nonceG1)
	g1 := Group{ID: groupID, OwnerID: userID, Nonce: nonceG1, GID: 5001, Version: 1, QuotaEnabled: true, SignerID: userID, SignKey: sk.Public()}
	g1.SignGroupForTest(userID, sk)
	g1Bytes, _ := json.Marshal(g1)
	gCmd, err := LogCommand{Type: CmdCreateGroup, Data: g1Bytes, UserID: userID}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.Node.Raft.Apply(gCmd, 5*time.Second).Error(); err != nil {
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
	qCmd, err := LogCommand{Type: CmdSetGroupQuota, Data: qBytes, UserID: tc.AdminID}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.Node.Raft.Apply(qCmd, 5*time.Second).Error(); err != nil {
		t.Fatalf("Set group quota failed: %v", err)
	}

	// 3. Create Inode 1 in Group G1 (OK)
	nonce1 := make([]byte, 16)
	rand.Read(nonce1)
	id1 := GenerateInodeID(userID, nonce1)
	inode1 := Inode{ID: id1, Nonce: nonce1, OwnerID: userID, GroupID: groupID, Size: 100, Type: FileType, Mode: 0644}
	inode1.SignInodeForTest(userID, sk)
	i1Bytes, _ := json.Marshal(inode1)
	iCmd, err := LogCommand{Type: CmdCreateInode, Data: i1Bytes, UserID: userID}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.Node.Raft.Apply(iCmd, 5*time.Second).Error(); err != nil {
		t.Fatalf("Create file 1 failed: %v", err)
	}

	// 4. Create Inode 2 in Group G1 (Fail: Group Inode Quota)
	nonce2 := make([]byte, 16)
	rand.Read(nonce2)
	id2 := GenerateInodeID(userID, nonce2)
	inode2 := Inode{ID: id2, Nonce: nonce2, OwnerID: userID, GroupID: groupID, Size: 100, Type: FileType, Mode: 0644}
	inode2.SignInodeForTest(userID, sk)
	i2Bytes, _ := json.Marshal(inode2)
	iCmd, err = LogCommand{Type: CmdCreateInode, Data: i2Bytes, UserID: userID}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f := tc.Node.Raft.Apply(iCmd, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Raft apply failed: %v", err)
	}
	if err, ok := f.Response().(error); !ok || !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded, got %v", f.Response())
	}
}
