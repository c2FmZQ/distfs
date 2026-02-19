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
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(groupID))
		var g Group
		json.Unmarshal(v, &g)
		if g.Members == nil {
			g.Members = make(map[string]bool)
		}
		g.Members["bob"] = true
		encoded, _ := json.Marshal(g)
		return b.Put([]byte(groupID), encoded)
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
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte("group-b"))
		var g Group
		json.Unmarshal(v, &g)
		if g.Members == nil {
			g.Members = make(map[string]bool)
		}
		g.Members["bob"] = true
		encoded, _ := json.Marshal(g)
		return b.Put([]byte("group-b"), encoded)
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
