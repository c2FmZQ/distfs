// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestDashboard_UsersNodes(t *testing.T) {
	node, ts, _, _, _ := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Add a user and a node via Raft
	user := User{ID: "dash-u1"}
	userBytes, _ := json.Marshal(user)
	node.Raft.Apply(LogCommand{Type: CmdCreateUser, Data: userBytes}.Marshal(), 5*time.Second)

	n := Node{ID: "dash-n1", Address: "1.2.3.4"}
	nBytes, _ := json.Marshal(n)
	node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: nBytes}.Marshal(), 5*time.Second)

	time.Sleep(1 * time.Second)

	// 2. GET /api/cluster/users
	req, _ := http.NewRequest("GET", ts.URL+"/api/cluster/users", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET users failed: %v, status %d", err, resp.StatusCode)
	}
	var users []User
	json.NewDecoder(resp.Body).Decode(&users)
	found := false
	for _, u := range users {
		if u.ID == "dash-u1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("dash-u1 not found")
	}

	// 3. GET /api/cluster/nodes
	req, _ = http.NewRequest("GET", ts.URL+"/api/cluster/nodes", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, _ = http.DefaultClient.Do(req)
	var nodes []Node
	json.NewDecoder(resp.Body).Decode(&nodes)
	found = false
	for _, nd := range nodes {
		if nd.ID == "dash-n1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("dash-n1 not found")
	}
}

func TestDashboard_Lookup(t *testing.T) {
	node, ts, _, _, _ := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	secret := []byte("cluster-secret")
	node.Raft.Apply(LogCommand{Type: CmdInitSecret, Data: secret}.Marshal(), 5*time.Second)

	time.Sleep(1 * time.Second)

	email := "test@example.com"
	reqBody, _ := json.Marshal(map[string]string{"email": email})
	req, _ := http.NewRequest("POST", ts.URL+"/api/cluster/lookup", bytes.NewReader(reqBody))
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Lookup failed: %d", resp.StatusCode)
	}

	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	if res["id"] == "" {
		t.Error("Empty lookup hash")
	}
}

func TestClusterStatus(t *testing.T) {
	node, ts, _, _, _ := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/v1/cluster/status", nil)
	req.Header.Set("X-Raft-Secret", "testsecret")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Status failed: %d", resp.StatusCode)
	}

	var status map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&status)
	if status["state"] != "Leader" {
		t.Errorf("Expected Leader, got %v", status["state"])
	}
}

func TestDashboard_Auth(t *testing.T) {
	_, ts, _, _, _ := setupCluster(t)
	defer ts.Close()

	// No secret
	resp, _ := http.Get(ts.URL + "/api/cluster/users")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}

	// Wrong secret
	req, _ := http.NewRequest("GET", ts.URL+"/api/cluster/users", nil)
	req.Header.Set("X-Raft-Secret", "wrong")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong secret, got %d", resp.StatusCode)
	}
}
