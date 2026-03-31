//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestReplicationMonitor_Scan(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	s := tc.Server
	defer s.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setup Nodes: Node 1 (Source), Node 2 (Target)
	n1 := Node{ID: "n1", Address: "http://127.0.0.1:1111", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n2 := Node{ID: "n2", Address: "http://127.0.0.1:2222", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n3 := Node{ID: "n3", Address: "http://127.0.0.1:3333", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n4 := Node{ID: "n4", Address: "http://127.0.0.1:4444", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}

	n1b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n1)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n1b, 5*time.Second)
	n2b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n2)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n2b, 5*time.Second)
	n3b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n3)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n3b, 5*time.Second)
	n4b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n4)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n4b, 5*time.Second)

	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: "u1", UID: 1001, SignKey: sk.Public()}, sk, tc.AdminID, tc.AdminSK)

	// 2. Setup Inode with under-replication (n1, n3 are owners, but n3 will be "dead" soon)
	inode := Inode{
		ID:      "invalid-but-test-mocked",
		Type:    FileType,
		OwnerID: "u1",
		ChunkManifest: []ChunkEntry{
			{ID: "c1", Nodes: []string{"n1", "n3"}},
		},
	}
	inode.SignInodeForTest("u1", sk)
	ib, err := LogCommand{Type: CmdCreateInode, Data: mustMarshal(inode), UserID: "u1"}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(ib, 5*time.Second)

	// 3. Mock Data Node for n1
	var mu sync.Mutex
	dataReceived := false
	n1Mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/data/c1/replicate" {
			mu.Lock()
			dataReceived = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer n1Mock.Close()

	// Update n1 address to mock and mark n3 as dead (by not updating its heartbeat)
	n1.Address = n1Mock.URL
	n3.LastHeartbeat = time.Now().Add(-10 * time.Minute).Unix() // Expired
	nb, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n1)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(nb, 5*time.Second)
	nb, err = LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n3)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(nb, 5*time.Second)

	time.Sleep(100 * time.Millisecond)

	// 4. Manually trigger Scan
	s.replMonitor.Scan()

	time.Sleep(500 * time.Millisecond) // Wait for background repair

	mu.Lock()
	received := dataReceived
	mu.Unlock()
	if !received {
		t.Error("Replication request not received by source node")
	}

	// 5. Verify Inode updated in FSM
	err = node.FSM.db.View(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("inodes"), []byte("invalid-but-test-mocked"))
		if err != nil {
			return err
		}
		var i Inode
		json.Unmarshal(plain, &i)
		if len(i.ChunkManifest[0].Nodes) < 3 {
			return fmt.Errorf("nodes not incremented: %v", i.ChunkManifest[0].Nodes)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestReplication_Scan_Concurrent(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	WaitLeader(t, node.Raft)

	rm := NewReplicationMonitor(server)
	// We can't set private scanning field, so we just call it twice
	go rm.Scan()
	rm.Scan()
}

func TestReplicationMonitor_Prune(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	s := tc.Server
	defer s.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setup Nodes
	n1 := Node{ID: "n1", Address: "http://127.0.0.1:1111", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n2 := Node{ID: "n2", Address: "http://127.0.0.1:2222", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n3 := Node{ID: "n3", Address: "http://127.0.0.1:3333", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n4 := Node{ID: "n4", Address: "http://127.0.0.1:4444", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}

	n1b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n1)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n1b, 5*time.Second)
	n2b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n2)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n2b, 5*time.Second)
	n3b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n3)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n3b, 5*time.Second)
	n4b, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n4)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(n4b, 5*time.Second)

	sk, _ := crypto.GenerateIdentityKey()
	CreateUser(t, tc.Node, User{ID: "u1", UID: 1001, SignKey: sk.Public()}, sk, tc.AdminID, tc.AdminSK)

	// 2. Setup Inode with over-replication (4 nodes, target is 3)
	inode := Inode{
		ID:      "over-replicated-inode",
		Type:    FileType,
		OwnerID: "u1",
		ChunkManifest: []ChunkEntry{
			{ID: "c1", Nodes: []string{"n1", "n2", "n3", "n4"}},
		},
	}
	inode.SignInodeForTest("u1", sk)
	ib, err := LogCommand{Type: CmdCreateInode, Data: mustMarshal(inode), UserID: "u1"}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(ib, 5*time.Second)

	// 3. Mock Data Nodes for pruning
	n4Mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && r.URL.Path == "/v1/data/c1" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer n4Mock.Close()
	n4.Address = n4Mock.URL
	nb, err := LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n4)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	node.Raft.Apply(nb, 5*time.Second)

	time.Sleep(100 * time.Millisecond)

	// 4. Manually trigger Scan
	s.replMonitor.Scan()

	time.Sleep(500 * time.Millisecond) // Wait for background pruning

	// 5. Verify Inode updated in FSM (should have exactly 3 nodes)
	err = node.FSM.db.View(func(tx *bolt.Tx) error {
		plain, err := node.FSM.Get(tx, []byte("inodes"), []byte("over-replicated-inode"))
		if err != nil {
			return err
		}
		var i Inode
		json.Unmarshal(plain, &i)
		if len(i.ChunkManifest[0].Nodes) != 3 {
			return fmt.Errorf("nodes not pruned: %v", i.ChunkManifest[0].Nodes)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestReplication_Misc(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Force Scan
	server.ForceReplicationScan()

	// 2. Stop Monitor
	server.replMonitor.Stop()
}

func TestGC_Misc(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Force Scan
	server.ForceGCScan()

	// 2. Stop Worker
	server.gcWorker.Stop()
}

func TestReplication_Scan_Types(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Directory (should be skipped)
	d := Inode{ID: "000000000000000000000000000000d1", Type: DirType, OwnerID: "u1"}
	db, _ := json.Marshal(d)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, db, "")

	// 2. Symlink (should be skipped)
	s := Inode{ID: "000000000000000000000000000000e1", Type: SymlinkType, OwnerID: "u1"}
	sb, _ := json.Marshal(s)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, sb, "")

	// 3. Empty file (should be skipped)
	f := Inode{ID: "000000000000000000000000000000ee", Type: FileType, OwnerID: "u1"}
	fb, _ := json.Marshal(f)
	server.ApplyRaftCommandInternal(context.Background(), CmdCreateInode, fb, "")

	server.replMonitor.Scan()
}

func TestReplication_Repair_Fail(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// Trigger executeRepair with failing source node
	source := Node{ID: "n1", Address: "http://invalid"}
	nodes := map[string]Node{"n2": {ID: "n2", Address: "http://n2"}}
	server.replMonitor.executeRepair("invalid-but-test-mocked", "c1", source, []string{"n2"}, nodes)
	// Should log failure and return
}

func TestReplication_Repair_RaftFail(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	// Don't defer shutdown yet

	source := Node{ID: "n1", Address: ts.URL} // Valid URL but Raft will be gone
	nodes := map[string]Node{"n2": {ID: "n2", Address: "http://n2"}}

	// Shutdown Raft to force Apply failure
	node.Raft.Shutdown().Error()

	server.replMonitor.executeRepair("invalid-but-test-mocked", "c1", source, []string{"n2"}, nodes)
	// Should log "Failed to apply AddReplica"
	ts.Close()
}

func TestGC_DeleteFail(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Manually add a fake node that will fail
	nodeInfo := Node{ID: "fail-node", Address: "http://invalid", Status: NodeStatusActive}
	nb, _ := json.Marshal(nodeInfo)
	server.ApplyRaftCommandInternal(context.Background(), CmdRegisterNode, nb, "")

	// 2. Trigger processDeletion
	server.gcWorker.processDeletion("chunk1", []string{"fail-node"})
	// Should log error and continue
}

func TestKeyRotation_Misc(t *testing.T) {
	tc := SetupCluster(t)
	node := tc.Node
	ts := tc.TS
	server := tc.Server
	defer server.Shutdown()
	defer node.Shutdown()
	defer ts.Close()

	// 1. Trigger Rotation branch
	server.keyWorker.checkAndRotate()

	// 2. Stop Worker
	server.keyWorker.Stop()
}

func TestMetrics_CalculatePercentile(t *testing.T) {
	// Empty samples
	var emptyBuckets [15]uint64
	p := calculatePercentile(emptyBuckets, 0, 95)
	if p != 0 {
		t.Errorf("Expected 0 for 0 total, got %v", p)
	}

	// Single sample in first bucket
	buckets := [15]uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	p = calculatePercentile(buckets, 1, 0.50)
	if p != latencyBounds[0] {
		t.Errorf("Expected %d, got %d", latencyBounds[0], p)
	}

	// Sample in overflow bucket
	bucketsOverflow := [15]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	p = calculatePercentile(bucketsOverflow, 1, 0.99)
	if p <= latencyBounds[len(latencyBounds)-1] {
		t.Errorf("Expected value > %d, got %d", latencyBounds[len(latencyBounds)-1], p)
	}
}
