// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestReplicationMonitor_Scan(t *testing.T) {
	node, ts, _, _, s := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Setup Nodes: Node 1 (Source), Node 2 (Target)
	n1 := Node{ID: "n1", Address: "http://127.0.0.1:1111", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n2 := Node{ID: "n2", Address: "http://127.0.0.1:2222", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	n3 := Node{ID: "n3", Address: "http://127.0.0.1:3333", Status: NodeStatusActive, LastHeartbeat: time.Now().Unix()}
	
	node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n1)}.Marshal(), 5*time.Second)
	node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n2)}.Marshal(), 5*time.Second)
	node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n3)}.Marshal(), 5*time.Second)

	// 2. Setup Inode with under-replication (n1, n3 are owners, but n3 will be "dead" soon)
	inode := Inode{
		ID:   "f1",
		Type: FileType,
		ChunkManifest: []ChunkEntry{
			{ID: "c1", Nodes: []string{"n1", "n3"}},
		},
	}
	node.Raft.Apply(LogCommand{Type: CmdCreateInode, Data: mustMarshal(inode)}.Marshal(), 5*time.Second)

	// 3. Mock Data Node for n1
	dataReceived := false
	n1Mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/data/c1/replicate" {
			dataReceived = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer n1Mock.Close()

	// Update n1 address to mock and mark n3 as dead (by not updating its heartbeat)
	n1.Address = n1Mock.URL
	n3.LastHeartbeat = time.Now().Add(-10 * time.Minute).Unix() // Expired
	node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n1)}.Marshal(), 5*time.Second)
	node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n3)}.Marshal(), 5*time.Second)

	time.Sleep(100 * time.Millisecond)

	// 4. Manually trigger Scan
	s.replMonitor.Scan()

	time.Sleep(500 * time.Millisecond) // Wait for background repair

	if !dataReceived {
		t.Error("Replication request not received by source node")
	}

	// 5. Verify Inode updated in FSM
	err := node.FSM.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte("f1"))
		var i Inode
		json.Unmarshal(v, &i)
		if len(i.ChunkManifest[0].Nodes) < 3 {
			return fmt.Errorf("nodes not incremented: %v", i.ChunkManifest[0].Nodes)
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
