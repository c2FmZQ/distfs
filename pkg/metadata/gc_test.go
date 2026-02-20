// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestGCWorker_RunGC(t *testing.T) {
	node, ts, _, _, s := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Mock Data Node
	deleteReceived := false
	dataMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && r.URL.Path == "/v1/data/gc-chunk-1" {
			deleteReceived = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer dataMock.Close()

	// 2. Register Data Node
	n1 := Node{ID: "n1", Address: dataMock.URL, Status: NodeStatusActive}
	node.Raft.Apply(LogCommand{Type: CmdRegisterNode, Data: mustMarshal(n1)}.Marshal(), 5*time.Second)

	// 3. Manually add chunk to GC bucket
	err := node.FSM.db.Update(func(tx *bolt.Tx) error {
		return node.FSM.Put(tx, []byte("garbage_collection"), []byte("gc-chunk-1"), mustMarshal([]string{"n1"}))
	})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	// 4. Run GC
	s.ForceGCScan()

	time.Sleep(500 * time.Millisecond)

	if !deleteReceived {
		t.Error("DELETE request not received by data node")
	}

	// 5. Verify removed from GC bucket
	err = node.FSM.db.View(func(tx *bolt.Tx) error {
		plain, _ := node.FSM.Get(tx, []byte("garbage_collection"), []byte("gc-chunk-1"))
		if plain != nil {
			return fmt.Errorf("still exists")
		}
		return nil
	})
	if err != nil {
		t.Errorf("Chunk still in GC bucket: %v", err)
	}
}
