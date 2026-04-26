package metadata

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestGetTimeline(t *testing.T) {
	tc := SetupRawCluster(t)
	defer tc.Node.Shutdown()

	// Register node manually in FSM
	tc.Node.FSM.db.Update(func(tx *bolt.Tx) error {
		node := Node{
			ID:          tc.Node.NodeID,
			Address:     "http://localhost:8080",
			Status:      NodeStatusActive,
			RaftAddress: string(tc.Node.Transport.LocalAddr()),
		}
		tc.Node.FSM.Put(tx, []byte("nodes"), []byte(tc.Node.NodeID), MustMarshalJSON(node))
		return nil
	})

	// 1. Fetch Timeline (initial state)
	token := LoginSessionForTest(t, tc.TS, tc.AdminID, tc.AdminSK)
	req, _ := http.NewRequest("GET", "/v1/timeline", nil)
	req.Header.Set("Session-Token", token)
	rr := httptest.NewRecorder()
	tc.Server.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp TimelineResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// On first boot, index might be 0 or log-entry 1 depending on bootstrap
	if resp.NodeID == "" {
		t.Errorf("Expected valid NodeID in response")
	}

	// 2. Perform a mutation to advance timeline
	lcmd := LogCommand{Type: CmdStoreMetrics, Data: []byte(`{"node_id":"node-1"}`)}
	lcmdBytes, _ := lcmd.Marshal()

	f := tc.Node.Raft.Apply(lcmdBytes, 5*time.Second)
	if err := f.Error(); err != nil {
		t.Fatalf("Failed to apply command: %v", err)
	}

	// Wait for FSM to catch up
	var resp2 TimelineResponse
	for i := 0; i < 50; i++ {
		rr2 := httptest.NewRecorder()
		tc.Server.ServeHTTP(rr2, req)
		json.Unmarshal(rr2.Body.Bytes(), &resp2)
		if resp2.Index > resp.Index {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if resp2.Index <= resp.Index {
		t.Errorf("Expected timeline index to advance: %d -> %d", resp.Index, resp2.Index)
	}
	if len(resp2.Hash) != 32 {
		t.Errorf("Expected 32-byte SHA256 hash, got %d bytes", len(resp2.Hash))
	}
}
