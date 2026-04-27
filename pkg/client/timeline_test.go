//go:build !wasm

package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/metadata"
	bolt "go.etcd.io/bbolt"
)

func TestVerifyTimeline_SingleNode(t *testing.T) {
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	ctx := context.Background()

	// It should return nil (vacuously true) on a single node cluster
	err := c.VerifyTimelineWithNodes(ctx, []metadata.ClusterNode{
		{ID: "node-1", Address: ts.URL},
	})
	if err != nil {
		t.Fatalf("VerifyTimeline failed: %v", err)
	}
}

func TestVerifyTimeline_Registry(t *testing.T) {
	c, rn, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	ctx := context.Background()

	// Register metadata node so it can be anchored
	rn.FSM.DB().Update(func(tx *bolt.Tx) error {
		node := metadata.Node{
			ID:          rn.NodeID,
			Address:     ts.URL,
			Status:      metadata.NodeStatusActive,
			RaftAddress: string(rn.Transport.LocalAddr()),
		}
		rn.FSM.Put(tx, []byte("nodes"), []byte(rn.NodeID), metadata.MustMarshalJSON(node))
		return nil
	})

	// 1. Anchor the cluster
	if err := c.AnchorClusterInRegistry(ctx); err != nil {
		t.Fatalf("AnchorClusterInRegistry failed: %v", err)
	}

	// 2. Verify timeline using the anchored list
	if err := c.VerifyTimeline(ctx); err != nil {
		t.Fatalf("VerifyTimeline failed: %v", err)
	}
}

func TestVerifyTimelineReceipt(t *testing.T) {
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	// Mock Follower
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/timeline" && r.Method == http.MethodPost {
			var req metadata.VerifyTimelineRequest
			json.NewDecoder(r.Body).Decode(&req)

			if req.TimelineIndex == 10 && string(req.ClusterStateHash) == "consistent-hash" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(metadata.APIErrorResponse{Code: metadata.ErrCodeCryptographicFork})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer follower.Close()

	ctx := context.Background()

	// 1. Manually write the cluster config to /registry/cluster.json
	cfg := metadata.ClusterConfig{
		Nodes: []metadata.ClusterNode{
			{ID: "follower-1", Address: follower.URL},
		},
	}
	data, _ := json.Marshal(cfg)
	wc, _ := c.OpenBlobWrite(ctx, "/registry/cluster.json")
	wc.Write(data)
	wc.Close()

	receipt := metadata.SealedResponse{
		Sealed:           []byte("sealed-data"),
		TimelineIndex:    10,
		ClusterStateHash: []byte("consistent-hash"),
		BindingSignature: []byte("fake-sig"),
	}

	// 2. Perform verification
	if err := c.VerifyTimelineReceipt(ctx, receipt); err != nil {
		t.Fatalf("VerifyTimelineReceipt failed: %v", err)
	}

	// 3. Test failure case (hash mismatch)
	receipt.ClusterStateHash = []byte("evil-hash")
	err := c.VerifyTimelineReceipt(ctx, receipt)
	if !errors.Is(err, metadata.ErrCryptographicFork) {
		t.Fatalf("Expected ErrCryptographicFork, got: %v", err)
	}
}

func TestVerifyTimeline_MultiNode_Success(t *testing.T) {
	c, rn, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	ctx := context.Background()

	// Get real index/hash from leader
	req, _ := http.NewRequest("GET", ts.URL+"/v1/timeline", nil)
	resp, _ := http.DefaultClient.Do(req)
	var lResp metadata.TimelineResponse
	json.NewDecoder(resp.Body).Decode(&lResp)
	resp.Body.Close()

	// Mock Follower
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/timeline" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer follower.Close()

	// Inject follower into anchored nodes cache
	c.anchoredNodesMu.Lock()
	c.anchoredNodes = []metadata.ClusterNode{
		{ID: rn.NodeID, Address: ts.URL},
		{ID: "follower-1", Address: follower.URL},
	}
	c.anchoredNodesMu.Unlock()

	if err := c.VerifyTimeline(ctx); err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
}

func TestVerifyTimeline_MultiNode_ForkDetected(t *testing.T) {
	c, rn, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	ctx := context.Background()

	// Get real index/hash from leader
	req, _ := http.NewRequest("GET", ts.URL+"/v1/timeline", nil)
	resp, _ := http.DefaultClient.Do(req)
	var lResp metadata.TimelineResponse
	json.NewDecoder(resp.Body).Decode(&lResp)
	resp.Body.Close()

	// Mock Follower
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/timeline" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(metadata.APIErrorResponse{Code: metadata.ErrCodeCryptographicFork})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer follower.Close()

	// Inject follower into anchored nodes cache
	c.anchoredNodesMu.Lock()
	c.anchoredNodes = []metadata.ClusterNode{
		{ID: rn.NodeID, Address: ts.URL},
		{ID: "follower-1", Address: follower.URL},
	}
	c.anchoredNodesMu.Unlock()

	err := c.VerifyTimeline(ctx)
	if !errors.Is(err, metadata.ErrCryptographicFork) {
		t.Fatalf("Expected ErrCryptographicFork, got: %v", err)
	}
}
