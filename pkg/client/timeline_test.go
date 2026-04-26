//go:build !wasm

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestVerifyTimeline_SingleNode(t *testing.T) {
	c, _, _, ts, _, _ := setupTestClient(t)
	defer ts.Close()

	ctx := context.Background()

	// It should return nil (vacuously true) on a single node cluster
	err := c.VerifyTimeline(ctx)
	if err != nil {
		t.Fatalf("VerifyTimeline failed: %v", err)
	}
}

func TestVerifyTimeline_MultiNode_Success(t *testing.T) {
	// Mock Follower
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/timeline" {
			resp := metadata.TimelineResponse{
				Index: 10,
				Hash:  []byte("consistent-hash"),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer follower.Close()

	// Mock Leader
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/timeline" {
			resp := metadata.TimelineResponse{
				Index:       10,
				Hash:        []byte("consistent-hash"),
				ClusterURLs: []string{follower.URL},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leader.Close()

	c := NewClient(leader.URL)
	c.sessionToken = "dummy-token"
	err := c.VerifyTimeline(context.Background())
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
}

func TestVerifyTimeline_MultiNode_ForkDetected(t *testing.T) {
	// Mock Follower returning a different hash
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/timeline" {
			resp := metadata.TimelineResponse{
				Index: 10,
				Hash:  []byte("honest-follower-hash"),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer follower.Close()

	// Mock Leader lying about the hash
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/timeline" {
			resp := metadata.TimelineResponse{
				Index:       10,
				Hash:        []byte("malicious-leader-hash"),
				ClusterURLs: []string{follower.URL},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leader.Close()

	c := NewClient(leader.URL)
	c.sessionToken = "dummy-token"
	err := c.VerifyTimeline(context.Background())
	if err == nil {
		t.Fatal("Expected error due to fork, but got nil")
	}

	expectedPrefix := "CRYPTOGRAPHIC FORK DETECTED"
	if err.Error()[:len(expectedPrefix)] != expectedPrefix {
		t.Fatalf("Expected error to start with '%s', got: %v", expectedPrefix, err)
	}
}
