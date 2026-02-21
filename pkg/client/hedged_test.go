// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadChunk_HedgedRequests(t *testing.T) {
	c := NewClient("http://localhost:8080")

	// Mock server with controllable delays
	var callCount int32
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		// Slow response (3 seconds) - should trigger hedge
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chunk-data-from-1"))
	}))
	defer ts1.Close()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		// Fast response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chunk-data-from-2"))
	}))
	defer ts2.Close()

	urls := []string{ts1.URL, ts2.URL}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	start := time.Now()
	data, err := c.downloadChunk(ctx, "chunk-1", urls, "token")
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("downloadChunk failed: %v", err)
	}

	if string(data) != "chunk-data-from-2" {
		t.Errorf("got unexpected data: %s", string(data))
	}

	// Should have started TS1, waited 1s, started TS2, and finished shortly after.
	// So duration should be around 1s (+ network overhead).
	if duration > 2*time.Second {
		t.Errorf("request took too long (%v), hedge logic might be broken", duration)
	}
	if duration < 1*time.Second {
		t.Errorf("request was too fast (%v), expected at least 1s delay for second node", duration)
	}

	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestDownloadChunk_Cancellation(t *testing.T) {
	c := NewClient("http://localhost:8080")

	ts1Done := make(chan struct{})
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // Wait for cancellation
		close(ts1Done)
	}))
	defer ts1.Close()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Succeed immediately
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer ts2.Close()

	// TS1 is first, TS2 is replica. We'll wait for TS2 to succeed via hedge.
	urls := []string{ts1.URL, ts2.URL}

	_, err := c.downloadChunk(t.Context(), "chunk-1", urls, "token")
	if err != nil {
		t.Fatalf("downloadChunk failed: %v", err)
	}

	// TS1 should be canceled immediately after TS2 succeeds
	select {
	case <-ts1Done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("TS1 was not canceled after success from TS2")
	}
}

func TestDownloadChunk_AllFail(t *testing.T) {
	c := NewClient("http://localhost:8080")

	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts1.Close()

	urls := []string{ts1.URL}
	_, err := c.downloadChunk(t.Context(), "chunk-1", urls, "token")
	if err == nil {
		t.Fatal("expected error when all nodes fail")
	}
}
