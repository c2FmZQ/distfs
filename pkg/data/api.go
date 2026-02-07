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

package data

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Server struct {
	store Store
}

func NewServer(store Store) *Server {
	return &Server{store: store}
}

// ServeHTTP needs a slightly better router
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/data/") {
		http.NotFound(w, r)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/data/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	
	chunkID := parts[0]
	if !validChunkID.MatchString(chunkID) {
		http.Error(w, "invalid chunk id", http.StatusBadRequest)
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodPut:
			s.handlePut(w, r, chunkID)
		case http.MethodGet:
			s.handleGet(w, r, chunkID)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if len(parts) == 2 && parts[1] == "replicate" && r.Method == http.MethodPost {
		s.handleReplicate(w, r, chunkID)
		return
	}

	http.NotFound(w, r)
}

func (s *Server) handleReplicate(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Targets []string `json:"targets"`
	}
	// Limit JSON size
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "no targets", http.StatusBadRequest)
		return
	}

	// We assume first target is next hop, rest are forwarded
	target := req.Targets[0]
	remaining := ""
	if len(req.Targets) > 1 {
		remaining = strings.Join(req.Targets[1:], ",")
	}

	// Async or Sync? Sync is safer for feedback.
	if err := s.replicate(id, target, remaining); err != nil {
		http.Error(w, fmt.Sprintf("replication failed: %v", err), http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request, id string) {
	// Limit body size to prevent DoS. Chunk is ~1MB.
	// Allow 2MB limit to cover overhead.
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)

	if err := s.store.WriteChunk(id, r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Replication Pipeline
	replicas := r.URL.Query().Get("replicas")
	if replicas != "" {
		targets := strings.Split(replicas, ",")
		nextTarget := targets[0]
		remaining := strings.Join(targets[1:], ",")

		if err := s.replicate(id, nextTarget, remaining); err != nil {
			// If replication fails, we fail the write to ensure consistency
			// (Client should retry)
			http.Error(w, fmt.Sprintf("replication failed: %v", err), http.StatusBadGateway)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
}

func (s *Server) replicate(id, target, remaining string) error {
	rc, err := s.store.ReadChunk(id)
	if err != nil {
		return err
	}
	defer rc.Close()

	// Target is assumed to be a valid base URL (e.g., http://host:port)
	url := fmt.Sprintf("%s/v1/data/%s", target, id)
	if remaining != "" {
		url += "?replicas=" + remaining
	}

	req, err := http.NewRequest("PUT", url, rc)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	size, err := s.store.GetChunkSize(id)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rc, err := s.store.ReadChunk(id)
	if err != nil {
		// Should not happen if GetChunkSize succeeded, but race condition possible
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))

	if _, err := io.Copy(w, rc); err != nil {
		// Response already committed
		return
	}
}
