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

package metadata

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

// handleClusterDashboard routes /api/cluster/* requests.
func (s *Server) handleClusterDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/cluster/users" && r.Method == http.MethodGet {
		s.handleClusterUsers(w, r)
		return
	}
	if r.URL.Path == "/api/cluster/nodes" && r.Method == http.MethodGet {
		s.handleClusterNodes(w, r)
		return
	}
	if r.URL.Path == "/api/cluster/lookup" && r.Method == http.MethodPost {
		s.handleClusterLookup(w, r)
		return
	}
	if r.URL.Path == "/api/cluster/join" && r.Method == http.MethodPost {
		s.handleClusterJoin(w, r)
		return
	}
	if r.URL.Path == "/api/cluster/remove" && r.Method == http.MethodPost {
		s.handleClusterRemove(w, r)
		return
	}

	// Serve Static UI
	sub, err := fs.Sub(uiAssets, "ui")
	if err != nil {
		http.Error(w, "ui assets missing", http.StatusInternalServerError)
		return
	}
	http.StripPrefix("/api/cluster/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
}

// handleClusterUsers returns a list of all registered users (admin only).
func (s *Server) handleClusterUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var u User
			if err := json.Unmarshal(v, &u); err == nil {
				users = append(users, u)
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// handleClusterNodes returns a list of all registered storage nodes (admin only).
func (s *Server) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	var nodes []Node
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				nodes = append(nodes, n)
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

// handleClusterLookup resolves an email to its anonymized User ID (admin only).
func (s *Server) handleClusterLookup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	secret, err := s.fsm.GetClusterSecret()
	if err != nil {
		http.Error(w, "cluster secret unavailable", http.StatusInternalServerError)
		return
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(req.Email))
	hash := hex.EncodeToString(mac.Sum(nil))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": hash})
}

// handleClusterRemove removes a node from the Raft cluster (admin only).
func (s *Server) handleClusterRemove(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	f := s.raft.RemoveServer(raft.ServerID(req.ID), 0, 0)
	if err := f.Error(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
