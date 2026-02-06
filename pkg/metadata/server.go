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
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

type Server struct {
	raft *raft.Raft
	fsm  *MetadataFSM
}

func NewServer(r *raft.Raft, fsm *MetadataFSM) *Server {
	return &Server{raft: r, fsm: fsm}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/meta/inode/") {
		id := strings.TrimPrefix(r.URL.Path, "/v1/meta/inode/")
		if r.Method == http.MethodGet {
			s.handleGetInode(w, r, id)
			return
		}
	} else if r.URL.Path == "/v1/meta/inode" && r.Method == http.MethodPost {
		s.handleCreateInode(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleGetInode(w http.ResponseWriter, r *http.Request, id string) {
	// Strong Consistency: Verify Leader
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}
	if err := s.raft.VerifyLeader().Error(); err != nil {
		http.Error(w, "lost leadership", http.StatusServiceUnavailable)
		return
	}

	var data []byte
	// MetadataFSM db is private, but ServeHTTP is in same package.
	// Wait, db is private in fsm.
	// I need to expose db or add Read method to FSM.
	// FSM db is unexported.
	// But Server and FSM are in `metadata` package. Go allows access.
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(id))
		if v == nil {
			return os.ErrNotExist
		}
		data = make([]byte, len(v))
		copy(data, v)
		return nil
	})

	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleCreateInode(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}

	// DoS Protection: Limit body size to 10MB
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	cmd := LogCommand{Type: CmdCreateInode, Data: body}
	b, _ := json.Marshal(cmd)

	f := s.raft.Apply(b, 5*time.Second)
	if err := f.Error(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// FSM Response
	if resp := f.Response(); resp != nil {
		if err, ok := resp.(error); ok && err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
}