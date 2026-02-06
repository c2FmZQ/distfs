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
		if r.Method == http.MethodDelete {
			s.handleDeleteInode(w, r, id)
			return
		}
	} else if r.URL.Path == "/v1/meta/inode" && r.Method == http.MethodPost {
		s.handleCreateInode(w, r)
		return
	} else if r.URL.Path == "/v1/node" && r.Method == http.MethodPost {
		s.handleRegisterNode(w, r)
		return
	} else if r.URL.Path == "/v1/user" && r.Method == http.MethodPost {
		s.handleCreateUser(w, r)
		return
	} else if r.URL.Path == "/v1/group" && r.Method == http.MethodPost {
		s.handleCreateGroup(w, r)
		return
	} else if strings.HasPrefix(r.URL.Path, "/v1/group/") {
		// Update Group (PUT)
		if r.Method == http.MethodPut {
			s.handleUpdateGroup(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

// ... Inode Handlers ...

func (s *Server) handleGetInode(w http.ResponseWriter, r *http.Request, id string) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}
	if err := s.raft.VerifyLeader().Error(); err != nil {
		http.Error(w, "lost leadership", http.StatusServiceUnavailable)
		return
	}

	var data []byte
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
	s.applyCommand(w, r, CmdCreateInode, 10*1024*1024, http.StatusCreated)
}

func (s *Server) handleDeleteInode(w http.ResponseWriter, r *http.Request, id string) {
	s.applyCommandRaw(w, CmdDeleteInode, []byte(id), http.StatusOK)
}

func (s *Server) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdRegisterNode, 1024*1024, http.StatusCreated)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdCreateUser, 1024*1024, http.StatusCreated)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdCreateGroup, 1024*1024, http.StatusCreated)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	// Expects full group JSON
	s.applyCommand(w, r, CmdUpdateGroup, 10*1024*1024, http.StatusOK)
}

// Helpers
func (s *Server) applyCommand(w http.ResponseWriter, r *http.Request, cmdType CommandType, limit int64, successCode int) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	s.applyCommandRaw(w, cmdType, body, successCode)
}

func (s *Server) applyCommandRaw(w http.ResponseWriter, cmdType CommandType, data []byte, successCode int) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}

	cmd := LogCommand{Type: cmdType, Data: data}
	b, _ := json.Marshal(cmd)

	f := s.raft.Apply(b, 5*time.Second)
	if err := f.Error(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if resp := f.Response(); resp != nil {
		if err, ok := resp.(error); ok && err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(successCode)
}
