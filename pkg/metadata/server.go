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
	"context"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/tlsproxy/jwks"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

type Server struct {
	raft    *raft.Raft
	fsm     *MetadataFSM
	jwks    *jwks.Remote
	nodeKey *mlkem.DecapsulationKey768
	signKey *crypto.IdentityKey

	nonceCache map[string]time.Time
	nonceMu    sync.Mutex

	replMonitor *ReplicationMonitor
}

func NewServer(r *raft.Raft, fsm *MetadataFSM, jwksURL string, nodeKey *mlkem.DecapsulationKey768, signKey *crypto.IdentityKey) *Server {
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = nil
	remote := jwks.NewRemote(retryClient, nil)
	if jwksURL != "" {
		remote.SetIssuers([]jwks.Issuer{{JWKSURI: jwksURL}})
	}

	s := &Server{
		raft:       r,
		fsm:        fsm,
		jwks:       remote,
		nodeKey:    nodeKey,
		signKey:    signKey,
		nonceCache: make(map[string]time.Time),
	}
	s.replMonitor = NewReplicationMonitor(s)
	s.replMonitor.Start()
	return s
}

func (s *Server) Shutdown() {
	if s.replMonitor != nil {
		s.replMonitor.Stop()
	}
}

func (s *Server) ForceReplicationScan() {
	if s.replMonitor != nil {
		s.replMonitor.Scan()
	}
}

type contextKey string

const userContextKey contextKey = "user"

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/meta/key" && r.Method == http.MethodGet {
		s.handleGetNodeKey(w, r)
		return
	}
	if r.URL.Path == "/v1/user/register" && r.Method == http.MethodPost {
		s.handleRegisterUser(w, r)
		return
	}
	if r.URL.Path == "/v1/node" && r.Method == http.MethodPost {
		s.handleRegisterNode(w, r)
		return
	}

	user, err := s.authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if user != nil {
		ctx := context.WithValue(r.Context(), userContextKey, user)
		r = r.WithContext(ctx)
	}

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
	} else if r.URL.Path == "/v1/meta/inodes" && r.Method == http.MethodPost {
		s.handleGetInodes(w, r)
		return
	} else if r.URL.Path == "/v1/meta/token" && r.Method == http.MethodPost {
		s.handleIssueToken(w, r)
		return
	} else if r.URL.Path == "/v1/user" && r.Method == http.MethodPost {
		s.handleCreateUser(w, r)
		return
	} else if r.URL.Path == "/v1/group" && r.Method == http.MethodPost {
		s.handleCreateGroup(w, r)
		return
	} else if strings.HasPrefix(r.URL.Path, "/v1/group/") {
		if r.Method == http.MethodPut {
			s.handleUpdateGroup(w, r)
			return
		}
	} else if r.URL.Path == "/v1/meta/allocate" && r.Method == http.MethodPost {
		s.handleAllocateChunk(w, r)
		return
	} else if strings.HasPrefix(r.URL.Path, "/v1/meta/directory/") && strings.HasSuffix(r.URL.Path, "/entry") {
		id := strings.TrimPrefix(r.URL.Path, "/v1/meta/directory/")
		id = strings.TrimSuffix(id, "/entry")
		if r.Method == http.MethodPut {
			s.handleAddChild(w, r, id)
			return
		}
		if r.Method == http.MethodDelete {
			s.handleRemoveChild(w, r, id)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) authenticate(r *http.Request) (*User, error) {
	if s.nodeKey == nil {
		return nil, nil
	}

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("missing auth")
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		return nil, err
	}

	kemSize := mlkem.CiphertextSize768
	if len(sealed) < kemSize {
		return nil, fmt.Errorf("token too short")
	}

	kemCT := sealed[:kemSize]
	demCT := sealed[kemSize:]

	ss, err := s.nodeKey.Decapsulate(kemCT)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %v", err)
	}

	pt, err := crypto.DecryptDEM(ss, demCT)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	var signed SignedAuthToken
	if err := json.Unmarshal(pt, &signed); err != nil {
		return nil, err
	}

	var token AuthToken
	if err := json.Unmarshal(signed.Payload, &token); err != nil {
		return nil, err
	}

	if time.Since(time.Unix(token.Time, 0)) > 5*time.Minute {
		return nil, fmt.Errorf("expired")
	}

	s.nonceMu.Lock()
	if _, exists := s.nonceCache[token.Nonce]; exists {
		s.nonceMu.Unlock()
		return nil, fmt.Errorf("replay detected")
	}
	s.nonceCache[token.Nonce] = time.Now()
	if len(s.nonceCache) > 10000 && rand.Intn(100) == 0 {
		now := time.Now()
		for nonce, t := range s.nonceCache {
			if now.Sub(t) > 6*time.Minute {
				delete(s.nonceCache, nonce)
			}
		}
	}
	s.nonceMu.Unlock()

	var user User
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(token.UserID))
		if v == nil {
			return fmt.Errorf("user not found")
		}
		return json.Unmarshal(v, &user)
	})
	if err != nil {
		return nil, err
	}

	if !crypto.VerifySignature(user.SignKey, signed.Payload, signed.Signature) {
		return nil, fmt.Errorf("invalid signature")
	}

	return &user, nil
}

func (s *Server) handleGetNodeKey(w http.ResponseWriter, r *http.Request) {
	if s.nodeKey == nil {
		http.Error(w, "node key not configured", http.StatusInternalServerError)
		return
	}
	pub := s.nodeKey.EncapsulationKey()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(pub.Bytes())
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	if s.signKey == nil {
		http.Error(w, "signing key not configured", http.StatusInternalServerError)
		return
	}

	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		InodeID string   `json:"inode_id"`
		Chunks  []string `json:"chunks"`
		Mode    string   `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Verify Permission
	var inode Inode
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(req.InodeID))
		if v == nil {
			return fmt.Errorf("inode not found")
		}
		return json.Unmarshal(v, &inode)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if inode.OwnerID != user.ID {
		// TODO: Check group
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Construct Token
	capToken := CapabilityToken{
		Chunks: req.Chunks,
		Mode:   req.Mode,
		Exp:    time.Now().Add(10 * time.Minute).Unix(),
	}
	if len(capToken.Chunks) == 0 {
		// If empty, allow all chunks in inode?
		for _, c := range inode.ChunkManifest {
			capToken.Chunks = append(capToken.Chunks, c.ID)
		}
	}

	payload, _ := json.Marshal(capToken)
	sig := s.signKey.Sign(payload)

	signed := SignedAuthToken{
		Payload:   payload,
		Signature: sig,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signed)
}

func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		JWT     string `json:"jwt"`
		SignKey []byte `json:"sign_key"`
		EncKey  []byte `json:"enc_key"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.jwks.Ready(r.Context())
	token, err := jwt.Parse(req.JWT, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		return s.jwks.GetKey(kid)
	})

	if err != nil || !token.Valid {
		http.Error(w, "invalid jwt: "+err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}
	email, _ := claims["email"].(string)
	if email == "" {
		http.Error(w, "jwt missing email", http.StatusUnauthorized)
		return
	}

	user := User{
		ID:      email,
		SignKey: req.SignKey,
		EncKey:  req.EncKey,
		Name:    req.Name,
	}
	body, _ := json.Marshal(user)

	s.applyCommandRaw(w, CmdCreateUser, body, http.StatusCreated)
}

func (s *Server) handleAllocateChunk(w http.ResponseWriter, r *http.Request) {
	var nodes []Node
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err != nil {
				continue
			}
			if n.Status == NodeStatusActive {
				nodes = append(nodes, n)
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(nodes) == 0 {
		http.Error(w, "no active nodes", http.StatusServiceUnavailable)
		return
	}

	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(nodes), func(i, j int) { nodes[i], nodes[j] = nodes[j], nodes[i] })

	if len(nodes) > 3 {
		nodes = nodes[:3]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

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

func (s *Server) handleGetInodes(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}
	if err := s.raft.VerifyLeader().Error(); err != nil {
		http.Error(w, "lost leadership", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

	var ids []string
	if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if len(ids) > 1000 {
		http.Error(w, "too many ids", http.StatusBadRequest)
		return
	}

	result := make([]*Inode, 0, len(ids))
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		for _, id := range ids {
			v := b.Get([]byte(id))
			if v != nil {
				var inode Inode
				if err := json.Unmarshal(v, &inode); err == nil {
					result = append(result, &inode)
				}
			}
		}
		return nil
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
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
	s.applyCommand(w, r, CmdUpdateGroup, 10*1024*1024, http.StatusOK)
}

func (s *Server) handleAddChild(w http.ResponseWriter, r *http.Request, id string) {
	var update ChildUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	update.ParentID = id
	body, _ := json.Marshal(update)
	s.applyCommandRaw(w, CmdAddChild, body, http.StatusOK)
}

func (s *Server) handleRemoveChild(w http.ResponseWriter, r *http.Request, id string) {
	var update ChildUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	update.ParentID = id
	body, _ := json.Marshal(update)
	s.applyCommandRaw(w, CmdRemoveChild, body, http.StatusOK)
}

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
