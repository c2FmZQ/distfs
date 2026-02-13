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
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
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

//go:embed ui/*
var uiAssets embed.FS

type Server struct {
	nodeID  string
	raft    *raft.Raft
	fsm     *MetadataFSM
	jwks    *jwks.Remote
	jwksURL string
	// nodeKey removed - used for mTLS but not passed to Server for auth anymore
	signKey *crypto.IdentityKey

	raftSecret string

	nonceCache map[string]time.Time
	nonceMu    sync.Mutex

	replMonitor *ReplicationMonitor
	gcWorker    *GCWorker
	keyWorker   *KeyRotationWorker

	clientTLSConfig     *tls.Config
	keyRotationInterval time.Duration
}

func NewServer(nodeID string, r *raft.Raft, fsm *MetadataFSM, jwksURL string, signKey *crypto.IdentityKey, raftSecret string, clientTLSConfig *tls.Config, keyRotationInterval time.Duration) *Server {
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = nil
	remote := jwks.NewRemote(retryClient, nil)
	if jwksURL != "" {
		remote.SetIssuers([]jwks.Issuer{{JWKSURI: jwksURL}})
	}

	s := &Server{
		nodeID:              nodeID,
		raft:                r,
		fsm:                 fsm,
		jwks:                remote,
		jwksURL:             jwksURL,
		signKey:             signKey,
		raftSecret:          raftSecret,
		nonceCache:          make(map[string]time.Time),
		clientTLSConfig:     clientTLSConfig,
		keyRotationInterval: keyRotationInterval,
	}
	s.replMonitor = NewReplicationMonitor(s)
	s.replMonitor.Start()
	s.gcWorker = NewGCWorker(s)
	s.gcWorker.Start()
	s.keyWorker = NewKeyRotationWorker(s)
	s.keyWorker.Start()
	return s
}

func (s *Server) Shutdown() {
	if s.replMonitor != nil {
		s.replMonitor.Stop()
	}
	if s.gcWorker != nil {
		s.gcWorker.Stop()
	}
	if s.keyWorker != nil {
		s.keyWorker.Stop()
	}
}

func (s *Server) generateSelfToken(chunks []string, mode string) (string, error) {
	if s.signKey == nil {
		return "", fmt.Errorf("no signing key")
	}

	capToken := CapabilityToken{
		Chunks: chunks,
		Mode:   mode,
		Exp:    time.Now().Add(10 * time.Minute).Unix(),
	}

	payload, _ := json.Marshal(capToken)
	sig := s.signKey.Sign(payload)

	signed := SignedAuthToken{
		Payload:   payload,
		Signature: sig,
	}

	b, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (s *Server) ForceReplicationScan() {
	if s.replMonitor != nil {
		s.replMonitor.Scan()
	}
}

func (s *Server) ForceGCScan() {
	if s.gcWorker != nil {
		s.gcWorker.runGC()
	}
}

func (s *Server) StopKeyRotation() {
	if s.keyWorker != nil {
		s.keyWorker.Stop()
		s.keyWorker = nil
	}
}

type contextKey string

const userContextKey contextKey = "user"

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/meta/key" && r.Method == http.MethodGet {
		s.handleGetClusterKey(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/cluster") {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleClusterDashboard(w, r)
		return
	}

	if r.URL.Path == "/v1/cluster/status" && r.Method == http.MethodGet {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleClusterStatus(w, r)
		return
	}

	if r.URL.Path == "/api/debug/suicide" && r.Method == http.MethodPost {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleSuicide(w, r)
		return
	}

	if r.URL.Path == "/api/debug/scrub" && r.Method == http.MethodPost {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.ForceReplicationScan()
		w.WriteHeader(http.StatusOK)
		return
	}

	// For all other requests, if we are not the leader, forward to the leader.
	if s.forwardIfNecessary(w, r) {
		return
	}

	if r.URL.Path == "/v1/user/register" && r.Method == http.MethodPost {
		s.handleRegisterUser(w, r)
		return
	}
	if r.URL.Path == "/v1/node" && r.Method == http.MethodPost {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleRegisterNode(w, r)
		return
	}
	if r.URL.Path == "/v1/cluster/join" && r.Method == http.MethodPost {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleClusterJoin(w, r)
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
		if r.Method == http.MethodPut {
			s.handleUpdateInode(w, r, id)
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
	} else if r.URL.Path == "/v1/meta/rename" && r.Method == http.MethodPost {
		s.handleRename(w, r)
		return
	} else if r.URL.Path == "/v1/meta/setattr" && r.Method == http.MethodPost {
		s.handleSetAttr(w, r)
		return
	} else if r.URL.Path == "/v1/meta/link" && r.Method == http.MethodPost {
		s.handleLink(w, r)
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

func (s *Server) forwardIfNecessary(w http.ResponseWriter, r *http.Request) bool {
	if s.raft.State() == raft.Leader {
		return false
	}

	leaderAddr, _ := s.raft.LeaderWithID()
	if leaderAddr == "" {
		http.Error(w, "no leader", http.StatusServiceUnavailable)
		return true
	}

	// Find Leader API Address in FSM
	var leaderNode Node
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				if n.RaftAddress == string(leaderAddr) {
					leaderNode = n
					return nil
				}
			}
		}
		return fmt.Errorf("leader not registered")
	})

	if err != nil || leaderNode.Address == "" {
		// If leader is not in FSM, we can't forward.
		// Fallback: return 503 so client retries.
		http.Error(w, "leader address unknown", http.StatusServiceUnavailable)
		return true
	}

	targetAddr := leaderNode.Address
	if leaderNode.ClusterAddress != "" {
		targetAddr = leaderNode.ClusterAddress
	}

	// Ensure target scheme is https if using ClusterAddress (which implies mTLS)
	// Or check if s.clientTLSConfig is present
	if s.clientTLSConfig != nil && !strings.HasPrefix(targetAddr, "https://") {
		targetAddr = strings.Replace(targetAddr, "http://", "https://", 1)
	}

	target, err := url.Parse(targetAddr)
	if err != nil {
		http.Error(w, "invalid leader address", http.StatusInternalServerError)
		return true
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	if s.clientTLSConfig != nil {
		proxy.Transport = &http.Transport{
			TLSClientConfig: s.clientTLSConfig,
		}
	}
	proxy.ServeHTTP(w, r)
	return true
}

func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader: "+s.raft.State().String(), http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	f := s.raft.AddVoter(raft.ServerID(req.ID), raft.ServerAddress(req.Address), 0, 0)
	if err := f.Error(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"id":     s.nodeID,
		"state":  s.raft.State().String(),
		"leader": s.raft.Leader(),
		"stats":  s.raft.Stats(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) authenticate(r *http.Request) (*User, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("missing auth")
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		return nil, err
	}

	active, err := s.fsm.GetActiveKey()
	if err != nil {
		return nil, fmt.Errorf("active key not found: %v", err)
	}
	dk, err := crypto.UnmarshalDecapsulationKey(active.DecKey)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster key %s: %v", active.ID, err)
	}

	kemSize := mlkem.CiphertextSize768
	if len(sealed) < kemSize {
		return nil, fmt.Errorf("token too short: %d < %d", len(sealed), kemSize)
	}

	kemCT := sealed[:kemSize]
	demCT := sealed[kemSize:]

	ss, err := dk.Decapsulate(kemCT)
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

func (s *Server) handleGetClusterKey(w http.ResponseWriter, r *http.Request) {
	active, err := s.fsm.GetActiveKey()
	if err != nil {
		// If bootstrap hasn't happened or no key, return 503
		http.Error(w, "cluster key not available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(active.EncKey)
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
		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}
		return loadInodeWithPages(tx, &inode)
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

	var req RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var email string
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
	email, _ = claims["email"].(string)
	if email == "" {
		http.Error(w, "jwt missing email", http.StatusUnauthorized)
		return
	}

	secret, err := s.fsm.GetClusterSecret()
	if err != nil {
		http.Error(w, "cluster secret not available", http.StatusInternalServerError)
		return
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(email))
	userID := hex.EncodeToString(mac.Sum(nil))

	user := User{
		ID:      userID,
		SignKey: req.SignKey,
		EncKey:  req.EncKey,
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

	// Use crypto/rand for shuffling
	for i := len(nodes) - 1; i > 0; i-- {
		b := make([]byte, 8)
		rand.Read(b)
		j := int(binary.LittleEndian.Uint64(b) % uint64(i+1))
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}

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

		var inode Inode
		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}
		if err := loadInodeWithPages(tx, &inode); err != nil {
			return err
		}

		var err error
		data, err = json.Marshal(inode)
		return err
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
					if err := loadInodeWithPages(tx, &inode); err == nil {
						result = append(result, &inode)
					}
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

func (s *Server) handleUpdateInode(w http.ResponseWriter, r *http.Request, id string) {
	s.applyCommand(w, r, CmdUpdateInode, 10*1024*1024, http.StatusOK)
}

func (s *Server) handleDeleteInode(w http.ResponseWriter, r *http.Request, id string) {
	s.applyCommandRaw(w, CmdDeleteInode, []byte(id), http.StatusOK)
}

func (s *Server) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdRegisterNode, 1024*1024, http.StatusCreated)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdCreateGroup, 1024*1024, http.StatusCreated)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdUpdateGroup, 10*1024*1024, http.StatusOK)
}

func (s *Server) handleRename(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdRename, 1024*1024, http.StatusOK)
}

func (s *Server) handleSetAttr(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdSetAttr, 1024*1024, http.StatusOK)
}

func (s *Server) handleLink(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdLink, 1024*1024, http.StatusOK)
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
	resp, err := s.applyRaftCommand(cmdType, data)
	if err != nil {
		if w == nil {
			return
		}
		if err.Error() == "not leader" {
			http.Error(w, "not leader", http.StatusServiceUnavailable)
			return
		}
		switch err {
		case ErrConflict, ErrExists:
			http.Error(w, err.Error(), http.StatusConflict)
		case ErrNotFound:
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if w != nil {
		if resp != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(successCode)
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(successCode)
	}
}

func (s *Server) applyRaftCommand(cmdType CommandType, data []byte) (interface{}, error) {
	if s.raft.State() != raft.Leader {
		return nil, fmt.Errorf("not leader")
	}

	cmd := LogCommand{Type: cmdType, Data: data}
	b, _ := json.Marshal(cmd)

	f := s.raft.Apply(b, 5*time.Second)
	if err := f.Error(); err != nil {
		return nil, err
	}

	resp := f.Response()
	if err, ok := resp.(error); ok && err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) checkRaftSecret(r *http.Request) bool {
	if s.raftSecret == "" {
		return false // Fail closed
	}
	return r.Header.Get("X-Raft-Secret") == s.raftSecret
}

func (s *Server) handleSuicide(w http.ResponseWriter, r *http.Request) {
	log.Printf("CRITICAL: Suicide requested via debug API")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Goodbye cruel world\n"))
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(1)
	}()
}
