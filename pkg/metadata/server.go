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
	"bytes"
	"context"
	"crypto/hmac"
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

// Server is the HTTP server for the Metadata Node.
// It handles client requests and coordinates with the Raft cluster.
type Server struct {
	nodeID  string
	raft    *raft.Raft
	fsm     *MetadataFSM
	jwks    *jwks.Remote
	jwksURL string
	// nodeKey removed - used for mTLS but not passed to Server for auth anymore
	signKey *crypto.IdentityKey

	raftSecret string

	challengeCache map[string]challengeEntry // Base64(Challenge) -> Entry
	challengeMu    sync.Mutex

	requestNonceCache map[string]time.Time
	requestNonceMu    sync.Mutex

	replMonitor *ReplicationMonitor
	gcWorker    *GCWorker
	keyWorker   *KeyRotationWorker

	clientTLSConfig     *tls.Config
	keyRotationInterval time.Duration
}

type challengeEntry struct {
	UserID    string
	CreatedAt time.Time
}

// NewServer creates a new Metadata Server.
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
		challengeCache:      make(map[string]challengeEntry),
		requestNonceCache:   make(map[string]time.Time),
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

// Shutdown stops the server and its background workers.
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

	if r.URL.Path == "/v1/meta/key/sign" && r.Method == http.MethodGet {
		s.handleGetServerSignKey(w, r)
		return
	}

	if r.URL.Path == "/v1/meta/key/world" && r.Method == http.MethodGet {
		s.handleGetWorldPublicKey(w, r)
		return
	}

	if r.URL.Path == "/v1/meta/key/world/private" && r.Method == http.MethodGet {
		s.handleGetWorldPrivateKey(w, r)
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
	if r.URL.Path == "/v1/login" && r.Method == http.MethodPost {
		s.handleLogin(w, r)
		return
	}
	if r.URL.Path == "/v1/auth/challenge" && r.Method == http.MethodPost {
		s.handleAuthChallenge(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/user/") && r.Method == http.MethodGet {
		id := strings.TrimPrefix(r.URL.Path, "/v1/user/")
		s.handleGetUser(w, r, id)
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
		// Handle Sealed Request (Layer 7 E2EE)
		if r.Header.Get("X-DistFS-Sealed") == "true" && r.Method != http.MethodGet && r.ContentLength > 0 {
			payload, err := s.unsealRequest(r, user)
			if err != nil {
				http.Error(w, "failed to unseal: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(payload))
			r.ContentLength = int64(len(payload))
		} else if r.Header.Get("X-DistFS-Sealed") == "true" && r.Method != http.MethodGet {
			// X-DistFS-Sealed set but no body provided for mutation.
		} else if r.Method == http.MethodPost || r.Method == http.MethodPut || (r.Method == http.MethodDelete && r.ContentLength > 0) {
			// Enforce E2EE for mutations
			http.Error(w, "E2EE mandatory for this request", http.StatusForbidden)
			return
		}

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
	} else if r.URL.Path == "/v1/group/" && r.Method == http.MethodPost {
		s.handleCreateGroup(w, r)
		return
	} else if strings.HasPrefix(r.URL.Path, "/v1/group/") {
		id := strings.TrimPrefix(r.URL.Path, "/v1/group/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(id, "/private") && r.Method == http.MethodGet {
			id = strings.TrimSuffix(id, "/private")
			s.handleGetGroupPrivateKey(w, r, id)
			return
		}
		if r.Method == http.MethodPut {
			s.handleUpdateGroup(w, r)
			return
		}
		if r.Method == http.MethodGet {
			s.handleGetGroup(w, r, id)
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
	sess := r.Header.Get("Session-Token")
	if sess == "" {
		return nil, fmt.Errorf("missing session token")
	}

	b, err := base64.StdEncoding.DecodeString(sess)
	if err != nil {
		return nil, fmt.Errorf("invalid session token encoding")
	}

	var st SignedSessionToken
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("invalid session token format")
	}

	// Verify server's signature over the token
	payload, _ := json.Marshal(st.Token)
	if !crypto.VerifySignature(s.signKey.Public(), payload, st.Signature) {
		return nil, fmt.Errorf("invalid session signature")
	}

	if time.Now().Unix() > st.Token.Expiry {
		return nil, fmt.Errorf("session expired")
	}

	var user User
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(st.Token.UserID))
		if v == nil {
			return fmt.Errorf("user not found")
		}
		return json.Unmarshal(v, &user)
	})
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	var req AuthChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.challengeMu.Lock()
	// Lazy GC: remove entries older than 2 minutes
	for k, v := range s.challengeCache {
		if time.Since(v.CreatedAt) > 2*time.Minute {
			delete(s.challengeCache, k)
		}
	}
	s.challengeCache[base64.StdEncoding.EncodeToString(challenge)] = challengeEntry{
		UserID:    req.UserID,
		CreatedAt: time.Now(),
	}
	s.challengeMu.Unlock()

	sig := s.signKey.Sign(challenge)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthChallengeResponse{
		Challenge: challenge,
		Signature: sig,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var solve AuthChallengeSolve
	if err := json.NewDecoder(r.Body).Decode(&solve); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.challengeMu.Lock()
	cKey := base64.StdEncoding.EncodeToString(solve.Challenge)
	entry, ok := s.challengeCache[cKey]
	if ok && entry.UserID == solve.UserID {
		if time.Since(entry.CreatedAt) > 2*time.Minute {
			delete(s.challengeCache, cKey)
			ok = false
		} else {
			delete(s.challengeCache, cKey)
		}
	}
	s.challengeMu.Unlock()

	if !ok || entry.UserID != solve.UserID {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	// Verify User signature over challenge
	var user User
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(solve.UserID))
		if v == nil {
			return fmt.Errorf("user not found")
		}
		return json.Unmarshal(v, &user)
	})
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	if !crypto.VerifySignature(user.SignKey, solve.Challenge, solve.Signature) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Issue a 1-hour session token
	expiry := time.Now().Add(1 * time.Hour).Unix()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	st := SessionToken{
		UserID: user.ID,
		Expiry: expiry,
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
	}

	payload, _ := json.Marshal(st)
	sig := s.signKey.Sign(payload)

	signed := SignedSessionToken{
		Token:     st,
		Signature: sig,
	}

	b, _ := json.Marshal(signed)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SessionResponse{
		Token: base64.StdEncoding.EncodeToString(b),
	})
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
		// World Readable/Writable?
		if req.Mode == "R" && (inode.Mode&0004) != 0 {
			// Authorized for reading
		} else if req.Mode == "W" && (inode.Mode&0002) != 0 {
			// Authorized for writing
		} else if inode.GroupID != "" {
			inGroup, _ := s.fsm.IsUserInGroup(user.ID, inode.GroupID)
			if inGroup {
				if req.Mode == "R" && (inode.Mode&0040) != 0 {
					// Authorized for group reading
				} else if req.Mode == "W" && (inode.Mode&0020) != 0 {
					// Authorized for group writing
				} else {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			} else {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		} else {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
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

	data, _ := json.Marshal(signed)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	user, _ = r.Context().Value(userContextKey).(*User)
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(user, data)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(sealed)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
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

	// Check if exists
	var existing User
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(userID))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &existing)
	})
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(existing)
		return
	}

	user := User{
		ID:      userID,
		SignKey: req.SignKey,
		EncKey:  req.EncKey,
	}
	body, _ := json.Marshal(user)

	s.applyCommandRaw(w, r, CmdCreateUser, body, http.StatusCreated)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, id string) {
	var user User
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &user)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	data, _ := json.Marshal(user)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(ctxUser, data)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(sealed)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
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

	data, _ := json.Marshal(nodes)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	user, _ := r.Context().Value(userContextKey).(*User)
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(user, data)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(sealed)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
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

	// E2EE?
	user, _ := r.Context().Value(userContextKey).(*User)
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(user, data)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(sealed)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
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

	data, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	user, _ := r.Context().Value(userContextKey).(*User)
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(user, data)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(sealed)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleCreateInode(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdCreateInode, 10*1024*1024, http.StatusCreated)
}

func (s *Server) handleUpdateInode(w http.ResponseWriter, r *http.Request, id string) {
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.checkWritePermission(user, id); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.applyCommand(w, r, CmdUpdateInode, 10*1024*1024, http.StatusOK)
}

func (s *Server) handleDeleteInode(w http.ResponseWriter, r *http.Request, id string) {
	s.applyCommandRaw(w, r, CmdDeleteInode, []byte(id), http.StatusOK)
}

func (s *Server) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	s.applyCommand(w, r, CmdRegisterNode, 1024*1024, http.StatusCreated)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	log.Printf("GROUP: handleCreateGroup ENTERED (Method: %s, Path: %s)", r.Method, r.URL.Path)
	if s.raft.State() != raft.Leader {
		http.Error(w, "not leader", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Name    string         `json:"name"`
		EncName []byte         `json:"enc_name"`
		Lockbox crypto.Lockbox `json:"lockbox"`
		EncKey  []byte         `json:"enc_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("GROUP: handleCreateGroup decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		log.Printf("GROUP: handleCreateGroup unauthorized")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	secret, err := s.fsm.GetClusterSecret()
	if err != nil {
		log.Printf("GROUP: handleCreateGroup cluster secret failed: %v", err)
		http.Error(w, "cluster secret not available", http.StatusInternalServerError)
		return
	}

	// 1. Generate unique GID (POSIX)
	var gid uint32
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		idx := tx.Bucket([]byte("gids"))
		for {
			gid = generateID32()
			if gid < 1000 {
				continue
			}
			if idx.Get(uint32ToBytes(gid)) == nil {
				return nil
			}
		}
	})
	if err != nil {
		log.Printf("GROUP: handleCreateGroup GID allocation failed: %v", err)
		http.Error(w, "failed to allocate GID", http.StatusInternalServerError)
		return
	}

	// 2. Hash OwnerID + Name for Secure GroupID
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(fmt.Sprintf("%s:%s", user.ID, req.Name)))
	groupID := hex.EncodeToString(mac.Sum(nil))

	log.Printf("GROUP: handleCreateGroup creating '%s' (ID: %s, GID: %d) for user %s", req.Name, groupID, gid, user.ID)

	group := Group{
		ID:            groupID,
		EncryptedName: req.EncName,
		GID:           gid,
		OwnerID:       user.ID,
		Members:       make(map[string]bool),
		EncKey:        req.EncKey,
		Lockbox:       req.Lockbox,
	}
	body, _ := json.Marshal(group)

	log.Printf("GROUP: handleCreateGroup applying Raft command for ID=%s", groupID)
	_, err = s.applyRaftCommand(CmdCreateGroup, body)
	if err != nil {
		log.Printf("GROUP: handleCreateGroup raft apply failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(user, body)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusCreated)
			w.Write(sealed)
			log.Printf("GROUP: handleCreateGroup finished for %s (SEALED)", groupID)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(body)
	log.Printf("GROUP: handleCreateGroup finished for %s", groupID)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request, id string) {
	log.Printf("GROUP: handleGetGroup(%s) starting", id)
	// Must be member to see group?
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		log.Printf("GROUP: handleGetGroup(%s) unauthorized", id)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	inGroup, err := s.fsm.IsUserInGroup(user.ID, id)
	if err != nil {
		log.Printf("GROUP: handleGetGroup(%s) membership check failed for user %s: %v", id, user.ID, err)
		// Check if group exists at all
		var exists bool
		s.fsm.db.View(func(tx *bolt.Tx) error {
			exists = tx.Bucket([]byte("groups")).Get([]byte(id)) != nil
			return nil
		})
		log.Printf("GROUP: handleGetGroup(%s) exists in DB: %v", id, exists)

		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if !inGroup {
		log.Printf("GROUP: handleGetGroup(%s) forbidden for user %s", id, user.ID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var group Group
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &group)
	})
	if err != nil {
		log.Printf("GROUP: handleGetGroup(%s) retrieval failed: %v", id, err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	data, _ := json.Marshal(group)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	user, _ = r.Context().Value(userContextKey).(*User)
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(user, data)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(sealed)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
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
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.checkWritePermission(user, id); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var update ChildUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	update.ParentID = id
	body, _ := json.Marshal(update)
	s.applyCommandRaw(w, r, CmdAddChild, body, http.StatusOK)
}

func (s *Server) handleRemoveChild(w http.ResponseWriter, r *http.Request, id string) {
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.checkWritePermission(user, id); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var update ChildUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	update.ParentID = id
	body, _ := json.Marshal(update)
	s.applyCommandRaw(w, r, CmdRemoveChild, body, http.StatusOK)
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

	s.applyCommandRaw(w, r, cmdType, body, successCode)
}

func (s *Server) applyCommandRaw(w http.ResponseWriter, r *http.Request, cmdType CommandType, data []byte, successCode int) {
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
			data, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")

			// E2EE?
			user, _ := r.Context().Value(userContextKey).(*User)
			if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
				sealed, err := s.sealResponse(user, data)
				if err == nil {
					w.Header().Set("X-DistFS-Sealed", "true")
					w.WriteHeader(successCode)
					w.Write(sealed)
					return
				}
			}

			w.WriteHeader(successCode)
			w.Write(data)
			return
		}
		w.WriteHeader(successCode)
	}
}

func (s *Server) sealResponse(user *User, payload []byte) ([]byte, error) {
	uk, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user public key")
	}

	sealed, err := crypto.SealResponse(uk, s.signKey, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to seal response: %w", err)
	}

	res := SealedResponse{
		Sealed: sealed,
	}
	return json.Marshal(res)
}

func (s *Server) checkWritePermission(user *User, inodeID string) error {
	var inode Inode
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(inodeID))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &inode)
	})
	if err != nil {
		return err
	}

	if inode.OwnerID == user.ID {
		return nil
	}
	if (inode.Mode & 0002) != 0 {
		return nil
	}
	if inode.GroupID != "" {
		inGroup, _ := s.fsm.IsUserInGroup(user.ID, inode.GroupID)
		if inGroup && (inode.Mode&0020) != 0 {
			return nil
		}
	}
	return fmt.Errorf("forbidden")
}

func (s *Server) handleGetGroupPrivateKey(w http.ResponseWriter, r *http.Request, id string) {
	user, err := s.authenticate(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	inGroup, err := s.fsm.IsUserInGroup(user.ID, id)
	if err != nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if !inGroup {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var group Group
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &group)
	})
	if err != nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	// Group Private Key is stored in group.Lockbox, encrypted for each member.
	entry, ok := group.Lockbox[user.ID]
	if !ok {
		// Should not happen if IsUserInGroup returned true, but for safety:
		http.Error(w, "user not in group lockbox", http.StatusInternalServerError)
		return
	}

	data, _ := json.Marshal(entry)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(user, data)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(sealed)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
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

func (s *Server) handleGetServerSignKey(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(s.signKey.Public())
}

func (s *Server) handleGetWorldPublicKey(w http.ResponseWriter, r *http.Request) {
	world, err := s.fsm.GetWorldIdentity()
	if err != nil {
		if err == ErrNotFound && s.raft.State() == raft.Leader {
			s.checkAndInitWorld()
			world, err = s.fsm.GetWorldIdentity()
		}
		if err != nil {
			http.Error(w, "world identity not available", http.StatusNotFound)
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(world.Public)
}

func (s *Server) handleGetWorldPrivateKey(w http.ResponseWriter, r *http.Request) {
	user, err := s.authenticate(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	world, err := s.fsm.GetWorldIdentity()
	if err != nil {
		http.Error(w, "world identity not initialized", http.StatusNotFound)
		return
	}

	// Encapsulate World Private Key using user's Public EncKey
	userEK, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
	if err != nil {
		http.Error(w, "invalid user encryption key", http.StatusInternalServerError)
		return
	}

	ss, kemCT := crypto.Encapsulate(userEK)
	demCT, err := crypto.EncryptDEM(ss, world.Private)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"kem": base64.StdEncoding.EncodeToString(kemCT),
		"dem": base64.StdEncoding.EncodeToString(demCT),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) unsealRequest(r *http.Request, user *User) ([]byte, error) {
	var sealed SealedRequest
	if err := json.NewDecoder(r.Body).Decode(&sealed); err != nil {
		return nil, fmt.Errorf("invalid sealed request: %w", err)
	}

	if sealed.UserID != user.ID {
		return nil, fmt.Errorf("user mismatch in sealed request")
	}

	// 1. Get Active Cluster Key
	active, err := s.fsm.GetActiveKey()
	if err != nil {
		return nil, fmt.Errorf("active cluster key not found")
	}
	dk, err := crypto.UnmarshalDecapsulationKey(active.DecKey)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster key")
	}

	// 2. Open
	ts, payload, err := crypto.OpenRequest(dk, user.SignKey, sealed.Sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to open request: %w", err)
	}

	// 3. Replay Protection
	now := time.Now().UnixNano()
	if ts < now-int64(2*time.Minute) || ts > now+int64(2*time.Minute) {
		return nil, fmt.Errorf("request timestamp out of range")
	}

	nonce := user.ID + ":" + fmt.Sprintf("%d", ts)
	s.requestNonceMu.Lock()
	// Lazy GC
	for k, v := range s.requestNonceCache {
		if time.Since(v) > 5*time.Minute {
			delete(s.requestNonceCache, k)
		}
	}
	if _, exists := s.requestNonceCache[nonce]; exists {
		s.requestNonceMu.Unlock()
		return nil, fmt.Errorf("replay detected")
	}
	s.requestNonceCache[nonce] = time.Now()
	s.requestNonceMu.Unlock()

	return payload, nil
}

func (s *Server) checkAndInitWorld() {
	_, err := s.fsm.GetWorldIdentity()
	if err == nil {
		return
	}

	log.Printf("Initializing World Identity...")
	dk, _ := crypto.GenerateEncryptionKey()
	pk := dk.EncapsulationKey().Bytes()
	priv := crypto.MarshalDecapsulationKey(dk)

	world := WorldIdentity{
		Public:  pk,
		Private: priv,
	}

	data, _ := json.Marshal(world)
	cmd := LogCommand{
		Type: CmdInitWorld,
		Data: data,
	}

	future := s.raft.Apply(cmd.Marshal(), 10*time.Second)
	if err := future.Error(); err != nil {
		log.Printf("Failed to init world identity: %v", err)
	}
}
