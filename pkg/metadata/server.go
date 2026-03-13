//go:build !wasm

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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/logger"
	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/tlsproxy/jwks"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

type Raft interface {
	State() raft.RaftState
	LeaderWithID() (raft.ServerAddress, raft.ServerID)
	Apply(data []byte, timeout time.Duration) raft.ApplyFuture
	Leader() raft.ServerAddress
	Stats() map[string]string
	VerifyLeader() raft.Future
	RemoveServer(id raft.ServerID, prevIndex uint64, timeout time.Duration) raft.IndexFuture
	AddVoter(id raft.ServerID, address raft.ServerAddress, prevIndex uint64, timeout time.Duration) raft.IndexFuture
	GetConfiguration() raft.ConfigurationFuture
}

// Server is the HTTP server for the Metadata Node.
// It handles client requests and coordinates with the Raft cluster.
type Server struct {
	nodeID       string
	apiURL       string
	raftAddress  string
	tlsPublicKey []byte
	raft         Raft
	fsm          *MetadataFSM
	jwks         *jwks.Remote
	// nodeKey removed - used for mTLS but not passed to Server for auth anymore
	signKey *crypto.IdentityKey

	clusterSignKey *crypto.IdentityKey
	clusterSignMu  sync.RWMutex

	raftSecret string

	httpClient          *http.Client
	discoveryHTTPClient *http.Client

	challengeCache map[string]challengeEntry // Base64(Challenge) -> Entry
	challengeMu    sync.Mutex

	requestNonceCache map[string]time.Time
	requestNonceMu    sync.Mutex

	sessionKeyCache map[string]sessionKeyEntry // SessionToken -> Entry
	sessionKeyMu    sync.RWMutex

	// Request Batching
	batchMu      sync.Mutex
	batchQueue   []*LogCommand
	batchResps   []chan interface{} // Corresponding channels for batchQueue
	batchTimer   *time.Timer
	batchApplyCh chan batchRequest

	replMonitor *ReplicationMonitor
	gcWorker    *GCWorker
	keyWorker   *KeyRotationWorker

	clientTLSConfig     *tls.Config
	keyRotationInterval time.Duration

	forwardTransport *http.Transport
	leaderURLCache   map[raft.ServerAddress]string
	leaderURLMu      sync.RWMutex

	oidcMu     sync.RWMutex
	oidcConfig *OIDCConfig
	stopCh     chan struct{}

	vault  *NodeVault
	decKey *mlkem.DecapsulationKey768

	// Phase 53.1: Ephemeral Epoch Keys (In-Memory Only)
	epochPrivateKeys   map[string]*mlkem.DecapsulationKey768
	epochPrivateKeysMu sync.RWMutex
}

type batchRequest struct {
	cmds  []*LogCommand
	resps []chan interface{}
}

type sessionKeyEntry struct {
	key    []byte
	expiry int64
}

type challengeEntry struct {
	UserID    string
	CreatedAt time.Time
}

type schemeSwitchingTransport struct {
	standard  http.RoundTripper
	protected http.RoundTripper
}

func (t *schemeSwitchingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return t.protected.RoundTrip(req)
	}
	return t.standard.RoundTrip(req)
}

// NewServer creates a new Metadata Server.
func NewServer(nodeID string, r *raft.Raft, fsm *MetadataFSM, oidcDiscoveryURL string, signKey *crypto.IdentityKey, raftSecret string, clientTLSConfig *tls.Config, keyRotationInterval time.Duration, vault *NodeVault, decKey *mlkem.DecapsulationKey768, disableDoH bool, allowInsecure bool) *Server {
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = nil
	remote := jwks.NewRemote(retryClient, nil)

	resolver := ech.DefaultResolver
	if disableDoH {
		resolver = ech.InsecureGoResolver()
	}

	createTransport := func(tlsCfg *tls.Config) http.RoundTripper {
		protected := ech.NewTransport()
		protected.TLSConfig = tlsCfg
		protected.Resolver = resolver

		if !allowInsecure {
			return protected
		}

		standard := http.DefaultTransport.(*http.Transport).Clone()
		standard.TLSClientConfig = tlsCfg
		return &schemeSwitchingTransport{
			standard:  standard,
			protected: protected,
		}
	}

	echTransport := createTransport(clientTLSConfig)

	discoveryTLSConfig := func() *tls.Config {
		if clientTLSConfig == nil {
			return nil
		}
		cfg := clientTLSConfig.Clone()
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		}
		return cfg
	}()
	discoveryTransport := createTransport(discoveryTLSConfig)

	s := &Server{
		nodeID:     nodeID,
		raft:       r,
		fsm:        fsm,
		jwks:       remote,
		signKey:    signKey,
		raftSecret: raftSecret,
		httpClient: &http.Client{
			Transport: echTransport,
			Timeout:   10 * time.Second,
		},
		discoveryHTTPClient: &http.Client{
			Transport: discoveryTransport,
			Timeout:   5 * time.Second,
		},
		challengeCache:      make(map[string]challengeEntry),
		requestNonceCache:   make(map[string]time.Time),
		sessionKeyCache:     make(map[string]sessionKeyEntry),
		clientTLSConfig:     clientTLSConfig,
		keyRotationInterval: keyRotationInterval,
		forwardTransport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		leaderURLCache:   make(map[raft.ServerAddress]string),
		stopCh:           make(chan struct{}),
		batchQueue:       make([]*LogCommand, 0),
		batchResps:       make([]chan interface{}, 0),
		batchApplyCh:     make(chan batchRequest, 1000),
		vault:            vault,
		decKey:           decKey,
		epochPrivateKeys: make(map[string]*mlkem.DecapsulationKey768),
	}
	if oidcDiscoveryURL != "" {
		go s.discoverOIDC(oidcDiscoveryURL)
	}

	go s.batchProcessor()
	go s.sessionCleanupWorker()
	go s.metricsFlusher()

	s.replMonitor = NewReplicationMonitor(s)
	s.replMonitor.Start()
	s.gcWorker = NewGCWorker(s)
	s.gcWorker.Start()
	s.keyWorker = NewKeyRotationWorker(s)
	s.keyWorker.Start()

	s.loadClusterSignKey()
	go s.clusterKeyLoader()

	return s
}

func (s *Server) RegisterEpochKey(id string, sk *mlkem.DecapsulationKey768) {
	s.epochPrivateKeysMu.Lock()
	defer s.epochPrivateKeysMu.Unlock()
	s.epochPrivateKeys[id] = sk
}

func (s *Server) GetClusterSignKey() *crypto.IdentityKey {
	return s.getClusterSignKey()
}

func (s *Server) getClusterSignKey() *crypto.IdentityKey {
	s.clusterSignMu.RLock()
	csk := s.clusterSignKey
	s.clusterSignMu.RUnlock()

	if csk == nil && s.raft.State() == raft.Leader {
		s.loadClusterSignKey()
		s.clusterSignMu.RLock()
		csk = s.clusterSignKey
		s.clusterSignMu.RUnlock()
	}
	return csk
}

func (s *Server) clusterKeyLoader() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if s.raft.State() == raft.Leader {
				s.loadClusterSignKey()
			}
		}
	}
}

func (s *Server) loadClusterSignKey() {
	s.clusterSignMu.RLock()
	hasKey := s.clusterSignKey != nil
	s.clusterSignMu.RUnlock()

	if hasKey {
		return
	}

	var encPriv []byte
	var err error
	for i := 0; i < 5; i++ {
		err = s.fsm.db.View(func(tx *bolt.Tx) error {
			plain, err := s.fsm.Get(tx, []byte("system"), []byte("cluster_sign_key"))
			if err != nil {
				return err
			}
			if plain == nil {
				return ErrNotFound
			}
			var key ClusterSignKey
			if err := json.Unmarshal(plain, &key); err != nil {
				return err
			}
			encPriv = key.EncryptedPrivate
			return nil
		})
		if err == nil {
			break
		}
		if !errors.Is(err, ErrNotFound) {
			log.Printf("ERROR: Failed to fetch cluster sign key from FSM: %v", err)
			return
		}
		select {
		case <-s.stopCh:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}

	if encPriv == nil {
		return
	}

	priv := crypto.UnmarshalIdentityKey(encPriv)
	// UnmarshalIdentityKey for Ed25519 always succeeds if bytes are provided
	// as it just wraps the slice.

	s.clusterSignMu.Lock()
	s.clusterSignKey = priv
	s.clusterSignMu.Unlock()
	logger.Debugf("SUCCESS: Loaded cluster signing key (Leader)")
}

func (s *Server) discoverOIDC(discoveryURL string) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		resp, err := client.Get(discoveryURL)
		if err != nil {
			logger.Debugf("OIDC discovery failed: %v", err)
		} else {
			var conf OIDCConfig
			if err := json.NewDecoder(resp.Body).Decode(&conf); err != nil {
				logger.Debugf("failed to decode OIDC discovery: %v", err)
			} else {
				s.oidcMu.Lock()
				s.oidcConfig = &conf
				s.jwks.SetIssuers([]jwks.Issuer{{JWKSURI: conf.JWKSURI}})
				s.oidcMu.Unlock()
				logger.Debugf("OIDC discovery successful for %s", conf.Issuer)
			}
			resp.Body.Close()
		}
		select {
		case <-ticker.C:
		case <-s.stopCh:
			return
		}
	}
}

func (s *Server) batchProcessor() {
	for {
		select {
		case req := <-s.batchApplyCh:
			s.applyBatch(req)
		case <-s.stopCh:
			return
		}
	}
}

func (s *Server) metricsFlusher() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s.raft.State() == raft.Leader {
				snap := s.fsm.metrics.SnapshotAndReset()
				data, _ := json.Marshal(snap)
				s.ApplyRaftCommandInternal(CmdStoreMetrics, data, "")
			}
		case <-s.stopCh:
			return
		}
	}
}

func (s *Server) applyBatch(req batchRequest) {
	// 1. Marshal the batch
	data, err := json.Marshal(req.cmds)
	if err != nil {
		log.Printf("Failed to marshal batch: %v", err)
		for _, ch := range req.resps {
			ch <- err
		}
		return
	}

	// 2. Apply single Raft log
	cmd := LogCommand{
		Type:   CmdBatch,
		Data:   data,
		Atomic: false, // Server-aggregated batches MUST NOT be atomic to avoid cross-user interference
	}
	f := s.raft.Apply(cmd.Marshal(), 5*time.Second)
	if err := f.Error(); err != nil {
		for _, ch := range req.resps {
			ch <- err
		}
		return
	}

	// 3. Distribute results
	resp := f.Response()
	if err, ok := resp.(error); ok {
		for _, ch := range req.resps {
			ch <- err
		}
		return
	}

	results, ok := resp.([]interface{})
	if !ok || len(results) != len(req.resps) {
		log.Printf("Batch result mismatch: got %T results for %d requests", resp, len(req.resps))
		err := fmt.Errorf("internal batch error")
		for _, ch := range req.resps {
			ch <- err
		}
		return
	}

	for i, res := range results {
		req.resps[i] <- res
	}
}

// Shutdown stops the server and its background workers.
// Shutdown gracefully stops the server and its background workers.
func (s *Server) Shutdown() {
	close(s.stopCh)
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
	csk := s.getClusterSignKey()
	if csk == nil && s.signKey == nil {
		return "", fmt.Errorf("no signing key")
	}

	capToken := CapabilityToken{
		Chunks: chunks,
		Mode:   mode,
		Exp:    time.Now().Add(10 * time.Minute).Unix(),
	}

	payload, _ := json.Marshal(capToken)

	var sig []byte
	signerID := s.nodeID
	if csk != nil {
		sig = csk.Sign(payload)
		signerID = ""
	} else {
		sig = s.signKey.Sign(payload)
	}

	signed := SignedAuthToken{
		SignerID:  signerID,
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

func (s *Server) RotateFSMKey() error {
	if s.raft.State() != raft.Leader {
		return fmt.Errorf("not leader")
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return err
	}

	_, gen := s.fsm.keyRing.Current()
	req := RotateFSMKeyRequest{
		NewKey: newKey,
		Gen:    gen + 1,
	}
	data, _ := json.Marshal(req)

	_, err := s.ApplyRaftCommandInternal(CmdRotateFSMKey, data, "")
	return err
}

type contextKey string

const (
	userContextKey        contextKey = "user"
	adminBypassContextKey contextKey = "admin-bypass"
	sessionKeyContextKey  contextKey = "session-key"
)

func (s *Server) SetRaftAddress(addr string) {
	s.raftAddress = addr
}

func (s *Server) SetAPIURL(url string) {
	s.apiURL = url
}

func (s *Server) SetTLSPublicKey(k []byte) {
	s.tlsPublicKey = k
}

func (s *Server) handleNodeInfo(w http.ResponseWriter, r *http.Request) {
	// Support both legacy (direct secret) and new (HMAC) authentication
	nonceStr := r.Header.Get(raftNonceHeader)
	sigStr := r.Header.Get(raftSignatureHeader)

	if nonceStr != "" && sigStr != "" {
		nonce, err := hex.DecodeString(nonceStr)
		if err != nil {
			s.writeError(w, r, ErrCodeInternal, "invalid nonce", http.StatusBadRequest)
			return
		}
		if !s.verifySignature(nonce, "LEADER_PROBE", sigStr) {
			s.writeError(w, r, ErrCodeInternal, "invalid leader signature", http.StatusUnauthorized)
			return
		}
		// Prove knowledge of secret back to leader
		w.Header().Set(raftResponseHeader, s.signNonce(nonce, "NODE_RESPONSE"))
	} else if !s.checkRaftSecret(r) {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	info := map[string]interface{}{
		"id":           s.nodeID,
		"api_url":      s.apiURL,
		"raft_address": s.raftAddress,
		"public_key":   s.tlsPublicKey,
	}
	if s.signKey != nil {
		info["sign_key"] = s.signKey.Public()
	}
	if s.decKey != nil {
		info["enc_key"] = s.decKey.EncapsulationKey().Bytes()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// ServeHTTP routes and handles incoming Metadata API requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Identify Public Routes
	isPublic := false
	switch r.URL.Path {
	case "/v1/health", "/v1/meta/key", "/v1/meta/key/sign", "/v1/meta/key/world",
		"/v1/user/register", "/v1/login", "/v1/auth/config", "/v1/auth/challenge",
		"/v1/cluster/stats", "/v1/user/keysync":
		isPublic = true
	case "/v1/node/info":
		isPublic = true
	}

	// 2. Handle Public Routes before forwarding (Performance & Availability)
	if r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/v1/health":
			s.handleHealth(w, r)
			return
		case "/v1/meta/key":
			s.handleGetClusterKey(w, r)
			return
		case "/v1/meta/key/sign":
			s.handleGetServerSignKey(w, r)
			return
		case "/v1/meta/key/world":
			s.handleGetWorldPublicKey(w, r)
			return
		case "/v1/node/info":
			s.handleNodeInfo(w, r)
			return
		}
	}

	// Cluster Private Key (Authenticated encapsulation)
	if r.URL.Path == "/v1/meta/key/world/private" && r.Method == http.MethodGet {
		// Needs auth, skip for now - will be handled later
	}

	// Debug Routes (Protected by shared secret)
	if s.handleDebugRoutes(w, r) {
		return
	}

	if r.URL.Path == "/v1/system/bootstrap" && r.Method == http.MethodPost {
		s.handleSystemBootstrap(w, r)
		return
	}

	// For all other requests, if we are not the leader, forward to the leader.
	if s.forwardIfNecessary(w, r) {
		return
	}

	// 4. Authenticate User for remaining routes
	user, err := s.authenticate(r)
	if err != nil {
		authHeader := r.Header.Get("Authorization")
		isBearer := strings.HasPrefix(authHeader, "Bearer ")

		// Only allow Bearer tokens to bypass if the route handles its own JWT auth (keysync)
		if !isPublic && !s.checkRaftSecret(r) && !(isBearer && r.URL.Path == "/v1/user/keysync") {
			s.writeError(w, r, ErrCodeUnauthorized, err.Error(), http.StatusUnauthorized)
			return
		}
	}

	if user != nil {
		if user.Locked {
			// Locked users can only access endpoints necessary for unlocking/setup
			if r.URL.Path != "/v1/user/keysync" && r.URL.Path != "/v1/user/me" {
				s.writeError(w, r, ErrCodeForbidden, "account is locked pending administrator approval", http.StatusForbidden)
				return
			}
		}

		// Handle Sealed Request (Layer 7 E2EE)
		if r.Header.Get("X-DistFS-Sealed") == "true" && r.Method != http.MethodGet {
			payload, err := s.unsealRequest(w, r, user)
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					return
				} else {
					s.writeError(w, r, ErrCodeInternal, "failed to unseal: "+err.Error(), http.StatusBadRequest)
				}
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(payload))
			r.ContentLength = int64(len(payload))
		} else if r.Method == http.MethodPost || r.Method == http.MethodPut || (r.Method == http.MethodDelete && r.ContentLength > 0) {
			// Enforce E2EE for mutations
			if r.Header.Get("X-DistFS-Sealed") != "true" {
				s.writeError(w, r, ErrCodeForbidden, "E2EE mandatory for this request", http.StatusForbidden)
				return
			}
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		if r.Header.Get("X-DistFS-Admin-Bypass") == "true" {
			logger.Debugf("DEBUG AUTH: User %s provided Admin-Bypass header", user.ID)
			ctx = context.WithValue(ctx, adminBypassContextKey, true)
		}
		r = r.WithContext(ctx)
	}

	// 5. Mutation & Protected Routes
	if r.URL.Path == "/v1/node" {
		if !s.checkRaftSecret(r) {
			s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			s.handleRegisterNode(w, r)
			return
		}
		if r.Method == http.MethodGet {
			s.handleGetNodes(w, r)
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/v1/node/") {
		if !s.checkRaftSecret(r) {
			s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/node/")
		if r.Method == http.MethodDelete {
			s.handleRemoveNode(w, r, id)
			return
		}
	}

	if r.URL.Path == "/v1/user/register" && r.Method == http.MethodPost {
		s.handleRegisterUser(w, r)
		return
	}
	if r.URL.Path == "/v1/user/keysync" {
		if r.Method == http.MethodGet {
			s.handleGetKeySync(w, r)
			return
		}
		if r.Method == http.MethodPost {
			s.handleStoreKeySync(w, r)
			return
		}
	}
	if r.URL.Path == "/v1/login" && r.Method == http.MethodPost {
		s.handleLogin(w, r)
		return
	}
	if r.URL.Path == "/v1/auth/config" && r.Method == http.MethodGet {
		s.handleGetAuthConfig(w, r)
		return
	}
	if r.URL.Path == "/v1/auth/challenge" && r.Method == http.MethodPost {
		s.handleAuthChallenge(w, r)
		return
	}

	if r.URL.Path == "/v1/meta/key/world/private" && r.Method == http.MethodGet {
		if user == nil {
			s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleGetWorldPrivateKey(w, r)
		return
	}

	if r.URL.Path == "/v1/cluster/stats" && r.Method == http.MethodGet {
		s.handleGetClusterStats(w, r)
		return
	}

	if r.URL.Path == "/v1/system/metrics" && r.Method == http.MethodGet {
		if !s.checkRaftSecret(r) && user == nil {
			s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleGetMetrics(w, r)
		return
	}

	// Admin Routes (Individual PQC Authorization)
	if strings.HasPrefix(r.URL.Path, "/v1/admin/") {
		if user == nil {
			s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-DistFS-Sealed") != "true" {
			s.writeError(w, r, ErrCodeForbidden, "E2EE mandatory for admin operations", http.StatusForbidden)
			return
		}
		isAdmin := s.fsm.IsAdmin(user.ID)
		bypass, _ := r.Context().Value(adminBypassContextKey).(bool)
		logger.Debugf("DEBUG ADMIN ROUTE [%s]: user=%q isAdmin=%v bypass=%v", s.nodeID, user.ID, isAdmin, bypass)
		if !isAdmin {
			s.writeError(w, r, ErrCodeForbidden, "forbidden", http.StatusForbidden)
			return
		}
		s.handleAdmin(w, r)
		return
	}

	// 7. Authenticated Standard Routes (Inode / User / Group)
	if strings.HasPrefix(r.URL.Path, "/v1/user/") || strings.HasPrefix(r.URL.Path, "/v1/group/") || strings.HasPrefix(r.URL.Path, "/v1/meta/") {
		logger.Debugf("ROUTER: Path=%s Method=%s", r.URL.Path, r.Method)
		if user == nil {
			s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/v1/user/groups" && r.Method == http.MethodGet {
			s.handleListGroups(w, r)
			return
		}
		if r.URL.Path == "/v1/group/gid/allocate" && r.Method == http.MethodGet {
			s.handleAllocateGID(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/user/") && r.Method == http.MethodGet {
			id := strings.TrimPrefix(r.URL.Path, "/v1/user/")
			s.handleGetUser(w, r, id)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/v1/meta/inode/") {
			id := strings.TrimPrefix(r.URL.Path, "/v1/meta/inode/")
			if r.Method == http.MethodGet {
				s.handleGetInode(w, r, id)
				return
			}
		} else if r.URL.Path == "/v1/meta/inodes" && r.Method == http.MethodPost {
			s.handleGetInodes(w, r)
			return
		} else if r.URL.Path == "/v1/meta/token" && r.Method == http.MethodPost {
			s.handleIssueToken(w, r)
			return
		} else if r.URL.Path == "/v1/meta/batch" && r.Method == http.MethodPost {
			s.handleBatch(w, r)
			return
		} else if strings.HasPrefix(r.URL.Path, "/v1/group/") {
			id := strings.TrimPrefix(r.URL.Path, "/v1/group/")
			if id == "" {
				s.writeError(w, r, ErrCodeNotFound, "not found", http.StatusNotFound)
				return
			}
			if strings.HasSuffix(id, "/sign/private") && r.Method == http.MethodGet {
				id = strings.TrimSuffix(id, "/sign/private")
				s.handleGetGroupSignKey(w, r, id)
				return
			}
			if strings.HasSuffix(id, "/private") && r.Method == http.MethodGet {
				id = strings.TrimSuffix(id, "/private")
				s.handleGetGroupPrivateKey(w, r, id)
				return
			}
			if r.Method == http.MethodGet {
				s.handleGetGroup(w, r, id)
				return
			}
		} else if r.URL.Path == "/v1/meta/allocate" && r.Method == http.MethodPost {
			s.handleAllocateChunk(w, r)
			return
		} else if r.URL.Path == "/v1/meta/lease/acquire" && r.Method == http.MethodPost {
			s.handleAcquireLeases(w, r)
			return
		} else if r.URL.Path == "/v1/meta/lease/release" && r.Method == http.MethodPost {
			s.handleReleaseLeases(w, r)
			return
		}
	}

	s.writeError(w, r, ErrCodeNotFound, "not found", http.StatusNotFound)
}

func (s *Server) forwardIfNecessary(w http.ResponseWriter, r *http.Request) bool {
	if s.raft.State() == raft.Leader {
		return false
	}

	leaderAddr, _ := s.raft.LeaderWithID()
	if leaderAddr == "" {
		s.writeError(w, r, ErrCodeInternal, "no leader", http.StatusServiceUnavailable)
		return true
	}

	// 1. Check cache
	s.leaderURLMu.RLock()
	targetAddr, ok := s.leaderURLCache[leaderAddr]
	s.leaderURLMu.RUnlock()

	if !ok {
		// 2. Find Leader API Address in FSM
		var leaderNode Node
		err := s.fsm.db.View(func(tx *bolt.Tx) error {
			return s.fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
				var n Node
				if err := json.Unmarshal(v, &n); err == nil {
					if n.RaftAddress == string(leaderAddr) {
						leaderNode = n
						return ErrStopIteration // Hack to break early
					}
				}
				return nil
			})
		})

		if err != nil && err != ErrStopIteration {
			s.writeError(w, r, ErrCodeInternal, "leader address unknown", http.StatusServiceUnavailable)
			return true
		}
		if leaderNode.Address == "" {
			s.writeError(w, r, ErrCodeInternal, "leader address unknown", http.StatusServiceUnavailable)
			return true
		}

		targetAddr = leaderNode.Address
		if leaderNode.ClusterAddress != "" {
			targetAddr = leaderNode.ClusterAddress
		}

		if s.clientTLSConfig != nil && !strings.HasPrefix(targetAddr, "https://") {
			targetAddr = strings.Replace(targetAddr, "http://", "https://", 1)
		}

		// Update cache
		s.leaderURLMu.Lock()
		s.leaderURLCache[leaderAddr] = targetAddr
		s.leaderURLMu.Unlock()
	}

	target, err := url.Parse(targetAddr)
	if err != nil {
		s.leaderURLMu.Lock()
		delete(s.leaderURLCache, leaderAddr)
		s.leaderURLMu.Unlock()
		s.writeError(w, r, ErrCodeInternal, "invalid leader address", http.StatusInternalServerError)
		return true
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = s.forwardTransport
	proxy.ServeHTTP(w, r)
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	state := s.raft.State().String()
	isLeader := s.raft.State() == raft.Leader

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"raft_state": state,
		"is_leader":  isLeader,
	})
}

func (s *Server) handleSystemBootstrap(w http.ResponseWriter, r *http.Request) {
	// Only allowed if we don't have a secret yet.
	if s.vault.HasClusterSecret() {
		s.writeError(w, r, ErrCodeForbidden, "node already bootstrapped", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "failed to read body", http.StatusBadRequest)
		return
	}

	// Unseal using our node identity.
	plain, err := crypto.Unseal(body, s.decKey)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "failed to unseal bootstrap payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	var payload BootstrapPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		s.writeError(w, r, ErrCodeInternal, "failed to unmarshal bootstrap payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Persist to local vault
	if err := s.vault.SaveClusterSecret(payload.ClusterSecret); err != nil {
		s.writeError(w, r, ErrCodeInternal, "failed to save cluster secret: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update memory FSM secret
	s.fsm.mu.Lock()
	s.fsm.clusterSecret = payload.ClusterSecret
	s.fsm.mu.Unlock()

	// Initialize KeyRing
	if err := s.fsm.InitializeFSMKeyRing(payload.FSMKeyRing); err != nil {
		s.writeError(w, r, ErrCodeInternal, "failed to initialize FSM KeyRing: "+err.Error(), http.StatusInternalServerError)
		return
	}

	logger.Debugf("SUCCESS: Node bootstrapped with ClusterSecret and FSM KeyRing")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"id":     s.nodeID,
		"state":  s.raft.State().String(),
		"leader": s.raft.Leader(),
		"stats":  s.raft.Stats(),
	}
	s.writeJSON(w, r, status, http.StatusOK)
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
	valid := false
	clusterPub, err := s.fsm.GetClusterSignPublicKey()
	if err == nil && crypto.VerifySignature(clusterPub, payload, st.Signature) {
		valid = true
	} else if crypto.VerifySignature(s.signKey.Public(), payload, st.Signature) {
		valid = true
	}

	if !valid {
		return nil, fmt.Errorf("invalid session signature")
	}

	if time.Now().Unix() > st.Token.Expiry {
		return nil, fmt.Errorf("session expired")
	}

	var user User
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("users"), []byte(st.Token.UserID))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	var req AuthChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		s.writeError(w, r, ErrCodeInternal, "internal error", http.StatusInternalServerError)
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
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
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
		logger.Debugf("DEBUG: handleLogin: invalid challenge or user ID mismatch. entryFound=%v, entryUser=%s, solveUser=%s", ok, entry.UserID, solve.UserID)
		s.writeError(w, r, ErrCodeInternal, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	// Verify User signature over challenge
	var user User
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("users"), []byte(solve.UserID))
		if err != nil {
			return err
		}
		if plain == nil {
			logger.Debugf("DEBUG: handleLogin: user %s not found in FSM", solve.UserID)
			return fmt.Errorf("user not found")
		}
		return json.Unmarshal(plain, &user)
	})
	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, "user not found", http.StatusUnauthorized)
		return
	}

	if !crypto.VerifySignature(user.SignKey, solve.Challenge, solve.Signature) {
		logger.Debugf("DEBUG: handleLogin: invalid signature for user %s", solve.UserID)
		s.writeError(w, r, ErrCodeInternal, "invalid signature", http.StatusUnauthorized)
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

	csk := s.getClusterSignKey()

	var sig []byte
	if csk != nil {
		sig = csk.Sign(payload)
	} else {
		sig = s.signKey.Sign(payload)
	}

	// Phase 53.1: Ephemeral Session Key Exchange (KEM)
	var kemCT, sharedSecret []byte
	if len(solve.EncKey) > 0 {
		pk, err := crypto.UnmarshalEncapsulationKey(solve.EncKey)
		if err == nil {
			sharedSecret, kemCT = crypto.Encapsulate(pk)

			// Store the shared secret in the session key cache
			// Mapping is by st.Nonce (the session identifier)
			s.sessionKeyMu.Lock()
			s.sessionKeyCache[st.Nonce] = sessionKeyEntry{
				key:    sharedSecret,
				expiry: st.Expiry,
			}
			s.sessionKeyMu.Unlock()

			// Prune epochPrivateKeys
			active, err := s.fsm.GetActiveKey()
			if err == nil {
				s.epochPrivateKeysMu.Lock()
				for id := range s.epochPrivateKeys {
					if id != active.ID {
						delete(s.epochPrivateKeys, id)
					}
				}
				s.epochPrivateKeysMu.Unlock()
			}
		}
	}

	signed := SignedSessionToken{
		Token:     st,
		Signature: sig,
	}

	b, _ := json.Marshal(signed)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SessionResponse{
		Token: base64.StdEncoding.EncodeToString(b),
		KEMCT: kemCT,
	})
}

func (s *Server) handleGetClusterKey(w http.ResponseWriter, r *http.Request) {
	active, err := s.fsm.GetActiveKey()
	if err != nil {
		// If bootstrap hasn't happened or no key, return 503
		s.writeError(w, r, ErrCodeInternal, "cluster key not available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(active.EncKey)
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	if s.signKey == nil {
		s.writeError(w, r, ErrCodeInternal, "signing key not configured", http.StatusInternalServerError)
		return
	}

	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		InodeID string   `json:"inode_id"`
		Chunks  []string `json:"chunks"`
		Mode    string   `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	// Verify Permission
	var inode Inode
	exists := true
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("inodes"), []byte(req.InodeID))
		if err != nil {
			return err
		}
		if plain == nil {
			exists = false
			return nil
		}
		if err := json.Unmarshal(plain, &inode); err != nil {
			return err
		}
		return s.fsm.LoadInodeWithPages(tx, &inode)
	})
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		bypass, _ := r.Context().Value(adminBypassContextKey).(bool)
		isAdmin := s.fsm.IsAdmin(user.ID)
		if bypass && isAdmin {
			// Bypass enabled and authorized
		} else if inode.OwnerID != user.ID {
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
						msg := fmt.Sprintf("forbidden: group permission check failed (inode=%s group=%s user=%s mode=%s inode_mode=%o)", req.InodeID, inode.GroupID, user.ID, req.Mode, inode.Mode)
						log.Printf("ERROR: handleIssueToken: %s", msg)
						s.writeError(w, r, ErrCodeForbidden, "forbidden", http.StatusForbidden)
						return
					}
				} else {
					msg := fmt.Sprintf("forbidden: user not in group (inode=%s group=%s user=%s)", req.InodeID, inode.GroupID, user.ID)
					log.Printf("ERROR: handleIssueToken: %s", msg)
					s.writeError(w, r, ErrCodeForbidden, "forbidden", http.StatusForbidden)
					return
				}
			} else {
				msg := fmt.Sprintf("forbidden: permission check failed (inode=%s owner=%s user=%s mode=%s inode_mode=%o group=%s)", req.InodeID, inode.OwnerID, user.ID, req.Mode, inode.Mode, inode.GroupID)
				log.Printf("ERROR: handleIssueToken: %s", msg)
				s.writeError(w, r, ErrCodeForbidden, "forbidden", http.StatusForbidden)
				return
			}
		}
	} else {
		// Inode doesn't exist yet. Only allow "W" mode for creation.
		if req.Mode != "W" {
			s.writeError(w, r, ErrCodeNotFound, "inode not found", http.StatusNotFound)
			return
		}
	}

	// Construct Token
	capToken := CapabilityToken{
		Chunks: req.Chunks,
		Mode:   req.Mode,
		Exp:    time.Now().Add(10 * time.Minute).Unix(),
	}

	// Session Locking: Bind to SHA256(SessionID)
	if sess := r.Header.Get("Session-Token"); sess != "" {
		if b, err := base64.StdEncoding.DecodeString(sess); err == nil {
			var st SignedSessionToken
			if err := json.Unmarshal(b, &st); err == nil {
				h := sha256.Sum256([]byte(st.Token.Nonce))
				capToken.SessionBinding = h[:]
			}
		}
	}

	if len(capToken.Chunks) == 0 {
		// If empty, allow all chunks in inode?
		for _, c := range inode.ChunkManifest {
			capToken.Chunks = append(capToken.Chunks, c.ID)
		}
	}

	payload, _ := json.Marshal(capToken)

	csk := s.getClusterSignKey()

	var sig []byte
	signerID := s.nodeID
	if csk != nil {
		sig = csk.Sign(payload)
		signerID = "" // Distinguish as Cluster-wide (expected by tests)
	} else {
		sig = s.signKey.Sign(payload)
	}

	signed := SignedAuthToken{
		SignerID:  signerID,
		Payload:   payload,
		Signature: sig,
	}

	data, _ := json.Marshal(signed)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, ctxUser, data)
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

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		s.writeError(w, r, ErrCodeNotLeader, "not leader", http.StatusServiceUnavailable)
		return
	}

	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10*1024*1024))
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	var cmds []LogCommand
	if err := json.Unmarshal(body, &cmds); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad batch format", http.StatusBadRequest)
		return
	}

	for _, cmd := range cmds {
		switch cmd.Type {
		case CmdUpdateInode:
			var inode Inode
			if err := json.Unmarshal(cmd.Data, &inode); err != nil {
				s.writeError(w, r, ErrCodeInternal, "invalid inode data", http.StatusBadRequest)
				return
			}
			if err := s.checkWritePermission(r, user, inode.ID); err != nil {
				if err != ErrNotFound {
					s.writeError(w, r, ErrCodeForbidden, err.Error(), http.StatusForbidden)
					return
				}
			}
		case CmdDeleteInode:
			var id string
			if err := json.Unmarshal(cmd.Data, &id); err != nil {
				s.writeError(w, r, ErrCodeInternal, "invalid inode id", http.StatusBadRequest)
				return
			}
			if err := s.checkWritePermission(r, user, id); err != nil {
				if err != ErrNotFound {
					s.writeError(w, r, ErrCodeForbidden, err.Error(), http.StatusForbidden)
					return
				}
			}
		case CmdCreateInode:
			var inode Inode
			if err := json.Unmarshal(cmd.Data, &inode); err != nil {
				s.writeError(w, r, ErrCodeInternal, "invalid inode data", http.StatusBadRequest)
				return
			}
			bypass, _ := r.Context().Value(adminBypassContextKey).(bool)
			if !(bypass && s.fsm.IsAdmin(user.ID)) {
				if inode.OwnerID != user.ID {
					s.writeError(w, r, ErrCodeForbidden, "cannot create inode for another user", http.StatusForbidden)
					return
				}
			}
		case CmdCreateGroup:
			var group Group
			if err := json.Unmarshal(cmd.Data, &group); err != nil {
				s.writeError(w, r, ErrCodeInternal, "invalid group data", http.StatusBadRequest)
				return
			}
			if group.OwnerID != user.ID {
				s.writeError(w, r, ErrCodeForbidden, "cannot create group for another user", http.StatusForbidden)
				return
			}
			if group.IsSystem && !s.fsm.IsAdmin(user.ID) {
				s.writeError(w, r, ErrCodeForbidden, "only admins can create system groups", http.StatusForbidden)
				return
			}
		case CmdUpdateGroup:
			var group Group
			if err := json.Unmarshal(cmd.Data, &group); err != nil {
				s.writeError(w, r, ErrCodeInternal, "invalid group data", http.StatusBadRequest)
				return
			}
			if err := s.checkGroupWritePermission(r, user, &group); err != nil {
				s.writeError(w, r, ErrCodeForbidden, err.Error(), http.StatusForbidden)
				return
			}
		default:
			s.writeError(w, r, ErrCodeInternal, "unsupported batch command", http.StatusBadRequest)
			return
		}
	}

	sessionNonce := ""
	if sess := r.Header.Get("Session-Token"); sess != "" {
		if b, err := base64.StdEncoding.DecodeString(sess); err == nil {
			var st SignedSessionToken
			if err := json.Unmarshal(b, &st); err == nil {
				sessionNonce = st.Token.Nonce
			} else {
				logger.Debugf("DEBUG SERVER handleBatch: Unmarshal session failed: %v", err)
			}
		} else {
			logger.Debugf("DEBUG SERVER handleBatch: Decode session failed: %v", err)
		}
	} else {
		logger.Debugf("DEBUG SERVER handleBatch: Session-Token header is empty")
	}
	logger.Debugf("DEBUG SERVER handleBatch: extracted sessionNonce=%s from header", sessionNonce)

	// Phase 41/42: Client-submitted batches are always atomic.
	logCmd := LogCommand{
		Type:         CmdBatch,
		Data:         body,
		Atomic:       true,
		UserID:       user.ID,
		SessionNonce: sessionNonce,
	}

	f := s.raft.Apply(logCmd.Marshal(), 10*time.Second)
	if err := f.Error(); err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := f.Response()
	if s.fsm.containsError(resp) {
		status := http.StatusInternalServerError
		var firstErr error
		if slice, ok := resp.([]interface{}); ok {
			for _, item := range slice {
				if e, ok := item.(error); ok {
					firstErr = e
					break
				}
			}
		} else if e, ok := resp.(error); ok {
			firstErr = e
		}

		// Unwrap ErrAtomicRollback if necessary
		actualErr := firstErr
		if errors.Is(actualErr, ErrAtomicRollback) {
			unwrapped := errors.Unwrap(actualErr)
			if unwrapped != nil {
				actualErr = unwrapped
			}
		}

		if errors.Is(actualErr, ErrQuotaExceeded) || errors.Is(actualErr, ErrQuotaDisabled) {
			status = http.StatusForbidden
		} else if errors.Is(actualErr, ErrConflict) || errors.Is(actualErr, ErrExists) || errors.Is(actualErr, ErrLeaseRequired) {
			status = http.StatusConflict
		} else if errors.Is(actualErr, ErrNotFound) {
			status = http.StatusNotFound
		}
		resp = s.sanitizeResponse(resp)
		s.writeJSON(w, r, resp, status)
		return
	}
	s.writeJSON(w, r, s.sanitizeResponse(resp), http.StatusOK)
}

func (s *Server) verifyJWT(ctx context.Context, tokenStr string) (string, string, error) {
	s.jwks.Ready(ctx)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		return s.jwks.GetKey(kid)
	})

	if err != nil || !token.Valid {
		log.Printf("JWT Verification FAILED: %v", err)
		return "", "", fmt.Errorf("invalid jwt: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", fmt.Errorf("invalid claims")
	}
	email, _ := claims["email"].(string)
	if email == "" {
		return "", "", fmt.Errorf("jwt missing email")
	}

	secret := s.fsm.clusterSecret
	if secret == nil {
		return "", "", fmt.Errorf("cluster secret not initialized")
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(email))
	userID := hex.EncodeToString(mac.Sum(nil))

	return userID, email, nil
}

func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		s.writeError(w, r, ErrCodeNotLeader, "not leader", http.StatusServiceUnavailable)
		return
	}

	var req RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	userID, _, err := s.verifyJWT(r.Context(), req.JWT)
	if err != nil {
		s.writeError(w, r, ErrCodeUnauthorized, err.Error(), http.StatusUnauthorized)
		return
	}

	// Check if exists
	var existing User
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("users"), []byte(userID))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &existing)
	})
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(existing)
		return
	}

	// Generate unique UID
	var uid uint32
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		for i := 0; i < 1000; i++ {
			uid = generateID32()
			if uid < 1000 {
				continue
			}
			v, err := s.fsm.Get(tx, []byte("uids"), uint32ToBytes(uid))
			if err != nil {
				return err
			}
			if v == nil {
				return nil
			}
		}
		return fmt.Errorf("exhausted UID allocation attempts")
	})
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "failed to allocate UID", http.StatusInternalServerError)
		return
	}

	user := User{
		ID:      userID,
		UID:     uid,
		SignKey: req.SignKey,
		EncKey:  req.EncKey,
	}
	body, _ := json.Marshal(user)

	s.ApplyRaftCommandRaw(w, r, CmdCreateUser, body, http.StatusCreated)
}

func (s *Server) handleGetKeySync(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		log.Printf("handleGetKeySync: missing bearer token")
		s.writeError(w, r, ErrCodeUnauthorized, "missing bearer token", http.StatusUnauthorized)
		return
	}
	jwtStr := strings.TrimPrefix(auth, "Bearer ")

	userID, _, err := s.verifyJWT(r.Context(), jwtStr)
	if err != nil {
		log.Printf("handleGetKeySync: verifyJWT failed: %v", err)
		s.writeError(w, r, ErrCodeUnauthorized, err.Error(), http.StatusUnauthorized)
		return
	}

	blob, err := s.fsm.GetKeySyncBlob(userID)
	if err != nil {
		if err == ErrNotFound {
			s.writeError(w, r, ErrCodeNotFound, "not found", http.StatusNotFound)
		} else {
			s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blob)
}

func (s *Server) handleStoreKeySync(w http.ResponseWriter, r *http.Request) {
	user, err := s.authenticate(r)
	if err != nil {
		s.writeError(w, r, ErrCodeUnauthorized, err.Error(), http.StatusUnauthorized)
		return
	}

	// Session Token is present. Now check for sealing (Mandatory).
	if r.Header.Get("X-DistFS-Sealed") != "true" {
		s.writeError(w, r, ErrCodeForbidden, "E2EE mandatory for keysync storage", http.StatusForbidden)
		return
	}

	var blob KeySyncBlob
	if err := json.NewDecoder(r.Body).Decode(&blob); err != nil {
		s.writeError(w, r, ErrCodeInternal, "invalid blob format", http.StatusBadRequest)
		return
	}

	req := KeySyncRequest{
		UserID: user.ID,
		Blob:   blob,
	}
	data, _ := json.Marshal(req)

	s.ApplyRaftCommandRaw(w, r, CmdStoreKeySync, data, http.StatusCreated)
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	entries, err := s.fsm.GetUserGroups(user.ID)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := GroupListResponse{Groups: entries}
	data, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	if r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, user, data)
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

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, id string) {
	var user User
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("users"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &user)
	})
	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, err.Error(), http.StatusNotFound)
		return
	}

	// Redact sensitive info if not self/admin
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Map to public view to prevent accidental leaks
	resp := User{
		ID:      user.ID,
		UID:     user.UID,
		SignKey: user.SignKey,
		EncKey:  user.EncKey,
		IsAdmin: s.fsm.IsAdmin(user.ID),
	}
	if ctxUser.ID == id || s.fsm.IsAdmin(ctxUser.ID) {
		resp.Usage = user.Usage
		resp.Quota = user.Quota
	}
	user = resp

	data, _ := json.Marshal(user)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, ctxUser, data)
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
		return s.fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				age := time.Since(time.Unix(n.LastHeartbeat, 0))
				if n.Status == NodeStatusActive && n.Address != "" && age < 5*time.Minute {
					nodes = append(nodes, n)
				}
			}
			return nil
		})
	})
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(nodes) == 0 {
		s.writeError(w, r, ErrCodeInternal, "no active nodes", http.StatusServiceUnavailable)
		return
	}

	// Phase 53.5: Fixed Replication Factor R=3 for scalability.
	// We shuffle all active nodes and pick up to 3.
	for i := len(nodes) - 1; i > 0; i-- {
		b := make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			s.writeError(w, r, ErrCodeInternal, "entropy failure", http.StatusInternalServerError)
			return
		}
		j := int(binary.LittleEndian.Uint64(b) % uint64(i+1))
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}

	if len(nodes) > 3 {
		nodes = nodes[:3]
	}

	data, _ := json.Marshal(nodes)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, ctxUser, data)
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
		s.writeError(w, r, ErrCodeNotLeader, "not leader", http.StatusServiceUnavailable)
		return
	}
	if err := s.raft.VerifyLeader().Error(); err != nil {
		s.writeError(w, r, ErrCodeNotLeader, "lost leadership", http.StatusServiceUnavailable)
		return
	}

	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := s.checkReadPermission(r, user, id); err != nil {
		if err == ErrNotFound {
			s.writeError(w, r, ErrCodeNotFound, err.Error(), http.StatusNotFound)
		} else {
			s.writeError(w, r, ErrCodeForbidden, err.Error(), http.StatusForbidden)
		}
		return
	}

	var data []byte
	var inode Inode
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("inodes"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			return os.ErrNotExist
		}

		if err := json.Unmarshal(plain, &inode); err != nil {
			return err
		}
		if err := s.fsm.LoadInodeWithPages(tx, &inode); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, "not found", http.StatusNotFound)
		return
	}

	s.resolveURLs(inode.ChunkManifest)
	data, err = json.Marshal(inode)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, ctxUser, data)
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
		s.writeError(w, r, ErrCodeNotLeader, "not leader", http.StatusServiceUnavailable)
		return
	}
	if err := s.raft.VerifyLeader().Error(); err != nil {
		s.writeError(w, r, ErrCodeNotLeader, "lost leadership", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)

	var ids []string
	if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	if len(ids) > 1000 {
		s.writeError(w, r, ErrCodeInternal, "too many ids", http.StatusBadRequest)
		return
	}

	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	result := make([]*Inode, 0, len(ids))
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		for _, id := range ids {
			if s.checkReadPermission(r, user, id) != nil {
				continue // Skip unauthorized inodes in batch fetch
			}
			plain, err := s.fsm.Get(tx, []byte("inodes"), []byte(id))
			if err != nil || plain == nil {
				continue
			}
			var inode Inode
			if err := json.Unmarshal(plain, &inode); err == nil {
				if err := s.fsm.LoadInodeWithPages(tx, &inode); err == nil {
					result = append(result, &inode)
				}
			}
		}
		return nil
	})

	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, inode := range result {
		s.resolveURLs(inode.ChunkManifest)
	}

	data, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, ctxUser, data)
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

// evaluatePOSIXAccess checks permissions against the POSIX.1e ACL specification.
func evaluatePOSIXAccess(inode *Inode, userID string, inOwningGroup bool, userGroups []string, requiredMode uint32) bool {
	// requiredMode must be in the 3-bit space (e.g. 4 for read, 2 for write)
	req := requiredMode

	// 1. Owner
	if inode.OwnerID == userID {
		ownerBits := (inode.Mode >> 6) & 7
		return (ownerBits & req) != 0
	}

	mask := uint32(7) // default no mask
	if inode.AccessACL != nil && inode.AccessACL.Mask != nil {
		mask = *inode.AccessACL.Mask
	}

	// 2. Named Users
	if inode.AccessACL != nil && inode.AccessACL.Users != nil {
		if bits, ok := inode.AccessACL.Users[userID]; ok {
			return (bits & mask & req) != 0
		}
	}

	// 3. Groups (Owning Group + Named Groups)
	matchedGroup := false
	var groupUnion uint32 = 0

	if inOwningGroup {
		matchedGroup = true
		groupUnion |= (inode.Mode >> 3) & 7
	}

	if inode.AccessACL != nil && inode.AccessACL.Groups != nil {
		for _, gid := range userGroups {
			if bits, ok := inode.AccessACL.Groups[gid]; ok {
				matchedGroup = true
				groupUnion |= bits
			}
		}
	}

	if matchedGroup {
		return (groupUnion & mask & req) != 0
	}

	// 4. Other
	otherBits := inode.Mode & 7
	return (otherBits & req) != 0
}

func (s *Server) checkReadPermission(r *http.Request, user *User, inodeID string) error {
	bypass, _ := r.Context().Value(adminBypassContextKey).(bool)
	if bypass && s.fsm.IsAdmin(user.ID) {
		return nil
	}
	var inode Inode
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("inodes"), []byte(inodeID))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &inode)
	})
	if err != nil {
		return err
	}

	inOwningGroup := false
	if inode.GroupID != "" {
		inOwningGroup, _ = s.fsm.IsUserInGroup(user.ID, inode.GroupID)
	}
	userGroups, _ := s.fsm.GetUserGroupIDs(user.ID)

	if evaluatePOSIXAccess(&inode, user.ID, inOwningGroup, userGroups, 0004) {
		return nil
	}

	return fmt.Errorf("forbidden")
}

func (s *Server) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	var node Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		s.writeError(w, r, ErrCodeInternal, "invalid node data", http.StatusBadRequest)
		return
	}
	if node.LastHeartbeat == 0 {
		node.LastHeartbeat = time.Now().Unix()
	}
	data, _ := json.Marshal(node)
	s.ApplyRaftCommandWithHook(w, r, CmdRegisterNode, data, http.StatusCreated, nil)
}

func (s *Server) handleAllocateGID(w http.ResponseWriter, r *http.Request) {
	var gid uint32
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		for i := 0; i < 1000; i++ {
			gid = generateID32()
			if gid < 1000 {
				continue
			}
			v, err := s.fsm.Get(tx, []byte("gids"), uint32ToBytes(gid))
			if err != nil {
				return err
			}
			if v == nil {
				return nil
			}
		}
		return fmt.Errorf("exhausted GID allocation attempts")
	})
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, r, map[string]uint32{"gid": gid}, http.StatusOK)
}

func (s *Server) handleRemoveNode(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.removeNodeInternal(id); err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) removeNodeInternal(id string) error {
	if s.raft.State() != raft.Leader {
		return fmt.Errorf("not leader")
	}

	// 1. Remove from Raft (Configuration Change)
	f := s.raft.RemoveServer(raft.ServerID(id), 0, 0)
	if err := f.Error(); err != nil {
		// Log but continue to ensure FSM is also purged if possible.
		log.Printf("Warning: Raft RemoveServer for %s: %v", id, err)
	}

	// 2. Remove from FSM (Registry & Trust)
	data, _ := json.Marshal(id)
	_, err := s.ApplyRaftCommandInternal(CmdRemoveNode, data, "")
	return err
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request, id string) {
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 1. Fetch group first to check ownership/membership
	var group Group
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("groups"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &group)
	})
	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, err.Error(), http.StatusNotFound)
		return
	}

	// 2. Check Authorization
	authorized := false
	if group.OwnerID == user.ID {
		authorized = true
	} else if group.Members != nil && group.Members[user.ID] {
		authorized = true
	} else {
		// Check if OwnerID is a group we are in
		inOwningGroup, _ := s.fsm.IsUserInGroup(user.ID, group.OwnerID)
		if inOwningGroup {
			authorized = true
		}
	}

	isAdmin := s.fsm.IsAdmin(user.ID)
	if !authorized && !isAdmin {
		s.writeError(w, r, ErrCodeForbidden, "forbidden", http.StatusForbidden)
		return
	}

	data, _ := json.Marshal(group)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, ctxUser, data)
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

func (s *Server) checkGroupWritePermission(r *http.Request, user *User, updatedGroup *Group) error {
	bypass, _ := r.Context().Value(adminBypassContextKey).(bool)
	if bypass && s.fsm.IsAdmin(user.ID) {
		return nil
	}

	// 1. Fetch existing group
	existing, err := s.fsm.GetGroup(updatedGroup.ID)
	if err != nil {
		return err
	}

	// 2. Check Authorization based on OwnerID
	authorized := false
	if existing.OwnerID == user.ID {
		authorized = true
	} else {
		// Check if OwnerID is a group we are in
		inGroup, _ := s.fsm.IsUserInGroup(user.ID, existing.OwnerID)
		if inGroup {
			authorized = true
		}
	}

	if !authorized {
		return fmt.Errorf("user %s not authorized to manage group %s", user.ID, updatedGroup.ID)
	}

	// 2.1 Enforce IsSystem modification only for admins
	if updatedGroup.IsSystem != existing.IsSystem && !s.fsm.IsAdmin(user.ID) {
		return fmt.Errorf("only admins can modify system status")
	}

	return nil
}

// ApplyRaftCommand handles a generic Raft command proposal from an HTTP request.
func (s *Server) ApplyRaftCommand(w http.ResponseWriter, r *http.Request, cmdType CommandType, limit int64, successCode int) {
	if s.raft.State() != raft.Leader {
		s.writeError(w, r, ErrCodeNotLeader, "not leader", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "failed to read body", http.StatusBadRequest)
		return
	}

	s.ApplyRaftCommandRaw(w, r, cmdType, body, successCode)
}

// ApplyRaftCommandRaw proposes a raw data payload to Raft.
func (s *Server) ApplyRaftCommandRaw(w http.ResponseWriter, r *http.Request, cmdType CommandType, data []byte, successCode int) {
	s.ApplyRaftCommandWithHook(w, r, cmdType, data, successCode, nil)
}

// ApplyRaftCommandWithHook proposes a Raft command and executes a hook on the result before responding.
func (s *Server) ApplyRaftCommandWithHook(w http.ResponseWriter, r *http.Request, cmdType CommandType, data []byte, successCode int, hook func(interface{}) interface{}) {
	userID := ""
	if user, ok := r.Context().Value(userContextKey).(*User); ok && user != nil {
		userID = user.ID
	}
	resp, err := s.ApplyRaftCommandInternal(cmdType, data, userID)
	if err != nil {
		if w == nil {
			return
		}
		if err.Error() == "not leader" {
			s.writeError(w, r, ErrCodeNotLeader, "not leader", http.StatusServiceUnavailable)
			return
		}
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrExists) {
			s.writeError(w, r, ErrCodeVersionConflict, err.Error(), http.StatusConflict)
		} else if errors.Is(err, ErrNotFound) {
			s.writeError(w, r, ErrCodeNotFound, err.Error(), http.StatusNotFound)
		} else if errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrQuotaDisabled) {
			s.writeError(w, r, ErrCodeQuotaExceeded, err.Error(), http.StatusForbidden)
		} else {
			s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if w != nil {
		if resp != nil {
			if s.fsm.containsError(resp) {
				// Find the first error to determine status code
				status := http.StatusInternalServerError
				var firstErr error
				if slice, ok := resp.([]interface{}); ok {
					for _, item := range slice {
						if e, ok := item.(error); ok {
							firstErr = e
							break
						}
					}
				} else if e, ok := resp.(error); ok {
					firstErr = e
				}

				if errors.Is(firstErr, ErrQuotaExceeded) || errors.Is(firstErr, ErrQuotaDisabled) {
					status = http.StatusForbidden
				} else if errors.Is(firstErr, ErrConflict) || errors.Is(firstErr, ErrExists) || errors.Is(firstErr, ErrLeaseRequired) || errors.Is(firstErr, ErrStructuralInconsistency) {
					status = http.StatusConflict
				} else if errors.Is(firstErr, ErrNotFound) {
					status = http.StatusNotFound
				}

				resp = s.sanitizeResponse(resp)
				s.writeJSON(w, r, resp, status)
				return
			}

			if hook != nil {
				resp = hook(resp)
			}

			resp = s.sanitizeResponse(resp)
			s.writeJSON(w, r, resp, successCode)
			return
		}

		if hook != nil {
			resp = hook(nil)
		}

		w.WriteHeader(successCode)
	}
}

// ApplyRaftCommandInternal proposes a command to Raft from an internal server context.
func (s *Server) ApplyRaftCommandInternal(cmdType CommandType, data []byte, userID string) (interface{}, error) {
	if s.raft.State() != raft.Leader {
		return nil, fmt.Errorf("not leader")
	}

	cmd := &LogCommand{
		Type:   cmdType,
		Data:   data,
		UserID: userID,
		Atomic: cmdType == CmdBatch,
	}

	if cmd.Atomic {
		f := s.raft.Apply(cmd.Marshal(), 5*time.Second)
		if err := f.Error(); err != nil {
			return nil, err
		}
		resp := f.Response()
		if err, ok := resp.(error); ok {
			return nil, err
		}
		if s, ok := resp.(string); ok && strings.HasPrefix(s, "api error:") {
			return nil, fmt.Errorf("%s", s)
		}
		return resp, nil
	}

	respCh := make(chan interface{}, 1)

	s.batchMu.Lock()
	s.batchQueue = append(s.batchQueue, cmd)
	s.batchResps = append(s.batchResps, respCh)

	if len(s.batchQueue) >= 100 {
		if s.batchTimer != nil {
			s.batchTimer.Stop()
		}
		s.flushBatchLocked()
	} else if s.batchTimer == nil {
		s.batchTimer = time.AfterFunc(2*time.Millisecond, s.flushBatch)
	}
	s.batchMu.Unlock()

	res := <-respCh
	if err, ok := res.(error); ok && err != nil {
		return nil, err
	}
	return res, nil
}

// FSM returns the underlying Metadata State Machine.
func (s *Server) FSM() *MetadataFSM {
	return s.fsm
}

func (s *Server) SessionKeyCacheSize() int {
	s.sessionKeyMu.RLock()
	defer s.sessionKeyMu.RUnlock()
	return len(s.sessionKeyCache)
}

func (fsm *MetadataFSM) DB() *bolt.DB {
	return fsm.db
}

func (s *Server) flushBatch() {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	s.flushBatchLocked()
}

func (s *Server) flushBatchLocked() {
	if len(s.batchQueue) == 0 {
		s.batchTimer = nil
		return
	}

	batch := batchRequest{
		cmds:  make([]*LogCommand, len(s.batchQueue)),
		resps: make([]chan interface{}, len(s.batchResps)),
	}
	copy(batch.cmds, s.batchQueue)
	copy(batch.resps, s.batchResps)

	s.batchQueue = nil
	s.batchResps = nil
	s.batchTimer = nil

	// Use blocking send to provide backpressure instead of 503 Busy
	select {
	case s.batchApplyCh <- batch:
	case <-s.stopCh:
		for _, ch := range batch.resps {
			ch <- fmt.Errorf("server stopping")
		}
	}
}

func (s *Server) sealResponse(r *http.Request, user *User, payload []byte) ([]byte, error) {
	// Phase 53.1: Try symmetric sealing if session key is present in context (Forward Secrecy)
	if r != nil {
		if sessionKey, ok := r.Context().Value(sessionKeyContextKey).([]byte); ok && len(sessionKey) > 0 {
			sealed, err := crypto.SealResponseSymmetric(sessionKey, s.signKey, payload)
			if err == nil {
				res := SealedResponse{
					Sealed: sealed,
				}
				return json.Marshal(res)
			}
		}
	}

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

func (s *Server) checkWritePermission(r *http.Request, user *User, inodeID string) error {
	var inode Inode
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("inodes"), []byte(inodeID))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &inode)
	})
	if err != nil {
		return err
	}

	inOwningGroup := false
	if inode.GroupID != "" {
		inOwningGroup, _ = s.fsm.IsUserInGroup(user.ID, inode.GroupID)
	}
	userGroups, _ := s.fsm.GetUserGroupIDs(user.ID)

	if evaluatePOSIXAccess(&inode, user.ID, inOwningGroup, userGroups, 0002) {
		return nil
	}

	return fmt.Errorf("forbidden")
}

func (s *Server) handleGetGroupPrivateKey(w http.ResponseWriter, r *http.Request, id string) {
	user, err := s.authenticate(r)
	if err != nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	inGroup, err := s.fsm.IsUserInGroup(user.ID, id)
	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, "group not found", http.StatusNotFound)
		return
	}
	if !inGroup {
		s.writeError(w, r, ErrCodeForbidden, "forbidden", http.StatusForbidden)
		return
	}

	var group Group
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("groups"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &group)
	})
	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, "group not found", http.StatusNotFound)
		return
	}

	// Group Private Key is stored in group.Lockbox, encrypted for each member.
	entry, ok := group.Lockbox[user.ID]
	if !ok {
		// Should not happen if IsUserInGroup returned true, but for safety:
		s.writeError(w, r, ErrCodeInternal, "user not in group lockbox", http.StatusInternalServerError)
		return
	}

	data, _ := json.Marshal(entry)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, user, data)
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

func (s *Server) handleGetGroupSignKey(w http.ResponseWriter, r *http.Request, id string) {
	user, err := s.authenticate(r)
	if err != nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	inGroup, err := s.fsm.IsUserInGroup(user.ID, id)
	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, "group not found", http.StatusNotFound)
		return
	}
	if !inGroup {
		s.writeError(w, r, ErrCodeForbidden, "forbidden", http.StatusForbidden)
		return
	}

	var group Group
	err = s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("groups"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &group)
	})
	if err != nil {
		s.writeError(w, r, ErrCodeNotFound, "group not found", http.StatusNotFound)
		return
	}

	// Group Signing Key is stored in group.Lockbox with ":sign" suffix, encrypted for each member.
	entry, ok := group.Lockbox[user.ID+":sign"]
	if !ok {
		// Old groups might not have this, or user wasn't added with it
		s.writeError(w, r, ErrCodeInternal, "group signing key not available for user", http.StatusNotFound)
		return
	}

	data, _ := json.Marshal(entry)
	w.Header().Set("Content-Type", "application/json")

	// E2EE?
	if user != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, user, data)
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

const (
	raftSecretHeader    = "X-Raft-Secret"
	raftNonceHeader     = "X-Raft-Nonce"
	raftSignatureHeader = "X-Raft-Signature"
	raftResponseHeader  = "X-Raft-Response"
)

func (s *Server) signNonce(nonce []byte, label string) string {
	mac := hmac.New(sha256.New, []byte(s.raftSecret))
	mac.Write(nonce)
	mac.Write([]byte(label))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) verifySignature(nonce []byte, label, signature string) bool {
	expected := s.signNonce(nonce, label)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) == 1
}

func (s *Server) checkRaftSecret(r *http.Request) bool {
	if s.raftSecret == "" {
		return false // Fail closed
	}
	provided := sha256.Sum256([]byte(r.Header.Get("X-Raft-Secret")))
	expected := sha256.Sum256([]byte(s.raftSecret))
	return subtle.ConstantTimeCompare(provided[:], expected[:]) == 1
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/admin/")
	switch {
	case path == "users" && r.Method == http.MethodGet:
		s.handleClusterUsers(w, r)
	case path == "groups" && r.Method == http.MethodGet:
		s.handleClusterGroups(w, r)
	case path == "leases" && r.Method == http.MethodGet:
		s.handleClusterLeases(w, r)
	case path == "nodes" && r.Method == http.MethodGet:
		s.handleClusterNodes(w, r)
	case path == "status" && r.Method == http.MethodGet:
		s.handleClusterStatus(w, r)
	case path == "lookup" && r.Method == http.MethodPost:
		s.handleClusterLookup(w, r)
	case path == "join" && r.Method == http.MethodPost:
		s.handleClusterJoin(w, r)
	case path == "remove" && r.Method == http.MethodPost:
		s.handleClusterRemove(w, r)
	case path == "node" && r.Method == http.MethodPost:
		s.handleRegisterNode(w, r)
	case path == "promote" && r.Method == http.MethodPost:
		s.handleAdminPromote(w, r)
	case path == "lock" && r.Method == http.MethodPost:
		s.handleAdminSetUserLock(w, r)
	case path == "audit" && r.Method == http.MethodGet:
		s.handleAudit(w, r)
	case path == "quota/user" && r.Method == http.MethodPost:
		s.handleSetUserQuota(w, r)
	case path == "quota/group" && r.Method == http.MethodPost:
		s.handleSetGroupQuota(w, r)
	default:
		s.writeError(w, r, ErrCodeNotFound, "not found", http.StatusNotFound)
	}
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, code string, message string, status int) {
	resp := APIErrorResponse{
		Code:    code,
		Message: message,
	}
	s.writeJSON(w, r, resp, status)
}

func (s *Server) sanitizeResponse(res interface{}) interface{} {
	if err, ok := res.(error); ok {
		code := ErrCodeInternal
		if errors.Is(err, ErrQuotaExceeded) {
			code = ErrCodeQuotaExceeded
		} else if errors.Is(err, ErrConflict) {
			code = ErrCodeVersionConflict
		} else if errors.Is(err, ErrExists) {
			code = ErrCodeExists
		} else if errors.Is(err, ErrNotFound) {
			code = ErrCodeNotFound
		} else if errors.Is(err, ErrLeaseRequired) {
			code = ErrCodeLeaseRequired
		} else if errors.Is(err, ErrStructuralInconsistency) {
			code = ErrCodeStructuralInconsistency
		} else if errors.Is(err, ErrAtomicRollback) {
			code = ErrCodeAtomicRollback
		} else if errors.Is(err, ErrQuotaDisabled) {
			code = ErrCodeQuotaDisabled
		}
		return APIErrorResponse{Code: code, Message: err.Error()}
	}
	if slice, ok := res.([]interface{}); ok {
		sanitized := make([]interface{}, len(slice))
		for i, item := range slice {
			sanitized[i] = s.sanitizeResponse(item)
		}
		return sanitized
	}
	return res
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, data interface{}, status int) {
	b, err := json.Marshal(data)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if status == 0 {
		status = http.StatusOK
	}

	// E2EE?
	ctxUser, _ := r.Context().Value(userContextKey).(*User)
	if ctxUser != nil && r.Header.Get("X-DistFS-Sealed") == "true" {
		sealed, err := s.sealResponse(r, ctxUser, b)
		if err == nil {
			w.Header().Set("X-DistFS-Sealed", "true")
			w.WriteHeader(status)
			w.Write(sealed)
			return
		}
		// If sealing fails, we still want to return the error/data with original status
	}

	w.WriteHeader(status)
	w.Write(b)
}

func (s *Server) RedactUser(u *User) {
	u.SignKey = nil
	u.EncKey = nil
}

func (s *Server) RedactGroup(g *Group) {
	g.EncKey = nil
	g.SignKey = nil
	g.EncryptedSignKey = nil
	g.Lockbox = nil
	g.RegistryLockbox = nil
	g.EncryptedRegistry = nil
	g.Members = nil // Bulk lists shouldn't reveal member IDs
}

func (s *Server) RedactNode(n *Node) {
	n.PublicKey = nil
	n.SignKey = nil
}

func (s *Server) handleClusterUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		return s.fsm.ForEach(tx, []byte("users"), func(k, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err == nil {
				s.RedactUser(&u)
				users = append(users, u)
			}
			return nil
		})
	})
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, r, users, http.StatusOK)
}

func (s *Server) handleClusterGroups(w http.ResponseWriter, r *http.Request) {
	cursor := r.URL.Query().Get("cursor")
	limitStr := r.URL.Query().Get("limit")
	limit := 1000 // Default limit for admin console
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	groups, nextCursor, err := s.fsm.GetGroups(cursor, limit)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redact sensitive fields in bulk list
	for i := range groups {
		s.RedactGroup(&groups[i])
	}

	if nextCursor != "" {
		w.Header().Set("X-DistFS-Next-Cursor", nextCursor)
	}
	s.writeJSON(w, r, groups, http.StatusOK)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	// 1. Authorization
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil || !s.fsm.IsAdmin(user.ID) {
		s.writeError(w, r, ErrCodeForbidden, "admin privileges required", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)

	// 2. Perform Audit in a single View transaction
	s.fsm.db.View(func(tx *bolt.Tx) error {
		// A. Nodes
		s.fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				// Redact keys
				n.PublicKey = nil
				n.SignKey = nil
				encoder.Encode(AuditRecord{Type: AuditNode, Node: &n})
			}
			return nil
		})

		// B. Users & Quota Validation
		userUsage := make(map[string]UserUsage)
		s.fsm.ForEach(tx, []byte("users"), func(k, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err == nil {
				// Index Check
				uidKey := uint32ToBytes(u.UID)
				mappedID, _ := s.fsm.Get(tx, []byte("uids"), uidKey)
				if string(mappedID) != u.ID {
					encoder.Encode(AuditRecord{
						Type: AuditInconsistency,
						Report: &InconsistencyReport{
							Type:     "INDEX_MISMATCH",
							TargetID: u.ID,
							Message:  fmt.Sprintf("UID %d maps to %s, expected %s", u.UID, string(mappedID), u.ID),
						},
					})
				}

				encoder.Encode(AuditRecord{
					Type: AuditUser,
					User: &RedactedUser{
						ID:      u.ID,
						UID:     u.UID,
						Usage:   u.Usage,
						Quota:   u.Quota,
						IsAdmin: s.fsm.IsAdmin(u.ID),
					},
				})
			}
			return nil
		})

		// C. Groups
		s.fsm.ForEach(tx, []byte("groups"), func(k, v []byte) error {
			var g Group
			if err := json.Unmarshal(v, &g); err == nil {
				// Index Check
				gidKey := uint32ToBytes(g.GID)
				mappedID, _ := s.fsm.Get(tx, []byte("gids"), gidKey)
				if string(mappedID) != g.ID {
					encoder.Encode(AuditRecord{
						Type: AuditInconsistency,
						Report: &InconsistencyReport{
							Type:     "INDEX_MISMATCH",
							TargetID: g.ID,
							Message:  fmt.Sprintf("GID %d maps to %s, expected %s", g.GID, string(mappedID), g.ID),
						},
					})
				}

				encoder.Encode(AuditRecord{
					Type: AuditGroup,
					Group: &RedactedGroup{
						ID:           g.ID,
						GID:          g.GID,
						OwnerID:      g.OwnerID,
						Usage:        g.Usage,
						Quota:        g.Quota,
						QuotaEnabled: g.QuotaEnabled,
						MemberCount:  len(g.Members),
						IsSystem:     g.IsSystem,
					},
				})
			}
			return nil
		})

		// D. Inodes & Link Symmetry
		groupUsage := make(map[string]UserUsage)
		s.fsm.ForEach(tx, []byte("inodes"), func(k, v []byte) error {
			var i Inode
			if err := json.Unmarshal(v, &i); err == nil {
				// Accounting: Accumulate usage for validation
				targetUser := i.OwnerID
				targetGroup := i.GroupID

				isGroupBilled := false
				if targetGroup != "" {
					gPlain, _ := s.fsm.Get(tx, []byte("groups"), []byte(targetGroup))
					if gPlain != nil {
						var g Group
						json.Unmarshal(gPlain, &g)
						if g.QuotaEnabled {
							isGroupBilled = true
						}
					}
				}

				if isGroupBilled {
					curr := groupUsage[targetGroup]
					curr.InodeCount++
					curr.TotalBytes += int64(i.Size)
					groupUsage[targetGroup] = curr
				} else if targetUser != "" {
					curr := userUsage[targetUser]
					curr.InodeCount++
					curr.TotalBytes += int64(i.Size)
					userUsage[targetUser] = curr
				}

				// Redaction
				recipients := make([]string, 0, len(i.Lockbox))
				for rid := range i.Lockbox {
					recipients = append(recipients, rid)
				}

				ri := &RedactedInode{
					ID:             i.ID,
					Links:          i.Links,
					Type:           i.Type,
					OwnerID:        i.OwnerID,
					GroupID:        i.GroupID,
					Mode:           i.Mode,
					Size:           i.Size,
					CTime:          i.CTime,
					NLink:          i.NLink,
					Children:       i.Children,
					Version:        i.Version,
					IsSystem:       i.IsSystem,
					Leases:         i.Leases,
					Unlinked:       i.Unlinked,
					SignerID:       i.SignerID,
					BlobSize:       len(i.ClientBlob),
					ChunkPageCount: len(i.ChunkPages),
					RecipientIDs:   recipients,
				}

				// Structural Symmetry Check
				if i.Type == DirType {
					for nameHMAC, childID := range i.Children {
						childPlain, _ := s.fsm.Get(tx, []byte("inodes"), []byte(childID))
						if childPlain == nil {
							encoder.Encode(AuditRecord{
								Type: AuditInconsistency,
								Report: &InconsistencyReport{
									Type:     "DANGLING_CHILD",
									TargetID: i.ID,
									Message:  fmt.Sprintf("child %s (%s) not found", nameHMAC, childID),
								},
							})
						} else {
							var child Inode
							if err := json.Unmarshal(childPlain, &child); err != nil {
								encoder.Encode(AuditRecord{
									Type: AuditInconsistency,
									Report: &InconsistencyReport{
										Type:     "CORRUPT_METADATA",
										TargetID: childID,
										Message:  fmt.Sprintf("failed to decode child inode: %v", err),
									},
								})
								continue
							}
							expectedLink := i.ID + ":" + nameHMAC
							if !child.Links[expectedLink] {
								encoder.Encode(AuditRecord{
									Type: AuditInconsistency,
									Report: &InconsistencyReport{
										Type:     "ASYMMETRIC_LINK",
										TargetID: childID,
										Message:  fmt.Sprintf("child missing link back to parent %s", i.ID),
									},
								})
							}
						}
					}
				}

				encoder.Encode(AuditRecord{Type: AuditInode, Inode: ri})
			}
			return nil
		})

		// E. GC & Lifecycle
		s.fsm.ForEach(tx, []byte("garbage_collection"), func(k, v []byte) error {
			encoder.Encode(AuditRecord{Type: AuditGC, GCChunk: string(k)})
			return nil
		})

		s.fsm.ForEach(tx, []byte("unlinked_inodes"), func(k, v []byte) error {
			id := string(k)
			encoder.Encode(AuditRecord{Type: AuditLease, GCChunk: id}) // Reuse field
			return nil
		})

		for uid, calc := range userUsage {
			uPlain, _ := s.fsm.Get(tx, []byte("users"), []byte(uid))
			if uPlain != nil {
				var u User
				if err := json.Unmarshal(uPlain, &u); err != nil {
					encoder.Encode(AuditRecord{
						Type: AuditInconsistency,
						Report: &InconsistencyReport{
							Type:     "CORRUPT_METADATA",
							TargetID: uid,
							Message:  fmt.Sprintf("failed to decode user record: %v", err),
						},
					})
					continue
				}
				if u.Usage.InodeCount != calc.InodeCount || u.Usage.TotalBytes != calc.TotalBytes {
					encoder.Encode(AuditRecord{
						Type: AuditInconsistency,
						Report: &InconsistencyReport{
							Type:     "USER_QUOTA_MISMATCH",
							TargetID: uid,
							Message:  fmt.Sprintf("DB: {Inodes:%d, Bytes:%d}, Calculated: {Inodes:%d, Bytes:%d}", u.Usage.InodeCount, u.Usage.TotalBytes, calc.InodeCount, calc.TotalBytes),
						},
					})
				}
			}
		}
		for gid, calc := range groupUsage {
			gPlain, _ := s.fsm.Get(tx, []byte("groups"), []byte(gid))
			if gPlain != nil {
				var g Group
				if err := json.Unmarshal(gPlain, &g); err != nil {
					encoder.Encode(AuditRecord{
						Type: AuditInconsistency,
						Report: &InconsistencyReport{
							Type:     "CORRUPT_METADATA",
							TargetID: gid,
							Message:  fmt.Sprintf("failed to decode group record: %v", err),
						},
					})
					continue
				}
				if g.Usage.InodeCount != calc.InodeCount || g.Usage.TotalBytes != calc.TotalBytes {
					encoder.Encode(AuditRecord{
						Type: AuditInconsistency,
						Report: &InconsistencyReport{
							Type:     "GROUP_QUOTA_MISMATCH",
							TargetID: gid,
							Message:  fmt.Sprintf("DB: {Inodes:%d, Bytes:%d}, Calculated: {Inodes:%d, Bytes:%d}", g.Usage.InodeCount, g.Usage.TotalBytes, calc.InodeCount, calc.TotalBytes),
						},
					})
				}
			}
		}

		return nil
	})
}

func (s *Server) handleClusterLeases(w http.ResponseWriter, r *http.Request) {
	leases, err := s.fsm.GetLeases()
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, r, leases, http.StatusOK)
}

func (s *Server) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	var nodes []Node
	err := s.fsm.db.View(func(tx *bolt.Tx) error {
		return s.fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				s.RedactNode(&n)
				nodes = append(nodes, n)
			}
			return nil
		})
	})
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, r, nodes, http.StatusOK)
}

func (s *Server) handleClusterLookup(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userContextKey).(*User)
	var req struct {
		Email  string `json:"email"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	if req.Reason == "" {
		s.writeError(w, r, ErrCodeInternal, "reason required for deanonymization lookup", http.StatusBadRequest)
		return
	}

	secret, err := s.fsm.GetClusterSecret()
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "cluster secret unavailable", http.StatusInternalServerError)
		return
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(req.Email))
	hash := hex.EncodeToString(mac.Sum(nil))

	log.Printf("AUDIT: Admin %s resolved email to UserID %s. Reason: %s", user.ID, hash, req.Reason)

	s.writeJSON(w, r, map[string]string{"id": hash}, http.StatusOK)
}

func (s *Server) handleClusterRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	if err := s.removeNodeInternal(req.ID); err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	if s.raft.State() != raft.Leader {
		s.writeError(w, r, ErrCodeNotLeader, "not leader", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Address string `json:"address"` // Node API address (e.g. http://node-2:8080)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	// 1. Discover node metadata via internal API with Mutual HMAC Handshake
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		s.writeError(w, r, ErrCodeInternal, "internal error", http.StatusInternalServerError)
		return
	}

	infoURL := strings.TrimSuffix(req.Address, "/") + "/v1/node/info"
	var resp *http.Response
	var lastDiscoveryErr error

	for i := 0; i < 5; i++ {
		discoveryReq, err := http.NewRequest("GET", infoURL, nil)
		if err != nil {
			s.writeError(w, r, ErrCodeInternal, "invalid address", http.StatusBadRequest)
			return
		}
		discoveryReq.Header.Set(raftNonceHeader, hex.EncodeToString(nonce))
		discoveryReq.Header.Set(raftSignatureHeader, s.signNonce(nonce, "LEADER_PROBE"))

		resp, err = s.discoveryHTTPClient.Do(discoveryReq)
		if err == nil {
			break
		}
		lastDiscoveryErr = err
		logger.Debugf("DEBUG: Discovery of %s failed (attempt %d): %v", req.Address, i+1, err)
		time.Sleep(100 * time.Millisecond)
	}

	if resp == nil {
		s.writeError(w, r, ErrCodeInternal, fmt.Sprintf("discovery failed after retries: %v", lastDiscoveryErr), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		s.writeError(w, r, ErrCodeInternal, "node rejected leader signature (secret mismatch?)", http.StatusForbidden)
		return
	}

	// Verify node response signature
	nodeSig := resp.Header.Get(raftResponseHeader)
	if !s.verifySignature(nonce, "NODE_RESPONSE", nodeSig) {
		s.writeError(w, r, ErrCodeInternal, "invalid node response signature (secret mismatch?)", http.StatusForbidden)
		return
	}

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		s.writeError(w, r, ErrCodeInternal, "discovery requires mTLS connection", http.StatusInternalServerError)
		return
	}

	// Capture probed key from TLS Handshake
	probedCert := resp.TLS.PeerCertificates[0]
	probedEdKey, ok := probedCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		s.writeError(w, r, ErrCodeInternal, "probed peer key is not Ed25519", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		s.writeError(w, r, ErrCodeInternal, fmt.Sprintf("discovery failed: status %d", resp.StatusCode), http.StatusInternalServerError)
		return
	}

	var info struct {
		ID          string `json:"id"`
		APIURL      string `json:"api_url"`
		RaftAddress string `json:"raft_address"`
		PublicKey   []byte `json:"public_key"`
		SignKey     []byte `json:"sign_key"`
		EncKey      []byte `json:"enc_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		s.writeError(w, r, ErrCodeInternal, "invalid discovery response", http.StatusInternalServerError)
		return
	}

	// Cryptographic TOFU Match: Handshake Key must match reported Key
	if !bytes.Equal(probedEdKey, info.PublicKey) {
		s.writeError(w, r, ErrCodeInternal, "CRITICAL: TOFU key mismatch (man-in-the-middle detected?)", http.StatusForbidden)
		return
	}

	// 2. Check if already in cluster
	cfg := s.raft.GetConfiguration()
	if err := cfg.Error(); err == nil {
		for _, srv := range cfg.Configuration().Servers {
			if srv.ID == raft.ServerID(info.ID) {
				s.writeError(w, r, ErrCodeForbidden, "node already registered in cluster", http.StatusBadRequest)
				return
			}
		}
	}

	// 3. Push ClusterSecret and KeyRing to the new node via internal mTLS FIRST
	secret, err := s.fsm.GetClusterSecret()
	if err != nil {
		log.Printf("ERROR: ClusterSecret not available for push: %v", err)
		s.writeError(w, r, ErrCodeInternal, "ClusterSecret not available", http.StatusInternalServerError)
		return
	}

	payload := BootstrapPayload{
		ClusterSecret: secret,
		FSMKeyRing:    s.fsm.GetFSMKeyRing(),
	}
	payloadBytes, _ := json.Marshal(payload)

	probedKEM, err := crypto.UnmarshalEncapsulationKey(info.EncKey)
	if err != nil {
		log.Printf("ERROR: EncKey: %v", err)
		s.writeError(w, r, ErrCodeInternal, "invalid public key", http.StatusBadRequest)
		return
	}

	encPayload, err := crypto.Seal(payloadBytes, probedKEM, time.Now().UnixNano())
	if err != nil {
		log.Printf("ERROR: Seal: %v", err)
		s.writeError(w, r, ErrCodeInternal, "failed to seal bootstrap payload", http.StatusInternalServerError)
		return
	}

	bootstrapURL := strings.TrimSuffix(req.Address, "/") + "/v1/system/bootstrap"
	var pushResp *http.Response
	var lastPushErr error
	alreadyBootstrapped := false

	for i := 0; i < 5; i++ {
		pushReq, err := http.NewRequestWithContext(r.Context(), "POST", bootstrapURL, bytes.NewReader(encPayload))
		if err != nil {
			log.Printf("ERROR: Failed to create bootstrap push request: %v", err)
			s.writeError(w, r, ErrCodeInternal, "failed to create push request", http.StatusInternalServerError)
			return
		}
		pushReq.Header.Set("Content-Type", "application/octet-stream")
		if s.raftSecret != "" {
			pushReq.Header.Set("X-Raft-Secret", s.raftSecret)
		}

		// We use discoveryHTTPClient here because the joining node's certificate
		// is not yet in the FSM's trusted list. The payload is sealed with the node's
		// ML-KEM key, ensuring confidentiality.
		pushResp, err = s.discoveryHTTPClient.Do(pushReq)
		if err == nil {
			if pushResp.StatusCode == http.StatusOK {
				break
			}
			if pushResp.StatusCode == http.StatusForbidden || pushResp.StatusCode == http.StatusNotFound {
				alreadyBootstrapped = true
				break
			}
			b, _ := io.ReadAll(pushResp.Body)
			lastPushErr = fmt.Errorf("status %d (%s)", pushResp.StatusCode, b)
			pushResp.Body.Close()
		} else {
			lastPushErr = err
		}
		logger.Debugf("DEBUG: Push to %s failed (attempt %d): %v", bootstrapURL, i+1, lastPushErr)
		select {
		case <-r.Context().Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}

	if pushResp != nil {
		pushResp.Body.Close()
	}

	if err != nil || (pushResp != nil && pushResp.StatusCode != http.StatusOK && !alreadyBootstrapped) {
		log.Printf("ERROR: Node %s rejected ClusterSecret push: %v", req.Address, lastPushErr)
		s.writeError(w, r, ErrCodeInternal, fmt.Sprintf("node rejected cluster secret push: %v", lastPushErr), http.StatusInternalServerError)
		return
	}

	if alreadyBootstrapped {
		logger.Debugf("SUCCESS: Node %s already has ClusterSecret", req.Address)
	} else {
		logger.Debugf("SUCCESS: Pushed ClusterSecret to joining node %s", req.Address)
	}

	// 4. Add to Raft
	f := s.raft.AddVoter(raft.ServerID(info.ID), raft.ServerAddress(info.RaftAddress), 0, 0)
	if err := f.Error(); err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	// 5. Register/Update Node metadata in FSM
	var node Node
	s.fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := s.fsm.Get(tx, []byte("nodes"), []byte(info.ID))
		if err != nil {
			return err
		}
		if plain != nil {
			json.Unmarshal(plain, &node)
		}
		return nil
	})

	node.ID = info.ID
	node.Status = NodeStatusActive
	node.Address = info.APIURL
	node.ClusterAddress = req.Address
	node.RaftAddress = info.RaftAddress
	node.LastHeartbeat = time.Now().Unix()
	data, _ := json.Marshal(node)
	s.ApplyRaftCommandWithHook(w, r, CmdRegisterNode, data, http.StatusOK, func(resp interface{}) interface{} {
		return map[string]string{"status": "ok"}
	})
}

func (s *Server) handleAdminPromote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(req.UserID)
	s.ApplyRaftCommandRaw(w, r, CmdPromoteAdmin, data, http.StatusOK)
}

func (s *Server) handleAdminSetUserLock(w http.ResponseWriter, r *http.Request) {
	var req AdminSetUserLockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "invalid request", http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		s.writeError(w, r, ErrCodeInternal, "userID required", http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(req)
	s.ApplyRaftCommandRaw(w, r, CmdAdminSetUserLock, data, http.StatusOK)
}

func (s *Server) handleSetUserQuota(w http.ResponseWriter, r *http.Request) {
	var req SetUserQuotaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "invalid request", http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		s.writeError(w, r, ErrCodeInternal, "userID required", http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(req) // Re-marshal to sanitize
	s.ApplyRaftCommandRaw(w, r, CmdSetUserQuota, data, http.StatusOK)
}

func (s *Server) handleSetGroupQuota(w http.ResponseWriter, r *http.Request) {
	var req SetGroupQuotaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "invalid request", http.StatusBadRequest)
		return
	}
	if req.GroupID == "" {
		s.writeError(w, r, ErrCodeInternal, "groupID required", http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(req) // Re-marshal to sanitize
	s.ApplyRaftCommandRaw(w, r, CmdSetGroupQuota, data, http.StatusOK)
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
			s.writeError(w, r, ErrCodeInternal, "world identity not available", http.StatusNotFound)
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(world.Public)
}

func (s *Server) handleGetWorldPrivateKey(w http.ResponseWriter, r *http.Request) {
	user, err := s.authenticate(r)
	if err != nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	world, err := s.fsm.GetWorldIdentity()
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "world identity not initialized", http.StatusNotFound)
		return
	}

	// Encapsulate World Private Key using user's Public EncKey
	userEK, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "invalid user encryption key", http.StatusInternalServerError)
		return
	}

	ss, kemCT := crypto.Encapsulate(userEK)
	demCT, err := crypto.EncryptDEM(ss, world.Private)
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, "encryption failed", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"kem": base64.StdEncoding.EncodeToString(kemCT),
		"dem": base64.StdEncoding.EncodeToString(demCT),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) parseSessionToken(tokenStr string) (*SessionToken, error) {
	b, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, err
	}
	var st SignedSessionToken
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st.Token, nil
}

func (s *Server) unsealRequest(w http.ResponseWriter, r *http.Request, user *User) ([]byte, error) {
	// Limit reading to 10MB to prevent DoS
	limitBody := http.MaxBytesReader(w, r.Body, 10*1024*1024)
	var sealed SealedRequest
	if err := json.NewDecoder(limitBody).Decode(&sealed); err != nil {
		return nil, fmt.Errorf("invalid sealed request: %w", err)
	}

	if sealed.UserID != user.ID {
		return nil, fmt.Errorf("user mismatch in sealed request")
	}

	// 0. Check Session Cache (Memoization)
	sessionToken := r.Header.Get("Session-Token")
	if sessionToken != "" {
		// Phase 53.1: Session keys are cached by Nonce, not full token string
		if st, err := s.parseSessionToken(sessionToken); err == nil {
			s.sessionKeyMu.RLock()
			entry, ok := s.sessionKeyCache[st.Nonce]
			s.sessionKeyMu.RUnlock()

			if ok {
				if entry.expiry < time.Now().Unix() {
					s.sessionKeyMu.RUnlock()
					// Treat as cache miss, fall back to KEM
				} else {
					ts, payload, err := crypto.OpenRequestSymmetric(entry.key, user.SignKey, sealed.Sealed)
					if err == nil {
						// Success with cached key
						if err := s.checkReplay(user.ID, ts); err != nil {
							return nil, err
						}
						// Phase 53.1: Pass session key to handlers via context for symmetric response sealing
						*r = *r.WithContext(context.WithValue(r.Context(), sessionKeyContextKey, entry.key))
						return payload, nil
					}
					// If symmetric decryption fails, fall back to full KEM (maybe key rotated?)
				}
			}
		}
	}
	// 1. Get Active Cluster Key
	active, err := s.fsm.GetActiveKey()
	if err != nil {
		return nil, fmt.Errorf("active cluster key not found")
	}

	s.epochPrivateKeysMu.RLock()
	dk, ok := s.epochPrivateKeys[active.ID]
	s.epochPrivateKeysMu.RUnlock()

	if !ok {
		// If we are leader but don't have the private key for the active epoch,
		// it means we just became leader or the key was generated by a previous leader.
		// We MUST rotate to a new key that we hold in-memory.
		if s.raft.State() == raft.Leader {
			logger.Debugf("DEBUG: active epoch key %s missing in-memory, triggering rotation", active.ID)
			go s.keyWorker.rotate()
		}
		return nil, fmt.Errorf("active epoch key private part not available in-memory")
	}

	// 2. Open (Full KEM)
	ts, payload, sharedSecret, err := crypto.OpenRequest(dk, user.SignKey, sealed.Sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to open request: %w", err)
	}

	// Phase 53.1: Update session key cache if we have a session token.
	// This ensures that subsequent requests can use the symmetric path with the new shared secret.
	if sessionToken != "" {
		if st, err := s.parseSessionToken(sessionToken); err == nil {
			s.sessionKeyMu.Lock()
			s.sessionKeyCache[st.Nonce] = sessionKeyEntry{
				key:    sharedSecret,
				expiry: st.Expiry,
			}
			s.sessionKeyMu.Unlock()

			// Prune epochPrivateKeys
			active, err := s.fsm.GetActiveKey()
			if err == nil {
				s.epochPrivateKeysMu.Lock()
				for id := range s.epochPrivateKeys {
					if id != active.ID {
						delete(s.epochPrivateKeys, id)
					}
				}
				s.epochPrivateKeysMu.Unlock()
			}
		}
	}

	// 3. Replay Protection
	if err := s.checkReplay(user.ID, ts); err != nil {
		return nil, err
	}

	// Phase 53.1: Pass session key to handlers via context for symmetric response sealing
	*r = *r.WithContext(context.WithValue(r.Context(), sessionKeyContextKey, sharedSecret))

	return payload, nil
}
func (s *Server) checkReplay(userID string, ts int64) error {
	now := time.Now().UnixNano()
	if ts < now-int64(2*time.Minute) || ts > now+int64(2*time.Minute) {
		return fmt.Errorf("request timestamp out of range")
	}

	nonce := userID + ":" + fmt.Sprintf("%d", ts)
	s.requestNonceMu.Lock()
	// Lazy GC
	for k, v := range s.requestNonceCache {
		if time.Since(v) > 5*time.Minute {
			delete(s.requestNonceCache, k)
		}
	}
	if _, exists := s.requestNonceCache[nonce]; exists {
		s.requestNonceMu.Unlock()
		return fmt.Errorf("replay detected")
	}
	s.requestNonceCache[nonce] = time.Now()
	s.requestNonceMu.Unlock()
	return nil
}

func (s *Server) sessionCleanupWorker() {

	ticker := time.NewTicker(5 * time.Minute)

	defer ticker.Stop()

	for {

		select {

		case <-ticker.C:

			s.sessionKeyMu.RLock()

			var expired []string

			now := time.Now().Unix()

			for token, entry := range s.sessionKeyCache {

				if entry.expiry < now {

					expired = append(expired, token)

				}

			}

			s.sessionKeyMu.RUnlock()

			if len(expired) > 0 {

				s.sessionKeyMu.Lock()

				for _, token := range expired {
					delete(s.sessionKeyCache, token)
				}

				s.sessionKeyMu.Unlock()

				// Prune epochPrivateKeys
				active, err := s.fsm.GetActiveKey()
				if err == nil {
					s.epochPrivateKeysMu.Lock()
					for id := range s.epochPrivateKeys {
						if id != active.ID {
							delete(s.epochPrivateKeys, id)
						}
					}
					s.epochPrivateKeysMu.Unlock()
				}

			}

		case <-s.stopCh:

			return

		}

	}

}

func (s *Server) checkAndInitWorld() {

	_, err := s.fsm.GetWorldIdentity()

	if err == nil {

		return

	}

	logger.Debugf("Initializing World Identity...")

	dk, _ := crypto.GenerateEncryptionKey()

	pk := dk.EncapsulationKey().Bytes()

	priv := crypto.MarshalDecapsulationKey(dk)

	world := WorldIdentity{

		Public: pk,

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

func (s *Server) handleGetAuthConfig(w http.ResponseWriter, r *http.Request) {
	s.oidcMu.RLock()
	conf := s.oidcConfig
	s.oidcMu.RUnlock()

	if conf == nil {
		s.writeError(w, r, ErrCodeInternal, "OIDC configuration not available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conf)
}

func (s *Server) handleGetNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.fsm.GetNodes()
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"id":     s.nodeID,
		"state":  s.raft.State().String(),
		"leader": s.raft.Leader(),
		"nodes":  nodes,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) resolveURLs(manifest []ChunkEntry) {
	nodes, err := s.fsm.GetNodes()
	if err != nil {
		log.Printf("Failed to resolve URLs: %v", err)
		return
	}
	nodeMap := make(map[string]string, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n.Address
	}

	for i := range manifest {
		manifest[i].URLs = make([]string, 0, len(manifest[i].Nodes))
		for _, nodeID := range manifest[i].Nodes {
			if addr, ok := nodeMap[nodeID]; ok {
				manifest[i].URLs = append(manifest[i].URLs, addr)
			}
		}
	}
}

func (s *Server) handleGetClusterStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value(userContextKey).(*User); !ok {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}
	nodes, err := s.fsm.GetNodes()
	if err != nil {
		s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		return
	}

	var stats ClusterStats
	for _, node := range nodes {
		// Only count active nodes for capacity
		if node.Status == NodeStatusActive {
			stats.TotalCapacity += node.Capacity
			stats.TotalUsed += node.Used
			stats.NodeCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleAcquireLeases(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionToken := r.Header.Get("Session-Token")
	if sessionToken == "" {
		s.writeError(w, r, ErrCodeUnauthorized, "missing session token", http.StatusUnauthorized)
		return
	}

	sessionNonce := ""
	if b, err := base64.StdEncoding.DecodeString(sessionToken); err == nil {
		var st SignedSessionToken
		if err := json.Unmarshal(b, &st); err == nil {
			sessionNonce = st.Token.Nonce
		}
	}
	if sessionNonce == "" {
		s.writeError(w, r, ErrCodeUnauthorized, "invalid session token", http.StatusUnauthorized)
		return
	}

	var req LeaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	// Use Session Nonce as the unique owner ID for the lease
	req.SessionID = sessionNonce
	req.UserID = user.ID
	if req.Duration == 0 {
		req.Duration = int64(2 * time.Minute) // Default duration
	}

	body, _ := json.Marshal(req)
	s.ApplyRaftCommandRaw(w, r, CmdAcquireLeases, body, http.StatusOK)
}

func (s *Server) handleReleaseLeases(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(*User)
	if !ok || user == nil {
		s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionToken := r.Header.Get("Session-Token")
	if sessionToken == "" {
		s.writeError(w, r, ErrCodeUnauthorized, "missing session token", http.StatusUnauthorized)
		return
	}

	sessionNonce := ""
	if b, err := base64.StdEncoding.DecodeString(sessionToken); err == nil {
		var st SignedSessionToken
		if err := json.Unmarshal(b, &st); err == nil {
			sessionNonce = st.Token.Nonce
		}
	}
	if sessionNonce == "" {
		s.writeError(w, r, ErrCodeUnauthorized, "invalid session token", http.StatusUnauthorized)
		return
	}

	var req LeaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, ErrCodeInternal, "bad request", http.StatusBadRequest)
		return
	}

	req.SessionID = sessionNonce
	req.UserID = user.ID
	body, _ := json.Marshal(req)
	s.ApplyRaftCommandRaw(w, r, CmdReleaseLeases, body, http.StatusOK)
}

func (s *Server) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.checkRaftSecret(r) {
		user, ok := r.Context().Value(userContextKey).(*User)
		if !ok || user == nil || !s.fsm.IsAdmin(user.ID) {
			s.writeError(w, r, ErrCodeUnauthorized, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	snap, err := s.fsm.GetLatestMetrics()
	if err != nil {
		if err == ErrNotFound {
			s.writeError(w, r, ErrCodeInternal, "no metrics available", http.StatusNotFound)
		} else {
			s.writeError(w, r, ErrCodeInternal, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}
