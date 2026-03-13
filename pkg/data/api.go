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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/logger"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/ech"
	bolt "go.etcd.io/bbolt"
)

// Validator validates if a replication target is valid.
type Validator interface {
	// ValidateNode checks if the address belongs to a registered node.
	ValidateNode(address string) error
}

// DenyAllValidator rejects all replication requests.
type DenyAllValidator struct{}

func (d DenyAllValidator) ValidateNode(address string) error {
	return fmt.Errorf("replication denied: no valid cluster registry")
}

// NoopValidator allows all replication requests. SHOULD ONLY BE USED IN TESTS.
type NoopValidator struct{}

func (n NoopValidator) ValidateNode(address string) error {
	return nil
}

// Server is the HTTP server for the Data Node API.
type Server struct {
	store            Store
	metaPubKey       []byte
	fsm              *metadata.MetadataFSM
	validator        Validator
	client           *http.Client
	cachedMetaPubKey []byte
	cacheMu          sync.RWMutex
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

// NewServer creates a new Data Server.
func NewServer(store Store, metaPubKey []byte, fsm *metadata.MetadataFSM, validator Validator, disableDoH bool, allowInsecure bool) *Server {
	if validator == nil {
		if fsm != nil {
			validator = fsm
		} else {
			validator = DenyAllValidator{}
		}
	}

	var transport http.RoundTripper
	if !allowInsecure {
		e := ech.NewTransport()
		if disableDoH {
			e.Resolver = ech.InsecureGoResolver()
		}
		transport = e
	} else {
		standard := http.DefaultTransport.(*http.Transport).Clone()
		protected := ech.NewTransport()
		if disableDoH {
			protected.Resolver = ech.InsecureGoResolver()
		}
		transport = &schemeSwitchingTransport{
			standard:  standard,
			protected: protected,
		}
	}

	return &Server{
		store:      store,
		metaPubKey: metaPubKey,
		fsm:        fsm,
		validator:  validator,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// ServeHTTP handles incoming HTTP requests for chunks.
// Supported methods: PUT (upload), GET (download), DELETE (remove), POST (replicate).
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
		case http.MethodDelete:
			s.handleDelete(w, r, chunkID)
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

func (s *Server) Internal_Authenticate(r *http.Request, chunkID, requiredMode string) error {
	s.cacheMu.RLock()
	pubKey := s.cachedMetaPubKey
	s.cacheMu.RUnlock()

	if pubKey == nil {
		if s.fsm != nil {
			s.fsm.DB().View(func(tx *bolt.Tx) error {
				if plain, err := s.fsm.Get(tx, []byte("system"), []byte("cluster_sign_key")); err == nil && plain != nil {
					var key metadata.ClusterSignKey
					if err := json.Unmarshal(plain, &key); err == nil {
						pubKey = key.Public
						s.cacheMu.Lock()
						s.cachedMetaPubKey = pubKey
						s.cacheMu.Unlock()
					}
				}
				return nil
			})
		}
		if pubKey == nil {
			pubKey = s.metaPubKey
		}
	}

	if pubKey == nil {
		return fmt.Errorf("authentication failed: cluster signing key not available")
	}

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return fmt.Errorf("missing auth")
	}
	tokenStr := strings.TrimPrefix(auth, "Bearer ")

	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return fmt.Errorf("invalid token format")
	}

	var signed metadata.SignedAuthToken
	if err := json.Unmarshal(tokenBytes, &signed); err != nil {
		return fmt.Errorf("invalid token structure")
	}

	if !crypto.VerifySignature(pubKey, signed.Payload, signed.Signature) {
		logger.Debugf("DEBUG: Data Auth Failed! pubKey=%x, payload=%s, sig=%x", pubKey[:16], string(signed.Payload), signed.Signature[:16])
		return fmt.Errorf("invalid signature")
	}

	var cap metadata.CapabilityToken
	if err := json.Unmarshal(signed.Payload, &cap); err != nil {
		return fmt.Errorf("invalid capability payload")
	}

	if time.Now().Unix() > cap.Exp {
		return fmt.Errorf("token expired")
	}

	// Verify Session Binding if present
	if len(cap.SessionBinding) > 0 {
		sess := r.Header.Get("Session-Token")
		if sess == "" {
			return fmt.Errorf("missing session token required by capability")
		}
		b, err := base64.StdEncoding.DecodeString(sess)
		if err != nil {
			return fmt.Errorf("invalid session token encoding")
		}
		var st metadata.SignedSessionToken
		if err := json.Unmarshal(b, &st); err != nil {
			return fmt.Errorf("invalid session token structure")
		}

		// Verify server's signature over the session token
		payload, _ := json.Marshal(st.Token)
		if !crypto.VerifySignature(pubKey, payload, st.Signature) {
			return fmt.Errorf("invalid session token signature")
		}

		h := sha256.Sum256([]byte(st.Token.Nonce))
		if !bytes.Equal(h[:], cap.SessionBinding) {
			return fmt.Errorf("capability token is not bound to this session")
		}
	}

	hasPermission := false
	for _, m := range strings.Split(cap.Mode, "") {
		if m == requiredMode {
			hasPermission = true
			break
		}
	}
	if !hasPermission {
		return fmt.Errorf("permission denied: required %s, got %s", requiredMode, cap.Mode)
	}

	allowed := false
	for _, c := range cap.Chunks {
		if c == chunkID {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("chunk access denied")
	}

	return nil
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.Internal_Authenticate(r, id, "D"); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := s.store.DeleteChunk(id); err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReplicate(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.Internal_Authenticate(r, id, "R"); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req struct {
		Targets []string `json:"targets"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "no targets", http.StatusBadRequest)
		return
	}

	// Parallel Fan-out
	token := r.Header.Get("Authorization")
	sessionToken := r.Header.Get("Session-Token")
	errCh := make(chan error, len(req.Targets))
	for _, target := range req.Targets {
		go func(t string) {
			errCh <- s.replicate(id, t, "", token, sessionToken)
		}(target)
	}

	var errs []string
	for i := 0; i < len(req.Targets); i++ {
		if err := <-errCh; err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		http.Error(w, fmt.Sprintf("replication failed: %s", strings.Join(errs, "; ")), http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.Internal_Authenticate(r, id, "W"); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)

	if err := s.store.WriteChunk(id, r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	successCount := 1 // Local write succeeded
	replicas := r.URL.Query().Get("replicas")
	if replicas != "" {
		targets := strings.Split(replicas, ",")
		totalNodes := len(targets) + 1
		requiredQuorum := totalNodes/2 + 1

		token := r.Header.Get("Authorization")
		sessionToken := r.Header.Get("Session-Token")

		errCh := make(chan error, len(targets))
		for _, target := range targets {
			go func(t string) {
				errCh <- s.replicate(id, t, "", token, sessionToken)
			}(target)
		}

		// Phase 53.5: Scalable Sub-Quorum Persistence
		// We return success as soon as we reach requiredQuorum (W).
		// Remaining replicas will continue in background.
		var errs []string
		for i := 0; i < len(targets); i++ {
			if successCount >= requiredQuorum {
				// Quorum met! The remaining sends are buffered and will complete in background.
				break
			}

			if err := <-errCh; err == nil {
				successCount++
			} else {
				errs = append(errs, err.Error())
			}
		}

		if successCount < requiredQuorum {
			http.Error(w, fmt.Sprintf("quorum not reached (%d/%d): %s", successCount, requiredQuorum, strings.Join(errs, "; ")), http.StatusBadGateway)
			return
		}

		if len(errs) > 0 {
			logger.Debugf("DEBUG: Chunk %s reached quorum (%d/%d) but some replicas failed: %s", id, successCount, totalNodes, strings.Join(errs, "; "))
		}
	}

	w.WriteHeader(http.StatusCreated)
}

func (s *Server) replicate(id, target, remaining, token, sessionToken string) error {
	if err := s.validator.ValidateNode(target); err != nil {
		log.Printf("Data: Replication validation failed for %s: %v", target, err)
		return fmt.Errorf("invalid replication target: %w", err)
	}

	rc, err := s.store.ReadChunk(id)
	if err != nil {
		return err
	}
	defer rc.Close()

	url := fmt.Sprintf("%s/v1/data/%s", target, id)
	if remaining != "" {
		url += "?replicas=" + remaining
	}

	req, err := http.NewRequest("PUT", url, rc)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	if sessionToken != "" {
		req.Header.Set("Session-Token", sessionToken)
	}

	resp, err := s.client.Do(req)
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
	if err := s.Internal_Authenticate(r, id, "R"); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

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
		return
	}
}
