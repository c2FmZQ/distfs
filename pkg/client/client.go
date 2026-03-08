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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/ech"
)

type contextKey string

const adminBypassContextKey contextKey = "admin-bypass"

// GetServerSignKey fetches the cluster's public signing key (ML-DSA).
func (c *Client) GetServerSignKey(ctx context.Context) ([]byte, error) {
	c.keyMu.RLock()
	sk := c.serverSignPK
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/meta/key/sign", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.newAPIError(resp, resp.Body)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.keyMu.Lock()
	c.serverSignPK = b
	c.keyMu.Unlock()
	return b, nil
}

// GetServerKey fetches the cluster's current world public encryption key (ML-KEM).
func (c *Client) GetServerKey(ctx context.Context) (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	sk := c.serverKey
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/meta/key", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.newAPIError(resp, resp.Body)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	pk, err := crypto.UnmarshalEncapsulationKey(b)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.serverKey = pk
	c.keyMu.Unlock()
	return pk, nil
}

type pathCacheEntry struct {
	inodeID string
	key     []byte
	linkTag string          // "ParentID:NameHMAC"
	inode   *metadata.Inode // Optional: Cached full inode
}

type fileMetadata struct {
	key     []byte
	groupID string
	linkTag string // "ParentID:NameHMAC"
	inlined bool
}

// ContactInfo represents a signed identity for out-of-band discovery.
type ContactInfo struct {
	UserID    string `json:"uid"`
	EncKey    []byte `json:"ek"` // ML-KEM Public Key
	SignKey   []byte `json:"sk"` // ML-DSA Public Key
	Timestamp int64  `json:"ts"`
	Signature []byte `json:"sig"`
}

// GenerateContactString generates a signed DistFS contact string.
func (c *Client) GenerateContactString() (string, error) {
	if c.userID == "" || c.decKey == nil || c.signKey == nil {
		return "", fmt.Errorf("client identity not fully configured")
	}

	info := ContactInfo{
		UserID:    c.userID,
		EncKey:    c.decKey.EncapsulationKey().Bytes(),
		SignKey:   c.signKey.Public(),
		Timestamp: time.Now().Unix(),
	}

	// Sign: HMAC(uid | ek | sk | ts)
	h := crypto.NewHash()
	h.Write([]byte(info.UserID))
	h.Write(info.EncKey)
	h.Write(info.SignKey)
	binary.Write(h, binary.BigEndian, info.Timestamp)

	info.Signature = c.signKey.Sign(h.Sum(nil))

	b, err := json.Marshal(info)
	if err != nil {
		return "", err
	}

	return "distfs-contact:v1:" + base64.URLEncoding.EncodeToString(b), nil
}

// ParseContactString parses and verifies a DistFS contact string.
func (c *Client) ParseContactString(s string) (*ContactInfo, error) {
	prefix := "distfs-contact:v1:"
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("invalid contact string prefix")
	}

	b, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return nil, fmt.Errorf("failed to decode contact string: %w", err)
	}

	var info ContactInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal contact info: %w", err)
	}

	// Verify Signature
	h := crypto.NewHash()
	h.Write([]byte(info.UserID))
	h.Write(info.EncKey)
	h.Write(info.SignKey)
	binary.Write(h, binary.BigEndian, info.Timestamp)

	if !crypto.VerifySignature(info.SignKey, h.Sum(nil), info.Signature) {
		return nil, fmt.Errorf("invalid contact signature")
	}

	// Expiry check (e.g., 30 days)
	if time.Now().Unix() > info.Timestamp+(30*24*3600) {
		return nil, fmt.Errorf("contact info expired")
	}

	return &info, nil
}

// InodeUpdateFunc is a callback used to modify an inode during an atomic update.
type InodeUpdateFunc func(*metadata.Inode) error

// GroupUpdateFunc is a callback used to modify a group during an atomic update.
type GroupUpdateFunc func(*metadata.Group) error

// DirectoryEntry represents a signed identity attestation in the DistFS registry.
type DirectoryEntry struct {
	Username   string `json:"username"`
	FullName   string `json:"full_name"`
	Email      string `json:"email"`
	UserID     string `json:"uid"`
	EncKey     []byte `json:"ek"` // ML-KEM Public Key
	SignKey    []byte `json:"sk"` // ML-DSA Public Key
	HomeDir    string `json:"home_dir,omitempty"`
	VerifierID string `json:"verifier_id"`
	Timestamp  int64  `json:"ts"`
	Signature  []byte `json:"sig"` // Signature by Verifier over all other fields
}

// Client is the primary entry point for interacting with a DistFS cluster.
// It handles end-to-end encryption, chunking, and metadata coordination.
type Client struct {
	serverURL    string
	httpClient   *http.Client
	userID       string
	decKey       *mlkem.DecapsulationKey768
	signKey      *crypto.IdentityKey
	serverKey    *mlkem.EncapsulationKey768
	serverSignPK []byte
	keyCache     map[string]fileMetadata
	keyMu        *sync.RWMutex

	pathCache map[string]pathCacheEntry
	pathMu    *sync.RWMutex

	worldPublic   *mlkem.EncapsulationKey768
	worldPrivate  *mlkem.DecapsulationKey768
	groupKeys     map[string]*mlkem.DecapsulationKey768
	groupSignKeys map[string]*crypto.IdentityKey

	userCache  map[string]*metadata.User
	groupCache map[string]*metadata.Group
	cacheMu    *sync.RWMutex

	sessionToken  string
	sessionExpiry time.Time
	sessionKey    []byte // Cached shared secret for memoization
	sessionMu     *sync.RWMutex
	loginMu       *sync.Mutex

	// Root Anchoring (Phase 31)
	rootID      string
	rootOwner   string
	rootVersion uint64
	rootMu      *sync.RWMutex

	controlSem chan struct{}
	dataSem    chan struct{}

	admin bool

	mutationMu    *sync.Mutex
	mutationLocks map[string]*sync.Mutex

	onLeaseExpired func(id string, err error)

	registryDir string
}

// NewClient creates a new DistFS client.
func NewClient(serverAddr string) *Client {
	var transport http.RoundTripper

	if strings.HasPrefix(serverAddr, "http://") {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.ForceAttemptHTTP2 = true
		t.MaxIdleConns = 100
		t.MaxIdleConnsPerHost = 100
		transport = t
	} else {
		echTransport := ech.NewTransport()
		echTransport.HTTPTransport.MaxIdleConns = 100
		echTransport.HTTPTransport.MaxIdleConnsPerHost = 100
		transport = echTransport
	}

	return &Client{
		serverURL: serverAddr,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Minute,
		},
		keyCache:      make(map[string]fileMetadata),
		keyMu:         &sync.RWMutex{},
		pathCache:     make(map[string]pathCacheEntry),
		pathMu:        &sync.RWMutex{},
		groupKeys:     make(map[string]*mlkem.DecapsulationKey768),
		groupSignKeys: make(map[string]*crypto.IdentityKey),
		userCache:     make(map[string]*metadata.User),
		groupCache:    make(map[string]*metadata.Group),
		cacheMu:       &sync.RWMutex{},
		sessionMu:     &sync.RWMutex{},
		loginMu:       &sync.Mutex{},
		controlSem:    make(chan struct{}, 1024), // High throughput for metadata
		dataSem:       make(chan struct{}, 64),   // Limit chunk I/O
		mutationMu:    &sync.Mutex{},
		mutationLocks: make(map[string]*sync.Mutex),
		rootID:        metadata.RootID,
		rootMu:        &sync.RWMutex{},
	}
}

// WithIdentity returns a new client with the specified user identity.
func (c *Client) WithIdentity(userID string, key *mlkem.DecapsulationKey768) *Client {
	c2 := *c
	c2.userID = userID
	c2.decKey = key
	c2.keyCache = make(map[string]fileMetadata) // New cache for new identity
	return &c2
}

// WithSignKey returns a new client with the specified signing key.
func (c *Client) WithSignKey(key *crypto.IdentityKey) *Client {
	c2 := *c
	c2.signKey = key
	return &c2
}

// WithServerKey returns a new client with the pre-configured server public key.
func (c *Client) WithServerKey(key *mlkem.EncapsulationKey768) *Client {
	c2 := *c
	c2.serverKey = key
	return &c2
}

// WithRootAnchor returns a new client with the specified root anchoring information.
func (c *Client) WithRootAnchor(id, owner string, version uint64) *Client {
	c2 := *c
	c2.rootMu = &sync.RWMutex{}
	c2.rootID = id
	c2.rootOwner = owner
	c2.rootVersion = version
	return &c2
}

// WithRegistry sets the directory path used for username resolution.
func (c *Client) WithRegistry(dir string) *Client {
	c2 := *c
	c2.registryDir = dir
	return &c2
}

// WithRootID returns a new client with a different root inode ID (chroot).
func (c *Client) WithRootID(id string) *Client {
	c2 := *c
	c2.rootID = id
	c2.rootOwner = ""
	c2.rootVersion = 0
	c2.pathCache = make(map[string]pathCacheEntry)
	c2.pathMu = &sync.RWMutex{}
	c2.rootMu = &sync.RWMutex{}
	return &c2
}

// WithAdmin returns a new client with the admin bypass enabled.
func (c *Client) WithAdmin(admin bool) *Client {
	c2 := *c
	c2.admin = admin
	return &c2
}

// WithDisableDoH configures whether to disable DNS-over-HTTPS and use the system resolver instead.
func (c *Client) WithDisableDoH(disable bool) *Client {
	c2 := *c
	clonedClient := *c.httpClient
	c2.httpClient = &clonedClient

	if transport, ok := c2.httpClient.Transport.(*ech.Transport); ok {
		t2 := *transport
		if disable {
			t2.Resolver = ech.InsecureGoResolver()
		} else {
			t2.Resolver = ech.DefaultResolver
		}
		c2.httpClient.Transport = &t2
	}
	return &c2
}

// WithLeaseExpiredCallback returns a new client with the specified lease expiration callback.
func (c *Client) WithLeaseExpiredCallback(fn func(id string, err error)) *Client {
	c2 := *c
	c2.onLeaseExpired = fn
	return &c2
}

// GetRootAnchor returns the current root anchoring information.
func (c *Client) GetRootAnchor() (string, string, uint64) {
	c.rootMu.RLock()
	defer c.rootMu.RUnlock()
	return c.rootID, c.rootOwner, c.rootVersion
}

// UserID returns the current user ID.
func (c *Client) UserID() string {
	return c.userID
}

func (c *Client) SignKey() *crypto.IdentityKey {
	return c.signKey
}

func (c *Client) DecKey() *mlkem.DecapsulationKey768 {
	return c.decKey
}

func (c *Client) getSessionToken() string {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.sessionToken
}

func (c *Client) getSessionNonce() string {
	c.sessionMu.RLock()
	token := c.sessionToken
	c.sessionMu.RUnlock()

	if token == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(token); err == nil {
		var st metadata.SignedSessionToken
		if err := json.Unmarshal(b, &st); err == nil {
			return st.Token.Nonce
		}
	}
	return ""
}

// Login performs the challenge-response handshake to obtain a session token.
func (c *Client) Login(ctx context.Context) error {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()

	// 1. Get Challenge
	reqData := metadata.AuthChallengeRequest{UserID: c.userID}
	b, _ := json.Marshal(reqData)
	req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/auth/challenge", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.newAPIError(resp, resp.Body)
	}

	var challengeRes metadata.AuthChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeRes); err != nil {
		return err
	}

	// 2. Verify server signature over challenge
	serverSignPK, err := c.GetServerSignKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server sign key: %w", err)
	}
	if !crypto.VerifySignature(serverSignPK, challengeRes.Challenge, challengeRes.Signature) {
		return fmt.Errorf("invalid server signature on challenge")
	}

	// 3. Solve Challenge (Sign it)
	sig := c.signKey.Sign(challengeRes.Challenge)

	solve := metadata.AuthChallengeSolve{
		UserID:    c.userID,
		Challenge: challengeRes.Challenge,
		Signature: sig,
	}
	b, _ = json.Marshal(solve)

	req, err = http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/login", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.newAPIError(resp, resp.Body)
	}

	var res metadata.SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}

	c.sessionMu.Lock()
	c.sessionToken = res.Token
	c.sessionKey = nil
	c.sessionExpiry = time.Now().Add(55 * time.Minute) // Buffer
	c.sessionMu.Unlock()
	return nil
}

func (c *Client) getPathCache(path string) (pathCacheEntry, bool) {
	c.pathMu.RLock()
	defer c.pathMu.RUnlock()
	entry, ok := c.pathCache[path]
	return entry, ok
}

func (c *Client) putPathCache(path string, entry pathCacheEntry) {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	c.pathCache[path] = entry
}

func (c *Client) invalidatePathCache(path string) {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	delete(c.pathCache, path)
}

func (c *Client) invalidatePathCacheByID(id string) {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	for path, entry := range c.pathCache {
		if entry.inodeID == id {
			delete(c.pathCache, path)
		}
	}
}

func (c *Client) clearPathCache() {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	clear(c.pathCache)
}

func (c *Client) ensureSession(ctx context.Context) error {
	if c.userID == "" || c.signKey == nil || c.decKey == nil {
		return nil
	}
	c.sessionMu.RLock()
	token := c.sessionToken
	expiry := c.sessionExpiry
	c.sessionMu.RUnlock()

	if token == "" || time.Now().Add(5*time.Minute).After(expiry) {
		if err := c.Login(ctx); err != nil {
			return fmt.Errorf("session login failed: %w", err)
		}
	}
	return nil
}

func (c *Client) authenticateRequest(ctx context.Context, req *http.Request) error {
	// 1. Special cases: registration, login, and keys don't need session auth.
	if strings.HasSuffix(req.URL.Path, "/v1/user/register") ||
		strings.HasSuffix(req.URL.Path, "/v1/auth/challenge") ||
		strings.HasSuffix(req.URL.Path, "/v1/login") ||
		strings.HasSuffix(req.URL.Path, "/v1/meta/key") {
		return nil
	}

	// If no identity is configured, we can't authenticate.
	if c.userID == "" || c.signKey == nil || c.decKey == nil {
		return nil
	}

	// 2. For all other requests, use the Session Token.
	c.sessionMu.RLock()
	token := c.sessionToken
	expiry := c.sessionExpiry
	c.sessionMu.RUnlock()

	// If token is missing or about to expire, perform a login handshake.
	if token == "" || time.Now().Add(5*time.Minute).After(expiry) {
		if err := c.Login(ctx); err != nil {
			return fmt.Errorf("session login failed: %w", err)
		}
		c.sessionMu.RLock()
		token = c.sessionToken
		c.sessionMu.RUnlock()
	}

	req.Header.Set("Session-Token", token)
	if c.admin {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	} else if bypass, _ := req.Context().Value(adminBypassContextKey).(bool); bypass {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	}
	return nil
}

func (c *Client) sealBody(ctx context.Context, req *http.Request, payload []byte) error {
	if payload == nil {
		return nil
	}

	c.sessionMu.RLock()
	sessionKey := c.sessionKey
	sessionToken := c.sessionToken
	c.sessionMu.RUnlock()

	var sealed []byte

	if sessionKey != nil && sessionToken != "" {
		// 1. Optimized Path: Symmetric Encryption (Memoization)
		// We still send a dummy KEM CT to match the wire format expected by the server.
		// The server sees the Session-Token, looks up the key, and ignores the KEM CT.
		kemSize := mlkem.CiphertextSize768
		dummyKEM := make([]byte, kemSize)
		rand.Read(dummyKEM)

		// Encrypt Inner using cached key
		ts := time.Now().UnixNano()
		tsBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(tsBytes, uint64(ts))

		toSign := make([]byte, 8+len(payload))
		copy(toSign[0:8], tsBytes)
		copy(toSign[8:], payload)
		sig := c.signKey.Sign(toSign)

		inner := make([]byte, 8+len(sig)+len(payload))
		copy(inner[0:8], tsBytes)
		copy(inner[8:8+len(sig)], sig)
		copy(inner[8+len(sig):], payload)

		demCT, err := crypto.EncryptDEM(sessionKey, inner)
		if err != nil {
			return err
		}

		sealed = make([]byte, len(dummyKEM)+len(demCT))
		copy(sealed[0:len(dummyKEM)], dummyKEM)
		copy(sealed[len(dummyKEM):], demCT)

	} else {
		// 2. Standard Path: Full KEM
		sk, err := c.GetServerKey(ctx)
		if err != nil {
			return err
		}

		// 2a. Encapsulate
		sharedSecret, kemCT := crypto.Encapsulate(sk)

		// 2b. Prepare Inner
		ts := time.Now().UnixNano()
		tsBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(tsBytes, uint64(ts))

		toSign := make([]byte, 8+len(payload))
		copy(toSign[0:8], tsBytes)
		copy(toSign[8:], payload)
		sig := c.signKey.Sign(toSign)

		inner := make([]byte, 8+len(sig)+len(payload))
		copy(inner[0:8], tsBytes)
		copy(inner[8:8+len(sig)], sig)
		copy(inner[8+len(sig):], payload)

		// 2c. Encrypt DEM
		demCT, err := crypto.EncryptDEM(sharedSecret, inner)
		if err != nil {
			return err
		}

		sealed = make([]byte, len(kemCT)+len(demCT))
		copy(sealed[0:len(kemCT)], kemCT)
		copy(sealed[len(kemCT):], demCT)

		// Cache for next time if we have a session
		c.sessionMu.Lock()
		if c.sessionToken != "" {
			c.sessionKey = sharedSecret
		}
		c.sessionMu.Unlock()
	}

	sr := metadata.SealedRequest{
		UserID: c.userID,
		Sealed: sealed,
	}

	data, _ := json.Marshal(sr)
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Content-Type", "application/json")
	if c.admin {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	} else if bypass, _ := req.Context().Value(adminBypassContextKey).(bool); bypass {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	}
	return nil
}
func (c *Client) unsealResponse(ctx context.Context, resp *http.Response) (io.ReadCloser, error) {
	if resp.Header.Get("X-DistFS-Sealed") != "true" {
		// If the server rejected our request before unsealing it (e.g. 403 Forbidden),
		// it did not cache our session key. We must invalidate our local cache to
		// ensure the next request falls back to Full KEM.
		if resp.StatusCode >= 400 {
			c.sessionMu.Lock()
			c.sessionKey = nil
			c.sessionMu.Unlock()
		}
		return resp.Body, nil
	}

	defer resp.Body.Close()
	limitBody := io.LimitReader(resp.Body, 10*1024*1024)
	var sealed metadata.SealedResponse
	if err := json.NewDecoder(limitBody).Decode(&sealed); err != nil {
		return nil, fmt.Errorf("failed to decode sealed response: %w", err)
	}

	serverSignPK, err := c.GetServerSignKey(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Open
	ts, payload, err := crypto.OpenResponse(c.decKey, serverSignPK, sealed.Sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to open response: %w", err)
	}

	// 2. Replay/Staleness Protection
	now := time.Now().UnixNano()
	if ts < now-int64(5*time.Minute) || ts > now+int64(5*time.Minute) {
		return nil, fmt.Errorf("response timestamp out of range")
	}

	return io.NopCloser(bytes.NewReader(payload)), nil
}

func (c *Client) allocateNodes(ctx context.Context) ([]metadata.Node, error) {
	var nodes []metadata.Node
	err := c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/allocate", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, []byte("{}")); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests {
			return c.newAPIError(resp, resp.Body)
		}

		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return json.NewDecoder(body).Decode(&nodes)
	})

	if err != nil {
		return nil, fmt.Errorf("node allocation failed after retries: %w", err)
	}
	return nodes, nil
}

func (c *Client) issueToken(ctx context.Context, inodeID string, chunks []string, mode string) (string, error) {
	reqData := map[string]interface{}{
		"inode_id": inodeID,
		"chunks":   chunks,
		"mode":     mode,
	}
	data, _ := json.Marshal(reqData)

	var token string
	err := c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/token", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}

		respBytes, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		token = base64.StdEncoding.EncodeToString(respBytes)
		return nil
	})

	return token, err
}

func (c *Client) uploadChunk(ctx context.Context, id string, data []byte, nodes []metadata.Node, token string) error {
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes allocated")
	}
	primary := nodes[0]

	url := fmt.Sprintf("%s/v1/data/%s", primary.Address, id)
	if len(nodes) > 1 {
		var replicas []string
		for _, n := range nodes[1:] {
			if n.Address != "" {
				replicas = append(replicas, n.Address)
			}
		}
		if len(replicas) > 0 {
			url += "?replicas=" + strings.Join(replicas, ",")
		}
	}

	return c.withRetry(ctx, func() error {
		if err := c.acquireData(ctx); err != nil {
			return err
		}
		defer c.releaseData()

		req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(data))
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if sess := c.getSessionToken(); sess != "" {
			req.Header.Set("Session-Token", sess)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, resp.Body)
		}
		return nil
	})
}

func (c *Client) downloadChunk(ctx context.Context, id string, urls []string, token string) ([]byte, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs provided for chunk %s", id)
	}

	var data []byte
	err := c.withRetry(ctx, func() error {
		type result struct {
			data []byte
			err  error
		}

		resCh := make(chan result, len(urls))
		lctx, cancel := context.WithCancel(ctx)
		defer cancel()

		var started, consumed int
		for i, url := range urls {
			started++
			if i > 0 {
				// Staggered start: Wait for timeout OR a result from previous attempts
				wait := time.NewTimer(1 * time.Second)
				select {
				case <-lctx.Done():
					wait.Stop()
					return lctx.Err()
				case res := <-resCh:
					wait.Stop()
					consumed++
					if res.err == nil {
						data = res.data
						return nil
					}
					// If it was an error, we continue to start the next staggered request immediately
				case <-wait.C:
					// Timeout reached, start next replica
				}
			}
			go func(targetURL string) {
				if err := c.acquireData(lctx); err != nil {
					resCh <- result{err: err}
					return
				}
				defer c.releaseData()

				req, err := http.NewRequestWithContext(lctx, "GET", targetURL+"/v1/data/"+id, nil)
				if err != nil {
					resCh <- result{err: err}
					return
				}
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				if sess := c.getSessionToken(); sess != "" {
					req.Header.Set("Session-Token", sess)
				}

				resp, err := c.httpClient.Do(req)
				if err != nil {
					resCh <- result{err: err}
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					resCh <- result{err: c.newAPIError(resp, resp.Body)}
					return
				}

				limit := int64(crypto.ChunkSize + 4096) // 1MB + overhead buffer
				d, err := io.ReadAll(io.LimitReader(resp.Body, limit))
				resCh <- result{data: d, err: err}
			}(url)

			// Check if anyone finished before starting next stagger
			select {
			case res := <-resCh:
				consumed++
				if res.err == nil {
					data = res.data
					return nil
				}
			default:
			}
		}

		// Wait for remaining
		var lastErr error
		for i := consumed; i < started; i++ {
			res := <-resCh
			if res.err == nil {
				data = res.data
				return nil
			}
			lastErr = res.err
		}
		return lastErr
	})

	if err != nil {
		return nil, fmt.Errorf("failed to download chunk %s from any node: %w", id, err)
	}
	return data, nil
}

type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("api error: %d %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("api error: %d %s", e.StatusCode, e.Message)
}

func (c *Client) newAPIError(resp *http.Response, body io.Reader) *APIError {
	ae := &APIError{StatusCode: resp.StatusCode}
	if body == nil {
		ae.Message = resp.Status
		return ae
	}
	b, _ := io.ReadAll(body)
	if len(b) > 0 {
		var er metadata.APIErrorResponse
		if err := json.Unmarshal(b, &er); err == nil && er.Code != "" {
			ae.Code = er.Code
			ae.Message = er.Message
		} else {
			ae.Message = string(b)
		}
	} else {
		ae.Message = resp.Status
	}
	return ae
}

func (e *APIError) ToPOSIX() error {
	switch e.StatusCode {
	case http.StatusNotFound:
		return syscall.ENOENT
	case http.StatusUnauthorized, http.StatusForbidden:
		return syscall.EACCES
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		return syscall.EAGAIN
	case http.StatusConflict:
		return syscall.EEXIST
	default:
		return syscall.EIO
	}
}

// ListGroups retrieves all groups associated with the current user.
func (c *Client) ListGroups(ctx context.Context) iter.Seq2[metadata.GroupListEntry, error] {
	return func(yield func(metadata.GroupListEntry, error) bool) {
		var resp metadata.GroupListResponse
		err := c.withRetry(ctx, func() error {
			if err := c.acquireControl(ctx); err != nil {
				return err
			}
			defer c.releaseControl()

			req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/user/groups", nil)
			if err != nil {
				return err
			}
			if err := c.authenticateRequest(ctx, req); err != nil {
				return err
			}

			res, err := c.httpClient.Do(req)
			if err != nil {
				return err
			}
			body, err := c.unsealResponse(ctx, res)
			if err != nil {
				return err
			}
			defer body.Close()

			if res.StatusCode != http.StatusOK {
				return c.newAPIError(res, body)
			}

			return json.NewDecoder(body).Decode(&resp)
		})

		if err != nil {
			yield(metadata.GroupListEntry{}, err)
			return
		}

		for _, g := range resp.Groups {
			if !yield(g, nil) {
				return
			}
		}
	}
}

func (c *Client) GetUser(ctx context.Context, id string) (*metadata.User, error) {
	return c.getUserInternal(ctx, id, false)
}

func (c *Client) getUserInternal(ctx context.Context, id string, bypassCache bool) (*metadata.User, error) {
	if !bypassCache {
		c.cacheMu.RLock()
		if u, ok := c.userCache[id]; ok {
			c.cacheMu.RUnlock()
			return u, nil
		}
		c.cacheMu.RUnlock()
	}

	var user metadata.User
	err := c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/user/"+id, nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}

		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}

		return json.NewDecoder(body).Decode(&user)
	})

	if err != nil {
		return nil, err
	}

	c.cacheMu.Lock()
	c.userCache[id] = &user
	c.cacheMu.Unlock()

	return &user, nil
}

func (c *Client) signInode(ctx context.Context, inode *metadata.Inode) error {
	// 1. Resolve File Key for encryption
	fileKey := inode.GetFileKey()

	// 2. Prepare ClientBlob
	if len(fileKey) > 0 {
		blob := metadata.InodeClientBlob{
			Name:          inode.GetName(),
			SymlinkTarget: inode.GetSymlinkTarget(),
			InlineData:    inode.GetInlineData(),
			MTime:         inode.GetMTime(),
			UID:           inode.GetUID(),
			GID:           inode.GetGID(),
		}

		encBlob, err := c.encryptInodeClientBlob(blob, fileKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt client blob: %w", err)
		}
		inode.ClientBlob = encBlob
	}

	inode.SetSignerID(c.userID)
	inode.Mode = metadata.SanitizeMode(inode.Mode, inode.Type)
	hash := inode.ManifestHash()
	inode.UserSig = c.signKey.Sign(hash)

	// Group Signing (if applicable)
	if inode.GroupID != "" {
		gsk, err := c.GetGroupSignKey(ctx, inode.GroupID)
		if err == nil {
			inode.GroupSig = gsk.Sign(hash)
		}
	}
	return nil
}

// createInode initializes a new inode.
func (c *Client) createInode(ctx context.Context, inode metadata.Inode) (*metadata.Inode, error) {
	cmd, err := c.PrepareCreate(ctx, inode)
	if err != nil {
		return nil, err
	}

	results, err := c.ApplyBatch(ctx, []metadata.LogCommand{cmd})
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("empty results from createInode batch")
	}

	if err := c.IsResultError(results[0]); err != nil {
		return nil, err
	}

	var created metadata.Inode
	if err := json.Unmarshal(results[0], &created); err != nil {
		return nil, fmt.Errorf("failed to decode created inode: %w", err)
	}

	// Phase 31: Root Anchoring
	if created.ID == c.rootID {
		c.rootMu.Lock()
		c.rootOwner = created.OwnerID
		c.rootVersion = created.Version
		c.rootMu.Unlock()
	}

	return &created, nil
}

// UpdateInode performs an atomic read-modify-write operation on an inode.
func (c *Client) UpdateInode(ctx context.Context, id string, fn InodeUpdateFunc) (*metadata.Inode, error) {
	return c.updateInodeInternal(ctx, id, fn, true)
}

func (c *Client) updateInodeInternal(ctx context.Context, id string, fn InodeUpdateFunc, verify bool) (*metadata.Inode, error) {
	unlock := c.lockMutation(id)
	defer unlock()

	for i := 0; i < 50; i++ {
		// 1. Fetch latest state
		inode, err := c.getInodeInternal(ctx, id, verify)
		if err != nil {
			return nil, err
		}

		// 2. Apply mutation
		if err := fn(inode); err != nil {
			return nil, err
		}

		// Use PrepareUpdate which handles version increment and signing
		cmd, err := c.PrepareUpdate(ctx, *inode)
		if err != nil {
			return nil, err
		}

		results, err := c.ApplyBatch(ctx, []metadata.LogCommand{cmd})
		if err == nil {
			if len(results) == 0 {
				return nil, fmt.Errorf("empty results from updateInode batch")
			}
			if err := c.IsResultError(results[0]); err != nil {
				return nil, err
			}
			var updated metadata.Inode
			if err := json.Unmarshal(results[0], &updated); err != nil {
				return nil, fmt.Errorf("failed to decode updated inode: %w", err)
			}

			// Ensure we keep the file key if we already had it (e.g. placeholder updates)
			if key := inode.GetFileKey(); len(key) > 0 {
				updated.SetFileKey(key)
			}

			// Phase 31: Root Anchoring
			if updated.ID == c.rootID {
				c.rootMu.Lock()
				c.rootOwner = updated.OwnerID
				c.rootVersion = updated.Version
				c.rootMu.Unlock()
			}

			c.invalidatePathCacheByID(id)
			return &updated, nil
		}

		if err != metadata.ErrConflict {
			return nil, err
		}
		// On conflict, wait a bit and retry
		time.Sleep(time.Duration(i*50) * time.Millisecond)
	}

	return nil, metadata.ErrConflict
}

func (c *Client) ApplyBatch(ctx context.Context, cmds []metadata.LogCommand) ([]json.RawMessage, error) {
	data, err := json.Marshal(cmds)
	if err != nil {
		return nil, err
	}

	var results []json.RawMessage
	err = c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/batch", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode == http.StatusConflict {
			return metadata.ErrConflict
		}

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}

		if err := json.NewDecoder(body).Decode(&results); err != nil {
			return err
		}

		c.clearPathCache()
		return nil
	})

	if err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Client) PrepareCreate(ctx context.Context, inode metadata.Inode) (metadata.LogCommand, error) {
	if err := c.signInode(ctx, &inode); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(inode)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdCreateInode, Data: data, UserID: c.userID}, nil
}

func (c *Client) PrepareUpdate(ctx context.Context, inode metadata.Inode) (metadata.LogCommand, error) {
	inode.Version++ // Increment before signing
	if err := c.signInode(ctx, &inode); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(inode)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdUpdateInode, Data: data, UserID: c.userID}, nil
}

func (c *Client) PrepareDelete(id string) (metadata.LogCommand, error) {
	data, _ := json.Marshal(id)
	return metadata.LogCommand{Type: metadata.CmdDeleteInode, Data: data, UserID: c.userID}, nil
}

// DeleteInode deletes an inode by ID. It performs an atomic update setting NLink to 0.
func (c *Client) DeleteInode(ctx context.Context, id string) error {
	_, err := c.UpdateInode(ctx, id, func(i *metadata.Inode) error {
		i.NLink = 0
		return nil
	})
	return err
}

func (c *Client) getInode(ctx context.Context, id string) (*metadata.Inode, error) {
	return c.getInodeInternal(ctx, id, true)
}

func (c *Client) getInodeInternal(ctx context.Context, id string, verify bool) (*metadata.Inode, error) {
	var inode metadata.Inode
	err := c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/meta/inode/"+id, nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}

		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}

		if err := json.NewDecoder(body).Decode(&inode); err != nil {
			return err
		}

		// Phase 31: Root Anchoring
		if id == c.rootID {
			c.rootMu.RLock()
			owner := c.rootOwner
			version := c.rootVersion
			c.rootMu.RUnlock()

			if owner != "" && inode.OwnerID != owner {
				return fmt.Errorf("ROOT COMPROMISE DETECTED: expected owner %s, got %s", owner, inode.OwnerID)
			}
			if version > 0 && inode.Version < version {
				return fmt.Errorf("ROOT ROLLBACK DETECTED: expected version >= %d, got %d", version, inode.Version)
			}
			// Update anchor
			c.rootMu.Lock()
			c.rootOwner = inode.OwnerID
			c.rootVersion = inode.Version
			c.rootMu.Unlock()
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Phase 31: Verification
	if verify {
		if err := c.VerifyInode(ctx, &inode); err != nil {
			return nil, err
		}
	}

	return &inode, nil
}

func (c *Client) getInodes(ctx context.Context, ids []string) ([]*metadata.Inode, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}

	var inodes []*metadata.Inode
	err = c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/inodes", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return json.NewDecoder(body).Decode(&inodes)
	})

	if err != nil {
		return nil, err
	}

	// Phase 31: Verification
	var valid []*metadata.Inode
	for _, inode := range inodes {
		if err := c.VerifyInode(ctx, inode); err != nil {
			log.Printf("DEBUG CLIENT: getInodes skipping inode %s due to verification failure: %v", inode.ID, err)
			continue
		}
		valid = append(valid, inode)
	}
	return valid, nil
}

func (c *Client) writeInodeContent(ctx context.Context, id string, iType metadata.InodeType, fileKey []byte, r io.Reader, size int64, name string, encryptedName []byte, mode uint32, groupID string, parentID string, nameHMAC string, uid, gid uint32) error {
	if r == nil {
		r = bytes.NewReader(nil)
	}

	var inode metadata.Inode
	// Try to get existing inode
	existing, err := c.getInode(ctx, id)
	if err == nil {
		inode = *existing
		// Preserve existing Lockbox entries if possible
		if inode.Lockbox == nil {
			inode.Lockbox = crypto.NewLockbox()
		}
		if c.decKey != nil {
			if err := inode.Lockbox.AddRecipient(c.userID, c.decKey.EncapsulationKey(), fileKey); err != nil {
				return err
			}
		}
		if (mode & 0004) != 0 {
			wpk, err := c.GetWorldPublicKey(ctx)
			if err == nil {
				inode.Lockbox.AddRecipient(metadata.WorldID, wpk, fileKey)
			}
		}
		if groupID != "" && (mode&0060) != 0 {
			group, err := c.GetGroup(ctx, groupID)
			if err == nil {
				gpk, _ := crypto.UnmarshalEncapsulationKey(group.EncKey)
				inode.Lockbox.AddRecipient(groupID, gpk, fileKey)
			}
		}
		if name != "" {
			inode.SetName(name)
		}
		if uid != 0 || gid != 0 {
			inode.SetUID(uid)
			inode.SetGID(gid)
		}
		inode.SetMTime(time.Now().UnixNano())
		inode.SetFileKey(fileKey)
	} else if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
		lb, err := c.createLockbox(ctx, fileKey, mode, c.userID, groupID)
		if err != nil {
			return err
		}

		// Assume not found, create new
		links := make(map[string]bool)
		if parentID != "" {
			links[parentID+":"+nameHMAC] = true
		}
		inode = metadata.Inode{
			ID:            id,
			Type:          iType,
			Links:         links,
			Mode:          mode,
			Size:          uint64(size),
			ChunkManifest: nil,
			Lockbox:       lb,
			OwnerID:       c.userID,
			GroupID:       groupID,
			CTime:         time.Now().UnixNano(),
			NLink:         1,
			Version:       1,
		}
		if name != "" {
			inode.SetName(name)
		}
		inode.SetUID(uid)
		inode.SetGID(gid)
		inode.SetMTime(time.Now().UnixNano())
		inode.SetFileKey(fileKey)
		created, err := c.createInode(ctx, inode)
		if err != nil {
			return err
		}
		inode = *created
		if name != "" {
			inode.SetName(name)
		}
		inode.SetFileKey(fileKey)
	} else {
		return err
	}

	// 1. Handle Content
	inlineData, chunkEntries, err := c.uploadDataInternal(ctx, id, fileKey, r, size)
	if err != nil {
		return err
	}

	// 3. Atomic Inode Update
	updated, err := c.UpdateInode(ctx, id, func(i *metadata.Inode) error {
		i.SetInlineData(inlineData)
		i.ChunkManifest = chunkEntries
		i.Size = uint64(size)
		if size == 0 {
			i.Size = uint64(len(inlineData))
		}
		return nil
	})
	if err == nil {
		c.keyMu.Lock()
		c.keyCache[id] = fileMetadata{
			key:     fileKey,
			groupID: groupID,
			linkTag: parentID + ":" + nameHMAC,
			inlined: updated.GetInlineData() != nil,
		}
		c.keyMu.Unlock()
		return nil
	}
	return fmt.Errorf("writeInodeContent UpdateInode failed for %s: %w", id, err)
}

func (c *Client) uploadDataInternal(ctx context.Context, id string, fileKey []byte, r io.Reader, size int64) ([]byte, []metadata.ChunkEntry, error) {
	var inlineData []byte
	var chunkEntries []metadata.ChunkEntry

	if size <= metadata.InlineLimit {
		var err error
		inlineData, err = io.ReadAll(r)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Chunk Path
		buf := make([]byte, crypto.ChunkSize)
		var chunkIndex uint64

		for {
			n, err := io.ReadFull(r, buf)
			if n > 0 {
				chunkData := buf[:n]
				cid, ct, err := crypto.EncryptChunk(fileKey, chunkData, chunkIndex)
				if err != nil {
					return nil, nil, err
				}
				chunkIndex++

				token, err := c.issueToken(ctx, id, []string{cid}, "W")
				if err != nil {
					return nil, nil, fmt.Errorf("token issue failed: %w", err)
				}
				nodes, err := c.allocateNodes(ctx)
				if err != nil {
					return nil, nil, fmt.Errorf("allocation failed: %w", err)
				}
				if err := c.uploadChunk(ctx, cid, ct, nodes, token); err != nil {
					return nil, nil, err
				}

				var nodeIDs []string
				for _, node := range nodes {
					nodeIDs = append(nodeIDs, node.ID)
				}
				chunkEntries = append(chunkEntries, metadata.ChunkEntry{ID: cid, Nodes: nodeIDs})
			}
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return inlineData, chunkEntries, nil
}

// WriteFile writes a file. Returns the FileKey used.
func (c *Client) WriteFile(ctx context.Context, id string, r io.Reader, size int64, mode uint32) ([]byte, error) {
	c.keyMu.RLock()
	meta, ok := c.keyCache[id]
	c.keyMu.RUnlock()

	var fileKey []byte
	var groupID string
	var parentID string
	var nameHMAC string

	if ok {
		fileKey = meta.key
		groupID = meta.groupID
		parts := strings.SplitN(meta.linkTag, ":", 2)
		if len(parts) == 2 {
			parentID = parts[0]
			nameHMAC = parts[1]
		}
	} else {
		if inode, err := c.getInode(ctx, id); err == nil {
			if key, err := c.UnlockInode(ctx, inode); err == nil {
				fileKey = key
				groupID = inode.GroupID
				// Try to pick a link tag for the cache
				for tag := range inode.Links {
					parts := strings.SplitN(tag, ":", 2)
					if len(parts) == 2 {
						parentID = parts[0]
						nameHMAC = parts[1]
						break
					}
				}
				if parentID == "" {
					return nil, fmt.Errorf("inode %s has no valid parent links", id)
				}
			}
		}
	}

	if fileKey == nil {
		fileKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
			return nil, err
		}
	}

	if err := c.writeInodeContent(ctx, id, metadata.FileType, fileKey, r, size, "", nil, mode, groupID, parentID, nameHMAC, 0, 0); err != nil {
		return nil, err
	}
	return fileKey, nil
}

type readAheadResult struct {
	data  []byte
	err   error
	ready chan struct{}
}

// FileReader provides streaming read access to a file's chunks with background prefetching.
type FileReader struct {
	client          *Client
	inode           *metadata.Inode
	fileKey         []byte
	offset          int64
	currentChunkIdx int64
	currentChunk    []byte
	token           string
	leaseNonce      string
	mu              sync.Mutex

	readAhead   map[int64]*readAheadResult
	readAheadMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	onExpired func(id string, err error)
}

// NewReader creates a new FileReader for the given inode.
// The caller MUST call Close() on the returned reader to release resources and cancel background prefetching.
func (c *Client) NewReader(ctx context.Context, id string, fileKey []byte) (*FileReader, error) {
	inode, err := c.getInode(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.NewReaderWithInode(ctx, inode, fileKey, "")
}

// NewReaderWithInode creates a new FileReader from an already fetched Inode.
// If leaseNonce is empty, it will acquire a new shared usage lease.
func (c *Client) NewReaderWithInode(ctx context.Context, inode *metadata.Inode, fileKey []byte, leaseNonce string) (*FileReader, error) {
	id := inode.ID
	if fileKey == nil {
		c.keyMu.RLock()
		meta, ok := c.keyCache[id]
		c.keyMu.RUnlock()
		if ok {
			fileKey = meta.key
		}
	}

	if fileKey == nil {
		if c.decKey == nil {
			return nil, fmt.Errorf("client has no identity to unlock file")
		}
		key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
		if err != nil {
			return nil, err
		}
		fileKey = key

		// Optimization: Update cache from what we just fetched
		var linkTag string
		for tag := range inode.Links {
			linkTag = tag
			break
		}
		c.keyMu.Lock()
		c.keyCache[id] = fileMetadata{
			key:     fileKey,
			groupID: inode.GroupID,
			linkTag: linkTag,
			inlined: inode.GetInlineData() != nil,
		}
		c.keyMu.Unlock()
	}

	token, _ := c.issueToken(ctx, id, nil, "R")

	nonce := leaseNonce
	if nonce == "" {
		nonce = generateID()
		// POSIX compliance: acquire shared usage lease
		err := c.AcquireLeases(ctx, []string{id}, 2*time.Minute, LeaseOptions{Type: metadata.LeaseShared, Nonce: nonce})
		if err != nil {
			return nil, fmt.Errorf("failed to acquire shared lease: %w", err)
		}
	}

	lctx, cancel := context.WithCancel(context.Background())
	r := &FileReader{
		client:          c,
		inode:           inode,
		fileKey:         fileKey,
		offset:          0,
		currentChunkIdx: -1,
		token:           token,
		leaseNonce:      nonce,
		readAhead:       make(map[int64]*readAheadResult),
		ctx:             lctx,
		cancel:          cancel,
		onExpired:       c.onLeaseExpired,
	}

	r.wg.Add(1)
	go r.leaseRenewalLoop(id, metadata.LeaseShared)

	return r, nil
}

func (r *FileReader) Close() error {
	r.cancel()
	r.wg.Wait()
	// Release lease
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.client.ReleaseLeases(ctx, []string{r.inode.ID}, r.leaseNonce)
	return nil
}

func (r *FileReader) leaseRenewalLoop(id string, lType metadata.LeaseType) {
	defer r.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	lastSuccess := time.Now()
	leaseDuration := 2 * time.Minute

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := r.client.AcquireLeases(ctx, []string{id}, leaseDuration, LeaseOptions{Type: lType, Nonce: r.leaseNonce})
			cancel()

			if err == nil {
				lastSuccess = time.Now()
			} else {
				if time.Since(lastSuccess) > leaseDuration {
					if r.onExpired != nil {
						r.onExpired(id, err)
					}
					return // Stop renewal if expired
				}
			}
		}
	}
}

// triggerPrefetch starts an asynchronous download of the specified chunk index.
// The caller MUST hold r.mu.
func (r *FileReader) triggerPrefetch(idx int64) {
	if idx < 0 || idx >= int64(len(r.inode.ChunkManifest)) {
		return
	}
	chunkEntry := r.inode.ChunkManifest[idx]
	token := r.token

	r.readAheadMu.Lock()
	if _, exists := r.readAhead[idx]; exists {
		r.readAheadMu.Unlock()
		return
	}
	res := &readAheadResult{ready: make(chan struct{})}
	r.readAhead[idx] = res
	r.readAheadMu.Unlock()

	go func() {
		ct, err := r.client.downloadChunk(r.ctx, chunkEntry.ID, chunkEntry.URLs, token)
		var pt []byte
		if err == nil {
			pt, err = crypto.DecryptChunk(r.fileKey, uint64(idx), ct)
		}

		res.data = pt
		res.err = err
		close(res.ready)
	}()
}
func (r *FileReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.read(p)
}

func (r *FileReader) read(p []byte) (int, error) {
	if r.offset >= int64(r.inode.Size) {
		return 0, io.EOF
	}

	remaining := int64(r.inode.Size) - r.offset
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	totalRead := 0
	chunkSize := int64(crypto.ChunkSize)

	for len(p) > 0 {
		chunkIdx := r.offset / chunkSize
		chunkOffset := r.offset % chunkSize

		// Detect seek/random access and clear cache
		if r.currentChunkIdx != -1 && chunkIdx != r.currentChunkIdx+1 && chunkIdx != r.currentChunkIdx {
			r.readAheadMu.Lock()
			// Clear cache to prevent leaks during random access
			for k := range r.readAhead {
				delete(r.readAhead, k)
			}
			r.readAheadMu.Unlock()
		}

		var pt []byte
		if chunkIdx == r.currentChunkIdx && r.currentChunk != nil {
			pt = r.currentChunk
		} else if data := r.inode.GetInlineData(); data != nil {
			// Handle Inlined File
			pt = data
			r.currentChunk = pt
			r.currentChunkIdx = 0
		} else {
			// Trigger prefetch for next few chunks
			for i := int64(1); i <= 3; i++ {
				r.triggerPrefetch(chunkIdx + i)
			}

			// Check Cache
			r.readAheadMu.Lock()
			res, exists := r.readAhead[chunkIdx]
			r.readAheadMu.Unlock()

			if exists {
				// Wait for it
				r.mu.Unlock()
				<-res.ready
				r.mu.Lock()

				if res.err != nil {
					// Fallthrough to direct download if prefetch failed with 401/403
					if apiErr, ok := res.err.(*APIError); !ok || (apiErr.StatusCode != http.StatusUnauthorized && apiErr.StatusCode != http.StatusForbidden) {
						return totalRead, res.err
					}
				} else {
					pt = res.data
				}
			}

			if pt == nil {
				if chunkIdx >= int64(len(r.inode.ChunkManifest)) {
					break
				}
				chunkEntry := r.inode.ChunkManifest[chunkIdx]

				// Capture immutable state before unlocking for network I/O
				inodeID := r.inode.ID
				token := r.token
				r.mu.Unlock()
				ct, err := r.client.downloadChunk(r.ctx, chunkEntry.ID, chunkEntry.URLs, token)
				if err != nil {
					var apiErr *APIError
					if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden) {
						// Token might be stale or file was unlinked/appended.
						// Refresh metadata AND token.
						if updated, terr := r.client.GetInode(r.ctx, inodeID); terr == nil {
							if newToken, terr2 := r.client.issueToken(r.ctx, inodeID, nil, "R"); terr2 == nil {
								r.mu.Lock()
								r.inode = updated
								r.token = newToken
								r.mu.Unlock()
								// Retry with new token and potentially new URLs
								if chunkIdx < int64(len(updated.ChunkManifest)) {
									newEntry := updated.ChunkManifest[chunkIdx]
									ct, err = r.client.downloadChunk(r.ctx, newEntry.ID, newEntry.URLs, newToken)
								}
							}
						}
					}
				}
				r.mu.Lock()

				if err != nil {
					return totalRead, err
				}
				pt, err = crypto.DecryptChunk(r.fileKey, uint64(chunkIdx), ct)
				if err != nil {
					return totalRead, err
				}
			}

			// Cleanup old
			r.readAheadMu.Lock()
			delete(r.readAhead, chunkIdx-1)
			delete(r.readAhead, chunkIdx-2)
			r.readAheadMu.Unlock()

			r.currentChunk = pt
			r.currentChunkIdx = chunkIdx
		}

		available := int64(len(pt)) - chunkOffset
		if available <= 0 {
			return totalRead, fmt.Errorf("chunk offset out of bounds")
		}

		toCopy := int64(len(p))
		if toCopy > available {
			toCopy = available
		}

		copy(p, pt[chunkOffset:chunkOffset+toCopy])

		n := int(toCopy)
		p = p[n:]
		r.offset += int64(n)
		totalRead += n
	}
	return totalRead, nil
}

func (r *FileReader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offset = off
	return r.read(p)
}

func (r *FileReader) Stat() *metadata.Inode {
	return r.inode
}

func (r *FileReader) SetInode(inode *metadata.Inode) {
	var needsToken bool
	r.mu.Lock()

	// Invalidate cache if manifest or inline data changed
	invalidate := false
	if len(inode.ChunkManifest) != len(r.inode.ChunkManifest) {
		invalidate = true
	} else if !bytes.Equal(inode.GetInlineData(), r.inode.GetInlineData()) {
		invalidate = true
	} else {
		for i := range inode.ChunkManifest {
			if inode.ChunkManifest[i].ID != r.inode.ChunkManifest[i].ID {
				invalidate = true
				break
			}
		}
	}

	if invalidate {
		r.currentChunkIdx = -1
		r.currentChunk = nil
		// Also clear readahead cache
		r.readAheadMu.Lock()
		for k := range r.readAhead {
			delete(r.readAhead, k)
		}
		r.readAheadMu.Unlock()
		needsToken = true
	}

	r.inode = inode
	inodeID := r.inode.ID
	r.mu.Unlock()

	// Refresh token outside the lock if the manifest changed
	if needsToken {
		if token, err := r.client.issueToken(r.ctx, inodeID, nil, "R"); err == nil {
			r.mu.Lock()
			r.token = token
			r.mu.Unlock()
		}
	}
}

// ReadFile returns a reader for the specified file ID.
// If fileKey is nil, it attempts to unlock it using the client's identity.
func (c *Client) ReadFile(ctx context.Context, id string, fileKey []byte) (io.ReadCloser, error) {
	return c.NewReader(ctx, id, fileKey)
}

func (c *Client) OpenBlobRead(ctx context.Context, path string) (io.ReadCloser, error) {
	// 1. Resolve path to Inode
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		return nil, err
	}

	// 2. Open Reader
	rc, err := c.ReadFile(ctx, inode.ID, key)
	if err == nil {
		return rc, nil
	}

	// 3. Handle Placeholder (Leased) Files
	if errors.Is(err, crypto.ErrRecipientNotFound) {
		c.sessionMu.RLock()
		token := c.sessionToken
		c.sessionMu.RUnlock()
		// Strictly check if it's a new placeholder: Owned by us, Version 1, and Empty.
		isPlaceholder := false
		if inode.Version == 1 && inode.Size == 0 {
			now := time.Now().UnixNano()
			for _, l := range inode.Leases {
				if l.SessionID == token && l.Type == metadata.LeaseExclusive && l.Expiry > now {
					isPlaceholder = true
					break
				}
			}
		}
		if isPlaceholder {
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
	}

	return nil, err
}

func (c *Client) OpenBlobWrite(ctx context.Context, path string) (io.WriteCloser, error) {
	return c.OpenBlobWriteWithLease(ctx, path, "")
}

// OpenBlobWriteWithLease creates a writer for a blob.
// If leaseNonce is empty, it will acquire a new exclusive path lease.
func (c *Client) OpenBlobWriteWithLease(ctx context.Context, path string, leaseNonce string) (io.WriteCloser, error) {
	// 1. Resolve Path and compute PathID
	dir, fileName := filepath.Split(strings.TrimRight(path, "/"))
	if dir == "" {
		dir = "/"
	}

	pInode, pKey, err := c.ResolvePath(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve parent dir: %w", err)
	}

	mac := hmac.New(sha256.New, pKey)
	mac.Write([]byte(fileName))
	nameHMAC := hex.EncodeToString(mac.Sum(nil))
	parentID := pInode.ID
	groupID := pInode.GroupID

	pathID := "path:" + parentID + ":" + nameHMAC
	if path == "/" {
		pathID = "path:root:" + c.rootID
	}

	var fileKey []byte
	var oldInodeID string

	if childID, exists := pInode.Children[nameHMAC]; exists {
		oldInodeID = childID
		oldInode, _ := c.getInode(ctx, childID)
		if oldInode != nil {
			fileKey, _ = c.UnlockInode(ctx, oldInode)
		}
	}

	if fileKey == nil {
		fileKey = make([]byte, 32)
		rand.Read(fileKey)
	}

	// Always generate new UUID for atomic swap
	uidBytes := make([]byte, 16)
	rand.Read(uidBytes)
	newID := hex.EncodeToString(uidBytes)

	lb, err := c.createLockbox(ctx, fileKey, 0600, c.userID, groupID)
	if err != nil {
		return nil, err
	}

	inode := &metadata.Inode{
		ID:      newID,
		Type:    metadata.FileType,
		Mode:    0600,
		OwnerID: c.userID,
		GroupID: groupID,
		// Links will be updated during commit
		Links:   map[string]bool{parentID + ":" + nameHMAC: true},
		Lockbox: lb,
		Version: 1,
	}
	inode.SetName(fileName)
	inode.SetFileKey(fileKey)
	// Acquire lease first to prevent concurrent writers on this path.
	nonce := leaseNonce
	if nonce == "" {
		nonce = generateID()
		err := c.withConflictRetry(ctx, func() error {
			return c.AcquireLeases(ctx, []string{pathID}, 2*time.Minute, LeaseOptions{
				Type:  metadata.LeaseExclusive,
				Nonce: nonce,
			})
		})
		if err != nil {
			return nil, err
		}
	}

	lctx, cancel := context.WithCancel(context.Background())
	w := &FileWriter{
		client:     c,
		ctx:        lctx,
		cancel:     cancel,
		leaseNonce: nonce,
		inode:      *inode,
		fileKey:    fileKey,
		parentID:   parentID,
		nameHMAC:   nameHMAC,
		swapMode:   true,
		swapPath:   path,
		pathID:     pathID,
		oldInodeID: oldInodeID,
		isNew:      true, // It's "new" because it's a new InodeID
		onExpired:  c.onLeaseExpired,
	}

	w.wg.Add(1)
	go w.leaseRenewalLoop(pathID, metadata.LeaseExclusive)

	return w, nil
}

// FileWriter provides buffered write access to a file, performing an atomic swap on Close.
type FileWriter struct {
	client     *Client
	ctx        context.Context
	cancel     context.CancelFunc
	leaseNonce string
	wg         sync.WaitGroup
	inode      metadata.Inode

	fileKey    []byte
	parentID   string
	parentKey  []byte
	name       string
	nameHMAC   string
	buf        []byte
	manifest   []metadata.ChunkEntry
	written    int64
	closed     bool
	isNew      bool
	swapMode   bool
	swapPath   string
	pathID     string
	oldInodeID string

	onExpired func(id string, err error)
}

func (w *FileWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	n := len(p)
	for len(p) > 0 {
		space := crypto.ChunkSize - len(w.buf)
		if space > len(p) {
			w.buf = append(w.buf, p...)
			break
		}
		w.buf = append(w.buf, p[:space]...)
		if err := w.flushChunk(); err != nil {
			return 0, err
		}
		p = p[space:]
	}
	w.written += int64(n)
	return n, nil
}

func (w *FileWriter) flushChunk() error {
	if len(w.buf) == 0 {
		return nil
	}
	// Use next chunk index (current manifest length)
	chunkIndex := uint64(len(w.manifest))
	cid, ct, err := crypto.EncryptChunk(w.fileKey, w.buf, chunkIndex)
	if err != nil {
		return err
	}
	token, err := w.client.issueToken(w.ctx, w.inode.ID, []string{cid}, "W")
	if err != nil {
		return err
	}
	nodes, err := w.client.allocateNodes(w.ctx)
	if err != nil {
		return err
	}
	if err := w.client.uploadChunk(w.ctx, cid, ct, nodes, token); err != nil {
		return err
	}
	var nodeIDs []string
	for _, node := range nodes {
		nodeIDs = append(nodeIDs, node.ID)
	}
	w.manifest = append(w.manifest, metadata.ChunkEntry{ID: cid, Nodes: nodeIDs})
	w.buf = w.buf[:0]
	return nil
}

// Finish finalizes the file data (flushing chunks, updating manifest) but does NOT commit metadata to Raft.
func (w *FileWriter) Finish() error {
	if w.closed {
		return nil
	}

	// Handle Inlining for small files
	if len(w.manifest) == 0 && len(w.buf) <= metadata.InlineLimit {
		w.inode.SetInlineData(w.buf)
		w.inode.ChunkManifest = nil
		w.inode.Size = uint64(len(w.buf))
	} else {
		if err := w.flushChunk(); err != nil {
			return err
		}
		w.inode.SetInlineData(nil)
		w.inode.ChunkManifest = w.manifest
		w.inode.Size = uint64(w.written)
	}

	w.inode.SetFileKey(w.fileKey)
	return nil
}

func (w *FileWriter) Close() error {
	if w.closed {
		return nil
	}

	if err := w.Finish(); err != nil {
		return err
	}
	w.closed = true

	// Final Metadata Update
	var err error

	if w.swapMode {
		err = w.client.withConflictRetry(w.ctx, func() error {
			var cmds []metadata.LogCommand

			// 1. Prepare New Inode
			cmdNew, err := w.client.PrepareCreate(w.ctx, w.inode)
			if err != nil {
				return err
			}
			cmds = append(cmds, cmdNew)

			// 2. Update Parent Link
			if w.parentID != "" {
				parent, err := w.client.getInode(w.ctx, w.parentID)
				if err != nil {
					return fmt.Errorf("failed to get parent for swap: %w", err)
				}
				if parent.Children == nil {
					parent.Children = make(map[string]string)
				}
				parent.Children[w.nameHMAC] = w.inode.ID
				cmdParent, err := w.client.PrepareUpdate(w.ctx, *parent)
				if err != nil {
					return err
				}
				cmdParent.LeaseBindings = map[string]string{w.nameHMAC: w.pathID}
				cmds = append(cmds, cmdParent)
			}

			// 3. Optional: Delete Old Inode (Decrement NLink)
			if w.oldInodeID != "" && w.oldInodeID != w.inode.ID {
				cmdOld, err := w.client.PrepareDelete(w.oldInodeID)
				if err != nil {
					return err
				}
				cmds = append(cmds, cmdOld)
			}

			// Execute Atomic Batch
			_, err = w.client.ApplyBatch(w.ctx, cmds)
			return err
		})
	} else {
		if w.isNew {
			if w.parentID == "" {
				return fmt.Errorf("cannot link new file: parentID missing")
			}
			// 1. Create Inode
			_, err = w.client.createInode(w.ctx, w.inode)
			if err != nil {
				return err
			}
			// 2. Link to Parent
			_, err = w.client.UpdateInode(w.ctx, w.parentID, func(p *metadata.Inode) error {
				if p.Children == nil {
					p.Children = make(map[string]string)
				}
				// MERGE: Only add our entry
				p.Children[w.nameHMAC] = w.inode.ID
				return nil
			})
		} else {
			_, err = w.client.UpdateInode(w.ctx, w.inode.ID, func(i *metadata.Inode) error {
				i.ChunkManifest = w.inode.ChunkManifest
				i.Size = w.inode.Size
				i.SetInlineData(nil)
				return nil
			})
		}
	}

	// Release Lease
	leaseTarget := w.inode.ID
	if w.swapMode {
		leaseTarget = w.pathID
	}
	if releaseErr := w.client.ReleaseLeases(w.ctx, []string{leaseTarget}, w.leaseNonce); releaseErr != nil {
		log.Printf("Warning: Failed to release lease for %s: %v", leaseTarget, releaseErr)
	}

	if err == nil {
		w.client.keyMu.Lock()
		fm := fileMetadata{
			key:     w.fileKey,
			groupID: w.inode.GroupID,
			linkTag: w.parentID + ":" + w.nameHMAC,
			inlined: w.inode.GetInlineData() != nil,
		}
		w.client.keyCache[w.inode.ID] = fm
		if w.swapMode && w.swapPath != "" {
			w.client.keyCache[w.swapPath] = fm
		}
		w.client.keyMu.Unlock()

		if w.swapMode && w.swapPath != "" {
			w.client.pathMu.Lock()
			w.client.pathCache[w.swapPath] = pathCacheEntry{
				inodeID: w.inode.ID,
				key:     w.fileKey,
				linkTag: w.parentID + ":" + w.nameHMAC,
			}
			w.client.pathMu.Unlock()
		}
	}

	w.cancel()
	w.wg.Wait()

	return err
}

// Abort closes the writer and releases leases WITHOUT committing to Raft.
func (w *FileWriter) Abort() {
	if w.closed {
		return
	}
	w.closed = true
	w.cancel()
	w.wg.Wait()

	leaseTarget := w.inode.ID
	if w.swapMode {
		leaseTarget = w.pathID
	}
	w.client.ReleaseLeases(w.ctx, []string{leaseTarget}, w.leaseNonce)
}

func (w *FileWriter) leaseRenewalLoop(id string, lType metadata.LeaseType) {
	defer w.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	lastSuccess := time.Now()
	leaseDuration := 2 * time.Minute

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := w.client.AcquireLeases(ctx, []string{id}, leaseDuration, LeaseOptions{Type: lType, Nonce: w.leaseNonce})
			cancel()

			if err == nil {
				lastSuccess = time.Now()
			} else {
				if time.Since(lastSuccess) > leaseDuration {
					if w.onExpired != nil {
						w.onExpired(id, err)
					}
					return
				}
			}
		}
	}
}

// FetchChunk retrieves and decrypts a specific chunk of a file by index.
func (c *Client) FetchChunk(ctx context.Context, id string, key []byte, chunkIdx int64) ([]byte, error) {
	inode, err := c.GetInode(ctx, id)
	if err != nil {
		return nil, err
	}
	// Handle inline data
	if data := inode.GetInlineData(); data != nil {
		if chunkIdx == 0 {
			return data, nil
		}
		return nil, io.EOF
	}

	if chunkIdx < 0 || chunkIdx >= int64(len(inode.ChunkManifest)) {
		return nil, io.EOF
	}
	entry := inode.ChunkManifest[chunkIdx]
	token, err := c.issueToken(ctx, id, nil, "R")
	if err != nil {
		return nil, err
	}
	ct, err := c.downloadChunk(ctx, entry.ID, entry.URLs, token)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptChunk(key, uint64(chunkIdx), ct)
}

// DownloadChunkData downloads and decrypts a single chunk from a set of node URLs.
func (c *Client) DownloadChunkData(ctx context.Context, inodeID string, chunkID string, urls []string, key []byte, chunkIndex uint64) ([]byte, error) {
	token, err := c.issueToken(ctx, inodeID, []string{chunkID}, "R")
	if err != nil {
		return nil, err
	}
	enc, err := c.downloadChunk(ctx, chunkID, urls, token)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptChunk(key, chunkIndex, enc)
}

// UploadChunkData encrypts and uploads a single chunk to the cluster.
func (c *Client) UploadChunkData(ctx context.Context, id string, key []byte, chunkIndex uint64, data []byte) (metadata.ChunkEntry, error) {
	// Encrypt
	cid, ct, err := crypto.EncryptChunk(key, data, chunkIndex)
	if err != nil {
		return metadata.ChunkEntry{}, err
	}

	// Upload
	token, err := c.issueToken(ctx, id, []string{cid}, "W")
	if err != nil {
		return metadata.ChunkEntry{}, err
	}
	nodes, err := c.allocateNodes(ctx)
	if err != nil {
		return metadata.ChunkEntry{}, err
	}
	if err := c.uploadChunk(ctx, cid, ct, nodes, token); err != nil {
		return metadata.ChunkEntry{}, err
	}

	var nodeIDs []string
	var nodeURLs []string
	for _, node := range nodes {
		nodeIDs = append(nodeIDs, node.ID)
		nodeURLs = append(nodeURLs, node.Address)
	}
	return metadata.ChunkEntry{ID: cid, Nodes: nodeIDs, URLs: nodeURLs}, nil
}

// CommitInodeManifest updates the chunk manifest and size of an inode.
func (c *Client) CommitInodeManifest(ctx context.Context, id string, manifest []metadata.ChunkEntry, size uint64) (*metadata.Inode, error) {
	return c.UpdateInode(ctx, id, func(i *metadata.Inode) error {
		i.ChunkManifest = manifest
		i.Size = size
		i.SetInlineData(nil) // Ensure we are not inline if we have chunks
		return nil
	})
}

// SyncFile synchronizes local dirty chunks to the cluster and updates the manifest.
func (c *Client) SyncFile(ctx context.Context, id string, r io.ReaderAt, size int64, dirtyChunks map[int64]bool) (*metadata.Inode, error) {
	// 1. Get current inode state
	inode, err := c.getInode(ctx, id)
	if err != nil {
		return nil, err
	}

	key, err := c.UnlockInode(ctx, inode)
	if err != nil {
		return nil, err
	}

	// 2. Handle Small File Inlining (Optimized Path)
	if size <= metadata.InlineLimit {
		buf := make([]byte, size)
		if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
			return nil, err
		}
		return c.UpdateInode(ctx, id, func(i *metadata.Inode) error {
			i.SetInlineData(buf)
			i.ChunkManifest = nil
			i.ChunkPages = nil
			i.Size = uint64(size)
			return nil
		})
	}

	// 3. Handle Chunked File (Differential Update)
	inode.SetInlineData(nil)
	numChunks := (size + crypto.ChunkSize - 1) / crypto.ChunkSize
	newManifest := make([]metadata.ChunkEntry, numChunks)

	type chunkUpload struct {
		index int64
		id    string
		data  []byte
	}
	var uploads []chunkUpload
	var chunkIDs []string

	buf := make([]byte, crypto.ChunkSize)

	for i := int64(0); i < numChunks; i++ {
		// Determine if we need to upload this chunk
		needUpload := false
		if dirtyChunks != nil && dirtyChunks[i] {
			needUpload = true
		} else if i >= int64(len(inode.ChunkManifest)) {
			// New chunk (file grew)
			needUpload = true
		} else {
			// Check if we can reuse existing
			newManifest[i] = inode.ChunkManifest[i]
		}

		if needUpload {
			// Read from source
			offset := i * int64(crypto.ChunkSize)
			chunkSize := int64(crypto.ChunkSize)
			if offset+chunkSize > size {
				chunkSize = size - offset
			}

			// Clear buffer for safety
			for k := range buf {
				buf[k] = 0
			}

			n, err := r.ReadAt(buf[:chunkSize], offset)
			if err != nil && err != io.EOF {
				return nil, err
			}
			chunkData := make([]byte, n)
			copy(chunkData, buf[:n])

			// Encrypt
			cid, ct, err := crypto.EncryptChunk(key, chunkData, uint64(i))
			if err != nil {
				return nil, err
			}

			uploads = append(uploads, chunkUpload{
				index: i,
				id:    cid,
				data:  ct,
			})
			chunkIDs = append(chunkIDs, cid)
		}
	}

	if len(uploads) > 0 {
		// Batch: Issue one token for all chunks
		token, err := c.issueToken(ctx, id, chunkIDs, "W")
		if err != nil {
			return nil, err
		}
		// Batch: Allocate nodes once
		nodes, err := c.allocateNodes(ctx)
		if err != nil {
			return nil, err
		}

		var nodeIDs []string
		for _, node := range nodes {
			nodeIDs = append(nodeIDs, node.ID)
		}

		// Perform uploads (could be parallelized, but serial is safer for now)
		for _, u := range uploads {
			if err := c.uploadChunk(ctx, u.id, u.data, nodes, token); err != nil {
				return nil, err
			}
			newManifest[u.index] = metadata.ChunkEntry{ID: u.id, Nodes: nodeIDs}
		}
	}

	return c.UpdateInode(ctx, id, func(i *metadata.Inode) error {
		i.ChunkManifest = newManifest
		i.Size = uint64(size)
		i.SetInlineData(nil)
		return nil
	})
}

// ReadDataFile reads and unmarshals a single JSON data file.
func (c *Client) ReadDataFile(ctx context.Context, name string, data any) error {
	return c.ReadDataFiles(ctx, []string{name}, []any{data})
}

// ReadDataFiles reads and unmarshals multiple files atomically.
// It uses shared filename leases to ensure a consistent snapshot of the namespace.
func (c *Client) ReadDataFiles(ctx context.Context, names []string, targets []any) error {
	if len(names) != len(targets) {
		return fmt.Errorf("names and targets length mismatch")
	}

	readers, err := c.NewReaders(ctx, names)
	if err != nil {
		return err
	}
	defer func() {
		for _, r := range readers {
			if r != nil {
				r.Close()
			}
		}
	}()

	for i, r := range readers {
		if err := json.NewDecoder(r).Decode(targets[i]); err != nil {
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("failed to decode %s: %w", names[i], err)
			}
		}
	}
	return nil
}

// ClearCache clears the client's key and path caches.
func (c *Client) ClearCache() {
	c.keyMu.Lock()
	clear(c.keyCache)
	c.keyMu.Unlock()

	c.pathMu.Lock()
	clear(c.pathCache)
	c.pathMu.Unlock()
}

// NewReaders returns a collection of Readers for the given paths, ensuring a consistent point-in-time snapshot.
func (c *Client) NewReaders(ctx context.Context, paths []string) ([]*FileReader, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	pathIDs := make([]string, len(paths))
	for i, path := range paths {
		pid, err := c.GetPathID(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate path ID for %s: %w", path, err)
		}
		pathIDs[i] = pid
	}

	// 1. Acquire shared filename leases for all path IDs to "freeze" the namespace.
	nonce := generateID()
	lctx, lcancel := context.WithTimeout(ctx, 30*time.Second)
	err := c.withConflictRetry(lctx, func() error {
		return c.AcquireLeases(lctx, pathIDs, 2*time.Minute, LeaseOptions{Type: metadata.LeaseShared, Nonce: nonce})
	})
	lcancel()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire namespace snapshot: %w", err)
	}
	defer c.ReleaseLeases(ctx, pathIDs, nonce)

	// Clear cache to ensure we see the state as of when leases were acquired
	c.ClearCache()

	// 2. Resolve all paths sequentially.
	ids := make([]string, len(paths))
	keys := make([][]byte, len(paths))
	for i, path := range paths {
		_, key, err := c.ResolvePath(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %s: %w", path, err)
		}
		entry, _ := c.getPathCache(path)
		ids[i] = entry.inodeID
		keys[i] = key
	}

	// 3. Batch fetch all Inodes
	inodes, err := c.getInodes(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch inodes: %w", err)
	}

	// Create a map for quick lookup
	inodeMap := make(map[string]*metadata.Inode)
	for _, inode := range inodes {
		inodeMap[inode.ID] = inode
	}

	// 4. Acquire shared Inode leases in one batch
	inodeNonce := generateID()
	err = c.AcquireLeases(ctx, ids, 2*time.Minute, LeaseOptions{Type: metadata.LeaseShared, Nonce: inodeNonce})
	if err != nil {
		return nil, fmt.Errorf("failed to acquire inode leases: %w", err)
	}

	// 5. Initialize readers
	readers := make([]*FileReader, len(paths))
	for i, id := range ids {
		inode, ok := inodeMap[id]
		if !ok {
			// Cleanup
			for j := 0; j < i; j++ {
				readers[j].Close()
			}
			c.ReleaseLeases(ctx, ids, inodeNonce)
			return nil, fmt.Errorf("inode %s not found in batch fetch", id)
		}

		r, err := c.NewReaderWithInode(ctx, inode, keys[i], inodeNonce)
		if err != nil {
			// Cleanup
			for j := 0; j < i; j++ {
				readers[j].Close()
			}
			c.ReleaseLeases(ctx, ids, inodeNonce)
			return nil, fmt.Errorf("failed to open %s: %w", paths[i], err)
		}
		readers[i] = r
	}

	return readers, nil
}

// SaveDataFile serializes data to JSON and performs an atomic write to the cluster.
func (c *Client) SaveDataFile(ctx context.Context, name string, data any) error {
	return c.SaveDataFiles(ctx, []string{name}, []any{data})
}

// SaveDataFiles writes multiple files atomically in a single Raft transaction.
func (c *Client) SaveDataFiles(ctx context.Context, names []string, data []any) error {
	if len(names) != len(data) {
		return fmt.Errorf("names and data length mismatch")
	}

	pathIDs := make([]string, len(names))
	for i, name := range names {
		pid, err := c.GetPathID(ctx, name)
		if err != nil {
			return fmt.Errorf("failed to calculate path ID for %s: %w", name, err)
		}
		pathIDs[i] = pid
	}

	// Phase 41: Batch acquire all path leases first to prevent livelock with readers.
	nonce := generateID()
	lctx, lcancel := context.WithTimeout(ctx, 30*time.Second)
	err := c.withConflictRetry(lctx, func() error {
		return c.AcquireLeases(lctx, pathIDs, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce})
	})
	lcancel()
	if err != nil {
		return err
	}
	defer c.ReleaseLeases(ctx, pathIDs, nonce)

	// 1. Prepare all writers
	writers := make([]*FileWriter, len(names))
	for i, name := range names {
		b, err := json.Marshal(data[i])
		if err != nil {
			for j := 0; j < i; j++ {
				writers[j].Abort()
			}
			return err
		}
		wc, err := c.OpenBlobWriteWithLease(ctx, name, nonce)
		if err != nil {
			for j := 0; j < i; j++ {
				writers[j].Abort()
			}
			return err
		}
		if _, err := wc.Write(b); err != nil {
			if fw, ok := wc.(*FileWriter); ok {
				fw.Abort()
			} else {
				wc.Close()
			}
			for j := 0; j < i; j++ {
				writers[j].Abort()
			}
			return err
		}
		fw, ok := wc.(*FileWriter)
		if !ok {
			wc.Close()
			for j := 0; j < i; j++ {
				writers[j].Abort()
			}
			return fmt.Errorf("unexpected writer type for %s", name)
		}
		if err := fw.Finish(); err != nil {
			fw.Abort()
			for j := 0; j < i; j++ {
				writers[j].Abort()
			}
			return err
		}
		writers[i] = fw
	}

	// 2. Perform Atomic Commit for all writers together
	// Each writer is in swapMode, so they have prepared their new inodes.
	// We need to collect all their commands and apply them in one batch.
	err = c.withConflictRetry(ctx, func() error {
		var allCmds []metadata.LogCommand
		parents := make(map[string]*metadata.Inode)
		parentBindings := make(map[string]map[string]string)

		for _, w := range writers {
			// Phase 31: Prepare New Inode
			cmdNew, err := c.PrepareCreate(ctx, w.inode)
			if err != nil {
				return err
			}
			allCmds = append(allCmds, cmdNew)

			// Update Parent Link
			if w.parentID != "" {
				parent, ok := parents[w.parentID]
				if !ok {
					parent, err = c.getInode(ctx, w.parentID)
					if err != nil {
						return err
					}
					parents[w.parentID] = parent
				}

				if parent.Children == nil {
					parent.Children = make(map[string]string)
				}
				parent.Children[w.nameHMAC] = w.inode.ID

				// Track lease binding for this parent
				bindings, ok := parentBindings[w.parentID]
				if !ok {
					bindings = make(map[string]string)
					parentBindings[w.parentID] = bindings
				}
				bindings[w.nameHMAC] = w.pathID
			}

			// Delete Old via NLink decrement
			if w.oldInodeID != "" && w.oldInodeID != w.inode.ID {
				oldInode, err := c.getInode(ctx, w.oldInodeID)
				if err != nil {
					return err
				}
				if oldInode.NLink > 0 {
					oldInode.NLink--
				}
				cmdOld, err := c.PrepareUpdate(ctx, *oldInode)
				if err != nil {
					return err
				}
				allCmds = append(allCmds, cmdOld)
			}
		}

		// Add all parent updates to the batch
		for pid, parent := range parents {
			cmdParent, err := c.PrepareUpdate(ctx, *parent)
			if err != nil {
				return err
			}
			cmdParent.LeaseBindings = parentBindings[pid]
			allCmds = append(allCmds, cmdParent)
		}

		_, err := c.ApplyBatch(ctx, allCmds)
		return err
	})

	if err != nil {
		for _, w := range writers {
			w.Abort()
		}
		return err
	}

	// 3. Post-commit: Cleanup and caching
	c.keyMu.Lock()
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	defer c.keyMu.Unlock()

	for _, w := range writers {
		// Mark as closed so Close() doesn't try to commit again
		w.closed = true
		w.cancel()
		w.wg.Wait()

		// Update caches
		fm := fileMetadata{
			key:     w.fileKey,
			groupID: w.inode.GroupID,
			linkTag: w.parentID + ":" + w.nameHMAC,
			inlined: w.inode.GetInlineData() != nil,
		}
		c.keyCache[w.inode.ID] = fm
		c.keyCache[w.swapPath] = fm

		c.pathCache[w.swapPath] = pathCacheEntry{
			inodeID: w.inode.ID,
			key:     w.fileKey,
			linkTag: w.parentID + ":" + w.nameHMAC,
			inode:   &w.inode,
		}
	}

	return nil
}

func (c *Client) OpenForUpdate(ctx context.Context, name string, data any) (func(bool), error) {
	return c.OpenManyForUpdate(ctx, []string{name}, []any{data})
}

func (c *Client) OpenManyForUpdate(ctx context.Context, names []string, data []any) (func(bool), error) {
	if len(names) != len(data) {
		return nil, fmt.Errorf("names and data length mismatch")
	}

	pathIDs := make([]string, len(names))
	for i, name := range names {
		pid, err := c.GetPathID(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate path ID for %s: %w", name, err)
		}
		pathIDs[i] = pid
	}

	// 1. Acquire path-based exclusive leases for all files
	nonce := generateID()
	if err := c.AcquireLeases(ctx, pathIDs, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce}); err != nil {
		return nil, err
	}

	// 2. Read all files
	for i, name := range names {
		if err := c.ReadDataFile(ctx, name, data[i]); err != nil {
			c.ReleaseLeases(ctx, pathIDs, nonce)
			return nil, err
		}
	}

	// 3. Return commit callback
	return func(commit bool) {
		if commit {
			if err := c.SaveDataFiles(ctx, names, data); err != nil {
				log.Printf("Failed to save files during transactional update: %v", err)
			}
		}
		c.ReleaseLeases(ctx, pathIDs, nonce)
	}, nil
}

// GetInode fetches the inode metadata.
func (c *Client) GetInode(ctx context.Context, id string) (*metadata.Inode, error) {
	return c.getInode(ctx, id)
}

// GetInodeUnverified retrieves inode metadata by ID without verifying its integrity signatures.
// Use this only for administrative tasks or when the decryption key is unavailable.
func (c *Client) GetInodeUnverified(ctx context.Context, id string) (*metadata.Inode, error) {
	return c.getInodeInternal(ctx, id, false)
}

// GetInodes fetches metadata for multiple inodes in a single batch call.
func (c *Client) GetInodes(ctx context.Context, ids []string) ([]*metadata.Inode, error) {
	return c.getInodes(ctx, ids)
}

// VerifyInode verifies the manifest signatures and authorized signers.
func (c *Client) VerifyInode(ctx context.Context, inode *metadata.Inode) error {
	// 1. Decrypt ClientBlob if present
	if len(inode.ClientBlob) > 0 {
		fileKey := inode.GetFileKey()
		if len(fileKey) == 0 {
			// Try cache first
			c.keyMu.RLock()
			meta, ok := c.keyCache[inode.ID]
			c.keyMu.RUnlock()
			if ok {
				fileKey = meta.key
				inode.SetFileKey(fileKey)
			}
		}

		if len(fileKey) == 0 {
			// Try to unlock file key from lockbox
			if c.decKey != nil {
				key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
				if err == nil {
					fileKey = key
					inode.SetFileKey(key)
				}
			}
			if len(fileKey) == 0 && inode.GroupID != "" {
				gk, err := c.GetGroupPrivateKey(ctx, inode.GroupID)
				if err == nil {
					key, err := inode.Lockbox.GetFileKey(inode.GroupID, gk)
					if err == nil {
						fileKey = key
						inode.SetFileKey(key)
					}
				}
			}
			// Try World Access
			if len(fileKey) == 0 {
				if _, exists := inode.Lockbox[metadata.WorldID]; exists {
					gk, gerr := c.GetWorldPrivateKey(ctx)
					if gerr == nil {
						key, err := inode.Lockbox.GetFileKey(metadata.WorldID, gk)
						if err == nil {
							fileKey = key
							inode.SetFileKey(key)
						}
					}
				}
			}
		}

		if len(fileKey) == 0 {
			// If we can't decrypt, we can't verify the full integrity or see names.
			return fmt.Errorf("failed to decrypt file key: %w", crypto.ErrRecipientNotFound)
		}

		var blob metadata.InodeClientBlob
		if err := c.decryptInodeClientBlob(inode.ClientBlob, fileKey, &blob); err != nil {
			return fmt.Errorf("failed to decrypt client blob: %w", err)
		}

		// Populate transient fields
		inode.SetName(blob.Name)
		inode.SetSymlinkTarget(blob.SymlinkTarget)
		inode.SetInlineData(blob.InlineData)
		inode.SetMTime(blob.MTime)
		inode.SetUID(blob.UID)
		inode.SetGID(blob.GID)
	}

	signerID := inode.GetSignerID()

	if signerID == "" {
		return fmt.Errorf("missing manifest signature for inode %s", inode.ID)
	}

	// 2. Verify Signatures
	hash := inode.ManifestHash()
	user, err := c.GetUser(ctx, signerID)
	if err != nil {
		return fmt.Errorf("failed to fetch signer %s: %w", signerID, err)
	}
	if !crypto.VerifySignature(user.SignKey, hash, inode.UserSig) {
		return fmt.Errorf("invalid manifest signature by %s", signerID)
	}

	groupValid := false
	if inode.GroupID != "" && len(inode.GroupSig) > 0 {
		group, err := c.GetGroup(ctx, inode.GroupID)
		if err == nil {
			if crypto.VerifySignature(group.SignKey, hash, inode.GroupSig) {
				groupValid = true
			}
		}
	}

	// 3. Check Authorization
	authorized := (signerID == inode.OwnerID) || groupValid

	if !authorized {
		// Admin Bypass for mkdir --owner:
		// If signer is an admin, they are authorized to sign empty directories
		// (this is for initial administrative setup/provisioning).
		if user.IsAdmin && inode.Type == metadata.DirType && len(inode.Children) == 0 {
			authorized = true
		}
	}

	if !authorized {
		return fmt.Errorf("signer %s is not authorized for inode %s", signerID, inode.ID)
	}

	return nil
}

// UnlockInode attempts to decrypt the file key for the inode using the client's identity.
func (c *Client) UnlockInode(ctx context.Context, inode *metadata.Inode) ([]byte, error) {
	// Phase 31: Verification
	// This also decrypts ClientBlob and populates transient fields (including fileKey if unlocked)
	if err := c.VerifyInode(ctx, inode); err != nil {
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}

	if key := inode.GetFileKey(); len(key) > 0 {
		// Update Cache
		var linkTag string
		for tag := range inode.Links {
			linkTag = tag
			break
		}
		c.keyMu.Lock()
		c.keyCache[inode.ID] = fileMetadata{
			key:     key,
			groupID: inode.GroupID,
			linkTag: linkTag,
			inlined: inode.GetInlineData() != nil,
		}
		c.keyMu.Unlock()
		return key, nil
	}

	if c.decKey == nil {
		return nil, fmt.Errorf("client has no identity to unlock file")
	}

	var lastErr error

	// 1. Try personal access
	key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
	if err == nil {
		// Update Cache
		var linkTag string
		for tag := range inode.Links {
			linkTag = tag
			break
		}
		c.keyMu.Lock()
		c.keyCache[inode.ID] = fileMetadata{
			key:     key,
			groupID: inode.GroupID,
			linkTag: linkTag,
			inlined: inode.GetInlineData() != nil,
		}
		c.keyMu.Unlock()
		return key, nil
	}
	lastErr = err

	// 2. Try group access if personal failed
	if inode.GroupID != "" {
		if _, exists := inode.Lockbox[inode.GroupID]; exists {
			gk, gerr := c.GetGroupPrivateKey(ctx, inode.GroupID)
			if gerr == nil {
				key, err = inode.Lockbox.GetFileKey(inode.GroupID, gk)
				if err == nil {
					return key, nil
				}
				lastErr = err
			} else {
				lastErr = gerr
			}
		}
	}

	// 3. Try world access if group failed
	if _, exists := inode.Lockbox[metadata.WorldID]; exists {
		wk, err := c.GetWorldPrivateKey(ctx)
		if err == nil {
			key, err = inode.Lockbox.GetFileKey(metadata.WorldID, wk)
			if err == nil {
				return key, nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("access denied: no applicable recipient in lockbox")
	}
	return nil, lastErr
}

// GetGroupPrivateKey retrieves and decrypts the group private key.
func (c *Client) GetGroupPrivateKey(ctx context.Context, groupID string) (*mlkem.DecapsulationKey768, error) {
	c.keyMu.RLock()
	gk, ok := c.groupKeys[groupID]
	c.keyMu.RUnlock()
	if ok {
		return gk, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/group/"+groupID+"/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := c.unsealResponse(ctx, resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		return nil, fmt.Errorf("failed to fetch group private key: %d %s", resp.StatusCode, string(b))
	}

	var entry crypto.LockboxEntry
	if err := json.NewDecoder(body).Decode(&entry); err != nil {
		return nil, err
	}

	// Group Private Key is encrypted for Client's identity
	secret, err := crypto.Decapsulate(c.decKey, entry.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("group key decapsulate failed: %w", err)
	}
	privBytes, err := crypto.DecryptDEM(secret, entry.DEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("group key decrypt failed: %w", err)
	}

	gk, err = crypto.UnmarshalDecapsulationKey(privBytes)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.groupKeys[groupID] = gk
	c.keyMu.Unlock()
	return gk, nil
}

// GetGroupSignKey retrieves and decrypts the group signing key.
func (c *Client) GetGroupSignKey(ctx context.Context, groupID string) (*crypto.IdentityKey, error) {
	c.keyMu.RLock()
	gk, ok := c.groupSignKeys[groupID]
	c.keyMu.RUnlock()
	if ok {
		return gk, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/group/"+groupID+"/sign/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := c.unsealResponse(ctx, resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		return nil, fmt.Errorf("failed to fetch group signing key: %d %s", resp.StatusCode, string(b))
	}

	var entry crypto.LockboxEntry
	if err := json.NewDecoder(body).Decode(&entry); err != nil {
		return nil, err
	}

	// Group Signing Key is encrypted for Client's identity
	secret, err := crypto.Decapsulate(c.decKey, entry.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("group sign key decapsulate failed: %w", err)
	}
	privBytes, err := crypto.DecryptDEM(secret, entry.DEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("group sign key decrypt failed: %w", err)
	}

	gsk := crypto.UnmarshalIdentityKey(privBytes)

	c.keyMu.Lock()
	c.groupSignKeys[groupID] = gsk
	c.keyMu.Unlock()
	return gsk, nil
}

// GetWorldPublicKey fetches the cluster's world public key.
func (c *Client) GetWorldPublicKey(ctx context.Context) (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	wp := c.worldPublic
	c.keyMu.RUnlock()
	if wp != nil {
		return wp, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/meta/key/world", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := c.unsealResponse(ctx, resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		return nil, fmt.Errorf("failed to fetch world pub key: %d %s", resp.StatusCode, string(b))
	}
	b, _ := io.ReadAll(body)
	pk, err := crypto.UnmarshalEncapsulationKey(b)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.worldPublic = pk
	c.keyMu.Unlock()
	return pk, nil
}

// GetWorldPrivateKey retrieves and decrypts the cluster's world private key.
func (c *Client) GetWorldPrivateKey(ctx context.Context) (*mlkem.DecapsulationKey768, error) {
	c.keyMu.RLock()
	wp := c.worldPrivate
	c.keyMu.RUnlock()
	if wp != nil {
		return wp, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/meta/key/world/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := c.unsealResponse(ctx, resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		return nil, fmt.Errorf("failed to fetch world private key: %d %s", resp.StatusCode, string(b))
	}

	var data struct {
		KEM string `json:"kem"`
		DEM string `json:"dem"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
	}

	kemCT, err := base64.StdEncoding.DecodeString(data.KEM)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM encoding: %w", err)
	}
	demCT, err := base64.StdEncoding.DecodeString(data.DEM)
	if err != nil {
		return nil, fmt.Errorf("invalid DEM encoding: %w", err)
	}

	// Decrypt using Client's identity
	ss, err := crypto.Decapsulate(c.decKey, kemCT)
	if err != nil {
		return nil, fmt.Errorf("world key decapsulate failed: %w", err)
	}
	privBytes, err := crypto.DecryptDEM(ss, demCT)
	if err != nil {
		return nil, fmt.Errorf("world key decrypt failed: %w", err)
	}

	wk, err := crypto.UnmarshalDecapsulationKey(privBytes)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.worldPrivate = wk
	c.keyMu.Unlock()
	return wk, nil
}

// GetGroup fetches the group metadata.
func (c *Client) GetGroup(ctx context.Context, id string) (*metadata.Group, error) {
	return c.getGroupInternal(ctx, id, false)
}

func (c *Client) getGroupInternal(ctx context.Context, id string, bypassCache bool) (*metadata.Group, error) {
	if !bypassCache {
		c.cacheMu.RLock()
		if g, ok := c.groupCache[id]; ok {
			c.cacheMu.RUnlock()
			return g, nil
		}
		c.cacheMu.RUnlock()
	}

	group, err := c.getGroupRaw(ctx, id)
	if err != nil {
		return nil, err
	}

	if err := c.VerifyGroup(ctx, group); err != nil {
		return nil, fmt.Errorf("group integrity check failed: %w", err)
	}

	// 1. Decrypt ClientBlob if present
	if len(group.ClientBlob) > 0 {
		gk, err := c.GetGroupPrivateKey(ctx, group.ID)
		if err == nil {
			var blob metadata.GroupClientBlob
			if err := c.decryptClientBlob(group.ClientBlob, gk, &blob); err == nil {
				group.SetName(blob.Name)
			}
		}
	}

	c.cacheMu.Lock()
	c.groupCache[id] = group
	c.cacheMu.Unlock()

	return group, nil
}

// GetGroupUnverified fetches the group metadata skipping cache.
// Useful for integrity verification tests.
func (c *Client) GetGroupUnverified(ctx context.Context, id string) (*metadata.Group, error) {
	return c.getGroupInternal(ctx, id, true)
}

func (c *Client) getGroupRaw(ctx context.Context, id string) (*metadata.Group, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/group/"+id, nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := c.unsealResponse(ctx, resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		return nil, fmt.Errorf("get group failed: %d %s", resp.StatusCode, string(b))
	}

	var group metadata.Group
	if err := json.NewDecoder(body).Decode(&group); err != nil {
		return nil, err
	}
	return &group, nil
}

// VerifyGroup verifies the group metadata signature and authorized signer.
func (c *Client) VerifyGroup(ctx context.Context, group *metadata.Group) error {
	if group.Signature == nil {
		return fmt.Errorf("missing group signature")
	}

	hash := group.Hash()
	if group.SignerID == "" {
		return fmt.Errorf("missing signer ID for group %s (server-signed metadata prohibited)", group.ID)
	}

	// User-signed
	user, err := c.GetUser(ctx, group.SignerID)
	if err != nil {
		return fmt.Errorf("failed to fetch group signer %s: %w", group.SignerID, err)
	}
	if !crypto.VerifySignature(user.SignKey, hash, group.Signature) {
		return fmt.Errorf("invalid manifest signature by %s", group.SignerID)
	}

	return nil
}

// GetGroupName retrieves and decrypts the human-readable name of a group.
func (c *Client) GetGroupName(ctx context.Context, group *metadata.Group) (string, error) {
	gk, err := c.GetGroupPrivateKey(ctx, group.ID)
	if err != nil {
		return "", err
	}

	if len(group.ClientBlob) > 0 {
		var blob metadata.GroupClientBlob
		if err := c.decryptClientBlob(group.ClientBlob, gk, &blob); err == nil {
			return blob.Name, nil
		}
	}

	return "", fmt.Errorf("failed to decrypt group name: client blob missing or invalid")
}

// DecryptGroupName decrypts a group name from a list entry using cached or provided keys.
func (c *Client) DecryptGroupName(ctx context.Context, entry metadata.GroupListEntry) (string, error) {
	// 1. Try Cache
	c.keyMu.RLock()
	gdk, ok := c.groupKeys[entry.ID]
	c.keyMu.RUnlock()

	if !ok {
		// 2. Try to unlock group key from entry's lockbox
		if c.decKey == nil {
			return "", fmt.Errorf("client has no identity to unlock group")
		}
		// 2a. Try personal access
		gk, err := entry.Lockbox.GetFileKey(c.userID, c.decKey)
		if err != nil && entry.OwnerID != "" && entry.OwnerID != c.userID {
			// 2b. Try delegated access (requires owner group key)
			// Check if we have the owner group key cached
			c.keyMu.RLock()
			ogdk, gok := c.groupKeys[entry.OwnerID]
			c.keyMu.RUnlock()

			if gok {
				gk, err = entry.Lockbox.GetFileKey(entry.OwnerID, ogdk)
			} else {
				// Fallback to network if not cached
				if ogdk, gerr := c.GetGroupPrivateKey(ctx, entry.OwnerID); gerr == nil {
					gk, err = entry.Lockbox.GetFileKey(entry.OwnerID, ogdk)
				}
			}
		}
		if err != nil {
			return "", err
		}

		gdk, err = crypto.UnmarshalDecapsulationKey(gk)
		if err != nil {
			return "", err
		}

		// Cache it
		c.keyMu.Lock()
		c.groupKeys[entry.ID] = gdk
		c.keyMu.Unlock()
	}

	if len(entry.ClientBlob) > 0 {
		var blob metadata.GroupClientBlob
		if err := c.decryptClientBlob(entry.ClientBlob, gdk, &blob); err == nil {
			return blob.Name, nil
		}
	}

	return "", fmt.Errorf("failed to decrypt group name")
}

// GetGroupRegistryKey retrieves and decrypts the group registry key.
func (c *Client) getGroupRegistryKey(ctx context.Context, group *metadata.Group) ([]byte, error) {
	if c.decKey == nil {
		return nil, fmt.Errorf("client has no identity to unlock registry")
	}
	// 1. Try personal access
	key, err := group.RegistryLockbox.GetFileKey(c.userID, c.decKey)
	if err == nil {
		return key, nil
	}

	// 2. Try group-based management access
	if group.OwnerID != "" && group.OwnerID != c.userID {
		if _, exists := group.RegistryLockbox[group.OwnerID]; exists {
			gk, gerr := c.GetGroupPrivateKey(ctx, group.OwnerID)
			if gerr == nil {
				return group.RegistryLockbox.GetFileKey(group.OwnerID, gk)
			}
		}
	}
	return nil, err
}

func (c *Client) encryptRegistry(key []byte, members []metadata.MemberEntry) ([]byte, error) {
	data, err := json.Marshal(members)
	if err != nil {
		return nil, err
	}
	return crypto.EncryptDEM(key, data)
}

func (c *Client) decryptRegistry(key []byte, encrypted []byte) ([]metadata.MemberEntry, error) {
	data, err := crypto.DecryptDEM(key, encrypted)
	if err != nil {
		return nil, err
	}
	var members []metadata.MemberEntry
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, err
	}
	return members, nil
}

// CreateGroup creates a new user group.
func (c *Client) CreateGroup(ctx context.Context, name string, quotaEnabled bool) (*metadata.Group, error) {
	return c.createGroupInternal(ctx, name, false, quotaEnabled)
}

// CreateSystemGroup creates a new system group (Admin only).
func (c *Client) CreateSystemGroup(ctx context.Context, name string, quotaEnabled bool) (*metadata.Group, error) {
	return c.createGroupInternal(ctx, name, true, quotaEnabled)
}

func (c *Client) allocateGID(ctx context.Context) (uint32, error) {
	var res struct {
		GID uint32 `json:"gid"`
	}
	err := c.withRetry(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/group/gid/allocate", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, resp.Body)
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return err
		}
		return nil
	})
	return res.GID, err
}

func (c *Client) createGroupInternal(ctx context.Context, name string, isSystem bool, quotaEnabled bool) (*metadata.Group, error) {
	// Allocate numeric GID
	gid, err := c.allocateGID(ctx)
	if err != nil {
		return nil, fmt.Errorf("GID allocation failed: %w", err)
	}

	// 1. Generate Encryption Key (ML-KEM)
	dk, _ := crypto.GenerateEncryptionKey()
	pk := dk.EncapsulationKey().Bytes()
	priv := crypto.MarshalDecapsulationKey(dk)

	// 2. Generate Signing Key (ML-DSA/Ed25519)
	sk, _ := crypto.GenerateIdentityKey()
	spk := sk.Public()
	spriv := sk.MarshalPrivate()

	lb := crypto.NewLockbox()
	// Encrypt group private encryption key for the creator (owner)
	if err := lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), priv); err != nil {
		return nil, err
	}
	// Encrypt group private signing key for the creator (owner)
	// We use a different ID suffix to distinguish in the lockbox
	if err := lb.AddRecipient(c.userID+":sign", c.decKey.EncapsulationKey(), spriv); err != nil {
		return nil, err
	}

	// 3. Generate Registry Key (Symmetric)
	rk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rk); err != nil {
		return nil, err
	}

	// 3.2 Prepare ClientBlob
	blob := metadata.GroupClientBlob{Name: name}
	encBlob, err := c.encryptClientBlob(blob, dk.EncapsulationKey())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt group client blob: %w", err)
	}

	rlb := crypto.NewLockbox()
	// Encrypt Registry Key for the owner
	if err := rlb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), rk); err != nil {
		return nil, err
	}

	// Initialize Registry with the owner (if email is known)
	initialMembers := []metadata.MemberEntry{
		{UserID: c.userID, Info: ""}, // Placeholder for owner info
	}
	encRegistry, err := c.encryptRegistry(rk, initialMembers)
	if err != nil {
		return nil, err
	}

	// Generate Random GroupID (UUID replacement)
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return nil, fmt.Errorf("random failed: %w", err)
	}
	groupID := hex.EncodeToString(idBytes)

	group := &metadata.Group{
		ID:                groupID,
		GID:               gid,
		OwnerID:           c.userID,
		Members:           map[string]bool{c.userID: true},
		EncKey:            pk,
		SignKey:           spk,
		Lockbox:           lb,
		RegistryLockbox:   rlb,
		EncryptedRegistry: encRegistry,
		ClientBlob:        encBlob,
		IsSystem:          isSystem,
		QuotaEnabled:      quotaEnabled,
		Version:           1,
	}
	group.SetName(name)

	// Cache keys for signing
	c.keyMu.Lock()
	c.groupKeys[groupID] = dk
	c.groupSignKeys[groupID] = sk
	c.keyMu.Unlock()

	// Client-side Signing
	if err := c.signGroup(ctx, group, false); err != nil {
		return nil, err
	}

	// Unified Mutation: Use ApplyBatch
	cmd, err := c.PrepareCreateGroup(ctx, *group)
	if err != nil {
		return nil, err
	}

	results, err := c.ApplyBatch(ctx, []metadata.LogCommand{cmd})
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("empty results from createGroup batch")
	}

	if err := c.IsResultError(results[0]); err != nil {
		return nil, err
	}

	var created metadata.Group
	if err := json.Unmarshal(results[0], &created); err != nil {
		return nil, fmt.Errorf("failed to decode created group: %w", err)
	}

	// Verify the response integrity
	if err := c.VerifyGroup(ctx, &created); err != nil {
		return nil, fmt.Errorf("integrity check failed on created group: %w", err)
	}

	return &created, nil
}

// AddUserToGroup adds a new member to an existing group.
// AddUserToGroup adds a new member to an existing group.
func (c *Client) AddUserToGroup(ctx context.Context, groupID, userID, info string, ci *ContactInfo) error {
	var userEK *mlkem.EncapsulationKey768
	if ci != nil {
		if ci.UserID != userID {
			return fmt.Errorf("contact string user ID mismatch")
		}
		var err error
		userEK, err = crypto.UnmarshalEncapsulationKey(ci.EncKey)
		if err != nil {
			return fmt.Errorf("invalid contact enc key: %w", err)
		}
	} else {
		// We need the user's public key from the server
		user, err := c.GetUser(ctx, userID)
		if err != nil {
			return err
		}
		userEK, err = crypto.UnmarshalEncapsulationKey(user.EncKey)
		if err != nil {
			return err
		}
	}

	_, err := c.UpdateGroup(ctx, groupID, func(group *metadata.Group) error {
		// 1. Update Group Private Keys (Lockbox)
		gk, err := c.GetGroupPrivateKey(ctx, groupID)
		if err != nil {
			return err
		}
		priv := crypto.MarshalDecapsulationKey(gk)

		gsk, err := c.GetGroupSignKey(ctx, groupID)
		if err != nil {
			return err
		}
		spriv := gsk.MarshalPrivate()

		// Add new member to lockbox
		if err := group.Lockbox.AddRecipient(userID, userEK, priv); err != nil {
			return err
		}
		if err := group.Lockbox.AddRecipient(userID+":sign", userEK, spriv); err != nil {
			return err
		}

		if group.Members == nil {
			group.Members = make(map[string]bool)
		}
		group.Members[userID] = true

		// 2. Update Member Registry (if we are a manager)
		rk, err := c.getGroupRegistryKey(ctx, group)
		if err == nil {
			// We are a manager, update the registry
			members, err := c.decryptRegistry(rk, group.EncryptedRegistry)
			if err == nil {
				// Merge or update entry
				found := false
				for i, m := range members {
					if m.UserID == userID {
						members[i].Info = info
						found = true
						break
					}
				}
				if !found {
					members = append(members, metadata.MemberEntry{UserID: userID, Info: info})
				}

				encRegistry, err := c.encryptRegistry(rk, members)
				if err != nil {
					return err
				}
				group.EncryptedRegistry = encRegistry
			}
		}
		return nil
	})
	return err
}

// RemoveUserFromGroup removes a member from an existing group.
func (c *Client) RemoveUserFromGroup(ctx context.Context, groupID, userID string) error {
	_, err := c.UpdateGroup(ctx, groupID, func(group *metadata.Group) error {
		// 1. Remove from Members map
		if group.Members != nil {
			delete(group.Members, userID)
		}

		// 2. Remove from Lockbox
		if group.Lockbox != nil {
			delete(group.Lockbox, userID)
			delete(group.Lockbox, userID+":sign")
		}

		// 3. Remove from Registry (if we are a manager)
		rk, err := c.getGroupRegistryKey(ctx, group)
		if err == nil {
			// We are a manager, update the registry
			members, err := c.decryptRegistry(rk, group.EncryptedRegistry)
			if err == nil {
				var newMembers []metadata.MemberEntry
				for _, m := range members {
					if m.UserID != userID {
						newMembers = append(newMembers, m)
					}
				}
				encRegistry, err := c.encryptRegistry(rk, newMembers)
				if err != nil {
					return err
				}
				group.EncryptedRegistry = encRegistry
			}

			// Also remove from RegistryLockbox
			if group.RegistryLockbox != nil {
				delete(group.RegistryLockbox, userID)
			}
		}
		return nil
	})
	return err
}

// SetAttr updates the attributes of an inode at the given path.
func (c *Client) SetAttr(ctx context.Context, path string, attr metadata.SetAttrRequest) error {
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		return err
	}
	_, err = c.SetAttrByID(ctx, inode, key, attr)
	return err
}

// SetAttrByID updates the attributes of an inode by ID. Returns the updated inode.
func (c *Client) SetAttrByID(ctx context.Context, inode *metadata.Inode, key []byte, attr metadata.SetAttrRequest) (*metadata.Inode, error) {
	var ownerPK *mlkem.EncapsulationKey768
	var groupPK *mlkem.EncapsulationKey768
	var worldPK *mlkem.EncapsulationKey768

	// 1. Pre-fetch any required public keys before entering the atomic update
	// (which holds the controlMu semaphore).
	if attr.OwnerID != nil {
		u, err := c.GetUser(ctx, *attr.OwnerID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch new owner: %w", err)
		}
		pk, err := crypto.UnmarshalEncapsulationKey(u.EncKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal new owner key: %w", err)
		}
		ownerPK = pk
	}

	targetMode := inode.Mode
	if attr.Mode != nil {
		targetMode = *attr.Mode
	}
	targetGroupID := inode.GroupID
	if attr.GroupID != nil {
		targetGroupID = *attr.GroupID
	}

	worldRead := (targetMode & 0004) != 0
	groupRW := (targetMode & 0060) != 0

	if worldRead {
		wpk, err := c.GetWorldPublicKey(ctx)
		if err == nil {
			worldPK = wpk
		}
	}

	if targetGroupID != "" && groupRW {
		group, err := c.GetGroup(ctx, targetGroupID)
		if err == nil {
			gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
			if err == nil {
				groupPK = gpk
			}
		}
	}

	// 2. Perform Atomic Update
	updated, err := c.UpdateInode(ctx, inode.ID, func(i *metadata.Inode) error {
		// Update local fields
		if attr.Mode != nil {
			i.Mode = *attr.Mode
		}
		if attr.OwnerID != nil {
			i.OwnerID = *attr.OwnerID
		}
		if attr.GroupID != nil {
			i.GroupID = *attr.GroupID
		}
		if attr.Size != nil {
			i.Size = *attr.Size
		}
		if attr.MTime != nil {
			i.SetMTime(*attr.MTime)
		}

		// Update Lockbox (using pre-fetched keys)
		if ownerPK != nil {
			i.Lockbox.AddRecipient(*attr.OwnerID, ownerPK, key)
		}

		worldRead := (i.Mode & 0004) != 0
		groupRW := (i.Mode & 0060) != 0

		// 2.1 World Access
		_, worldInLockbox := i.Lockbox[metadata.WorldID]
		if worldRead && worldPK != nil {
			i.Lockbox.AddRecipient(metadata.WorldID, worldPK, key)
		} else if !worldRead && worldInLockbox {
			delete(i.Lockbox, metadata.WorldID)
		}

		// 2.2 Group Access
		if i.GroupID != "" {
			_, groupInLockbox := i.Lockbox[i.GroupID]
			if groupRW && groupPK != nil {
				i.Lockbox.AddRecipient(i.GroupID, groupPK, key)
			} else if !groupRW && groupInLockbox {
				delete(i.Lockbox, i.GroupID)
			}
		}
		return nil
	})

	return updated, err
}

// Remove deletes an inode at the given path.
// Remove deletes the file or empty directory at the given path.
func (c *Client) Remove(ctx context.Context, path string) error {
	return c.RemoveEntry(ctx, path)
}

// PushKeySync uploads an encrypted configuration blob to the server.
// Requires a valid session and mandatory Layer 7 E2EE (Sealing).
func (c *Client) PushKeySync(ctx context.Context, blob *metadata.KeySyncBlob) error {
	data, _ := json.Marshal(blob)
	req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/user/keysync", nil)
	if err != nil {
		return err
	}

	if err := c.authenticateRequest(ctx, req); err != nil {
		return err
	}

	if err := c.sealBody(ctx, req, data); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push keysync failed: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

// PullKeySync retrieves the encrypted configuration blob from the server.
// Authenticates using an OIDC JWT.
func (c *Client) PullKeySync(ctx context.Context, jwt string) (*metadata.KeySyncBlob, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/user/keysync", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pull keysync failed: %d %s", resp.StatusCode, string(b))
	}

	var blob metadata.KeySyncBlob
	if err := json.NewDecoder(resp.Body).Decode(&blob); err != nil {
		return nil, fmt.Errorf("failed to decode keysync blob: %w", err)
	}
	return &blob, nil
}

func (c *Client) acquireControl(ctx context.Context) error {
	select {
	case c.controlSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) leaseRenewalLoop(ctx context.Context, wg *sync.WaitGroup, ids []string, lType metadata.LeaseType, nonce string) {
	defer wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	lastSuccess := time.Now()
	leaseDuration := 2 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := c.AcquireLeases(rctx, ids, leaseDuration, LeaseOptions{Type: lType, Nonce: nonce})
			cancel()

			if err == nil {
				lastSuccess = time.Now()
			} else {
				if time.Since(lastSuccess) > leaseDuration {
					log.Printf("LEASE EXPIRED: failed to renew %v: %v", ids, err)
					return
				}
			}
		}
	}
}

func (c *Client) releaseControl() {
	<-c.controlSem
}

func (c *Client) acquireData(ctx context.Context) error {
	select {
	case c.dataSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) releaseData() {
	<-c.dataSem
}

func (c *Client) withRetry(ctx context.Context, op func() error) error {
	var lastErr error
	backoff := 100 * time.Millisecond
	maxBackoff := 10 * time.Second

	for i := 0; i < 5; i++ {
		err := op()
		if err == nil {
			return nil
		}
		lastErr = err

		if !c.isRetryable(err) {
			return err
		}

		// Exponential backoff with jitter (optimized global PRNG)
		jitter := time.Duration(mrand.Int63n(int64(backoff / 2)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff + jitter):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return fmt.Errorf("operation failed after retries: %w", lastErr)
}

func (c *Client) isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// 1. Check for specific wrapped types
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true // Always retry DNS errors during cluster join/discovery
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// urlErr.Err contains the underlying network error
		return c.isRetryable(urlErr.Err)
	}

	// 2. Check for specific syscall errors
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// 3. API errors
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusServiceUnavailable ||
			apiErr.StatusCode == http.StatusTooManyRequests ||
			apiErr.StatusCode == http.StatusInternalServerError ||
			apiErr.Code == metadata.ErrCodeNotLeader {
			return true
		}
	}

	return false
}

func (c *Client) withConflictRetry(ctx context.Context, op func() error) error {
	backoff := 50 * time.Millisecond
	maxBackoff := 5 * time.Second

	for i := 0; i < 100; i++ {
		err := op()
		if err == nil {
			return nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
				return err
			}
		}

		isConflict := (errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict) ||
			errors.Is(err, metadata.ErrConflict) ||
			(apiErr != nil && apiErr.Code == metadata.ErrCodeVersionConflict) ||
			(apiErr != nil && apiErr.Code == metadata.ErrCodeLeaseRequired)

		if isConflict {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			jitter := time.Duration(mrand.Int63n(int64(backoff/2) + 1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff + jitter):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		return err
	}
	return metadata.ErrConflict
}

func (c *Client) GetClusterStats(ctx context.Context) (*metadata.ClusterStats, error) {
	var stats metadata.ClusterStats
	err := c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/cluster/stats", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, resp.Body)
		}

		return json.NewDecoder(resp.Body).Decode(&stats)
	})

	if err != nil {
		return nil, err
	}
	return &stats, nil
}

type LeaseOptions struct {
	Type         metadata.LeaseType
	Nonce        string
	Lockbox      crypto.Lockbox
	Placeholders []metadata.Inode
	// OnExpired is called if the background renewal loop fails (e.g., network partition)
	// and the lease actually expires on the server.
	OnExpired func(id string, err error)
}

// AcquireLeases acquires distributed leases for multiple identifiers.
func (c *Client) AcquireLeases(ctx context.Context, ids []string, duration time.Duration, opts LeaseOptions) error {
	if len(ids) == 0 {
		return nil
	}

	leaseIDs := make([]string, len(ids))
	for i, id := range ids {
		if !metadata.IsInodeID(id) && !strings.HasPrefix(id, "path:") {
			leaseIDs[i] = "path:" + id
		} else {
			leaseIDs[i] = id
		}
	}

	req := metadata.LeaseRequest{
		InodeIDs:     leaseIDs,
		Duration:     int64(duration),
		Type:         opts.Type,
		Nonce:        opts.Nonce,
		Placeholders: opts.Placeholders,
	}
	data, _ := json.Marshal(req)

	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/lease/acquire", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, hReq); err != nil {
			return err
		}
		if err := c.sealBody(ctx, hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// ReleaseLeases releases previously acquired distributed leases.
func (c *Client) ReleaseLeases(ctx context.Context, ids []string, nonce string) error {
	leaseIDs := make([]string, len(ids))
	for i, id := range ids {
		if !metadata.IsInodeID(id) && !strings.HasPrefix(id, "path:") {
			leaseIDs[i] = "path:" + id
		} else {
			leaseIDs[i] = id
		}
	}

	req := metadata.LeaseRequest{
		InodeIDs: leaseIDs,
		Nonce:    nonce,
	}
	data, _ := json.Marshal(req)

	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/lease/release", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, hReq); err != nil {
			return err
		}
		if err := c.sealBody(ctx, hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// AdminListUsers returns an iterator over all users in the cluster.
func (c *Client) AdminListUsers(ctx context.Context) iter.Seq2[*metadata.User, error] {
	return func(yield func(*metadata.User, error) bool) {
		var users []metadata.User
		err := c.withRetry(ctx, func() error {
			if err := c.acquireControl(ctx); err != nil {
				return err
			}
			defer c.releaseControl()

			req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/users", nil)
			if err != nil {
				return err
			}
			req.Header.Set("X-DistFS-Sealed", "true")
			if err := c.authenticateRequest(ctx, req); err != nil {
				return err
			}

			resp, err := c.httpClient.Do(req)
			if err != nil {
				return err
			}
			body, err := c.unsealResponse(ctx, resp)
			if err != nil {
				return err
			}
			defer body.Close()

			if resp.StatusCode != http.StatusOK {
				return c.newAPIError(resp, body)
			}

			return json.NewDecoder(body).Decode(&users)
		})

		if err != nil {
			yield(nil, err)
			return
		}

		for i := range users {
			if !yield(&users[i], nil) {
				return
			}
		}
	}
}

// AdminListGroups returns an iterator over all groups in the cluster.
func (c *Client) AdminListGroups(ctx context.Context) iter.Seq2[*metadata.Group, error] {
	return func(yield func(*metadata.Group, error) bool) {
		cursor := ""
		for {
			var groups []metadata.Group
			var nextCursor string

			err := c.withRetry(ctx, func() error {
				if err := c.acquireControl(ctx); err != nil {
					return err
				}
				defer c.releaseControl()

				u := c.serverURL + "/v1/admin/groups"
				if cursor != "" {
					u += "?cursor=" + cursor
				}
				req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
				if err != nil {
					return err
				}
				req.Header.Set("X-DistFS-Sealed", "true")
				if err := c.authenticateRequest(ctx, req); err != nil {
					return err
				}

				resp, err := c.httpClient.Do(req)
				if err != nil {
					return err
				}
				body, err := c.unsealResponse(ctx, resp)
				if err != nil {
					return err
				}
				defer body.Close()

				if resp.StatusCode != http.StatusOK {
					return c.newAPIError(resp, body)
				}

				nextCursor = resp.Header.Get("X-DistFS-Next-Cursor")
				return json.NewDecoder(body).Decode(&groups)
			})

			if err != nil {
				yield(nil, err)
				return
			}

			for i := range groups {
				if !yield(&groups[i], nil) {
					return
				}
			}

			if nextCursor == "" {
				break
			}
			cursor = nextCursor
		}
	}
}

// AdminListLeases returns an iterator over all active leases in the cluster.
func (c *Client) AdminListLeases(ctx context.Context) iter.Seq2[*metadata.LeaseInfo, error] {
	return func(yield func(*metadata.LeaseInfo, error) bool) {
		var leases []metadata.LeaseInfo
		err := c.withRetry(ctx, func() error {
			if err := c.acquireControl(ctx); err != nil {
				return err
			}
			defer c.releaseControl()

			req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/leases", nil)
			if err != nil {
				return err
			}
			req.Header.Set("X-DistFS-Sealed", "true")
			if err := c.authenticateRequest(ctx, req); err != nil {
				return err
			}

			resp, err := c.httpClient.Do(req)
			if err != nil {
				return err
			}
			body, err := c.unsealResponse(ctx, resp)
			if err != nil {
				return err
			}
			defer body.Close()

			if resp.StatusCode != http.StatusOK {
				return c.newAPIError(resp, body)
			}

			return json.NewDecoder(body).Decode(&leases)
		})

		if err != nil {
			yield(nil, err)
			return
		}

		for i := range leases {
			if !yield(&leases[i], nil) {
				return
			}
		}
	}
}

// AdminListNodes returns an iterator over all storage nodes in the cluster.
func (c *Client) AdminListNodes(ctx context.Context) iter.Seq[*metadata.Node] {
	return func(yield func(*metadata.Node) bool) {
		var nodes []metadata.Node
		_ = c.withRetry(ctx, func() error {
			if err := c.acquireControl(ctx); err != nil {
				return err
			}
			defer c.releaseControl()

			req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/nodes", nil)
			if err != nil {
				return err
			}
			req.Header.Set("X-DistFS-Sealed", "true")
			if err := c.authenticateRequest(ctx, req); err != nil {
				return err
			}

			resp, err := c.httpClient.Do(req)
			if err != nil {
				return err
			}
			body, err := c.unsealResponse(ctx, resp)
			if err != nil {
				return err
			}
			defer body.Close()

			if resp.StatusCode != http.StatusOK {
				return c.newAPIError(resp, body)
			}

			return json.NewDecoder(body).Decode(&nodes)
		})

		for i := range nodes {
			if !yield(&nodes[i]) {
				return
			}
		}
	}
}

// AdminClusterStatus returns detailed information about the cluster state and node statistics.
func (c *Client) AdminClusterStatus(ctx context.Context) (map[string]interface{}, error) {
	var status map[string]interface{}
	err := c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/status", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-DistFS-Sealed", "true") // Required
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}

		return json.NewDecoder(body).Decode(&status)
	})
	return status, err
}

// ResolveUsername attempts to resolve a user identifier to a DistFS UserID.
// It prioritizes the local registry, then falls back to admin-only server lookup for emails.
func (c *Client) ResolveUsername(ctx context.Context, identifier string) (string, *DirectoryEntry, error) {
	if metadata.IsInodeID(identifier) {
		return identifier, nil, nil // Already a 32-char hex ID (e.g., group ID or root ID)
	}

	if len(identifier) == 64 {
		if _, err := hex.DecodeString(identifier); err == nil {
			return identifier, nil, nil // Already a 64-char hex User ID
		}
	}

	if strings.Contains(identifier, "@") {
		if c.admin {
			id, err := c.AdminLookup(ctx, identifier, "Username Resolution")
			return id, nil, err
		}
		return "", nil, fmt.Errorf("email resolution requires admin privileges (use registry username instead)")
	}

	// Try the registry
	regPath := c.registryDir
	if regPath == "" {
		regPath = "/registry"
	}
	if !strings.HasSuffix(regPath, "/") {
		regPath += "/"
	}
	filePath := regPath + identifier + ".user"

	var entry DirectoryEntry
	err := c.ReadDataFile(ctx, filePath, &entry)
	if err != nil {
		if isNotFound(err) {
			return "", nil, fmt.Errorf("user '%s' not found in registry %s", identifier, regPath)
		}
		return "", nil, fmt.Errorf("failed to read registry entry for %s: %w", identifier, err)
	}

	// TODO: Phase 49 - Verify the entry signature using the VerifierID's public key
	// This requires pulling the Verifier's key from the server (or recursively from the registry).
	// For this initial implementation, we trust the registry file if we could read it
	// (meaning we have read access to the registry group).

	return entry.UserID, &entry, nil
}

// AdminLookup resolves a plaintext email to its HMAC-derived User ID.
func (c *Client) AdminLookup(ctx context.Context, email, reason string) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"email":  email,
		"reason": reason,
	})
	var result struct {
		ID string `json:"id"`
	}
	err := c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/lookup", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}

		return json.NewDecoder(body).Decode(&result)
	})
	return result.ID, err
}

// AdminAudit streams redacted audit records from the server.
func (c *Client) AdminAudit(ctx context.Context, handler func(metadata.AuditRecord) error) error {
	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/audit", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}

		// Phase 48: Audit requires sealing. For GET we must set the header
		// to indicate we expect standard unsealing behavior on the response.
		req.Header.Set("X-DistFS-Sealed", "true")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}

		decoder := json.NewDecoder(body)
		for decoder.More() {
			var record metadata.AuditRecord
			if err := decoder.Decode(&record); err != nil {
				return fmt.Errorf("audit stream decode error: %w", err)
			}
			if err := handler(record); err != nil {
				return err
			}
		}
		return nil
	})
}

// AdminAuditForest captures all audit records and organizes the Inodes into directory trees.
// TODO: For very large clusters, this full in-memory buffering should be refactored
// to use a disk-backed store or a multi-pass approach to avoid OOM.
func (c *Client) AdminAuditForest(ctx context.Context) (roots []*metadata.RedactedInode, orphans []*metadata.RedactedInode, reports []metadata.InconsistencyReport, users []metadata.RedactedUser, groups []metadata.RedactedGroup, nodes []metadata.Node, gc []string, allInodes map[string]*metadata.RedactedInode, err error) {
	allInodes = make(map[string]*metadata.RedactedInode)

	err = c.AdminAudit(ctx, func(record metadata.AuditRecord) error {

		switch record.Type {
		case metadata.AuditInode:
			allInodes[record.Inode.ID] = record.Inode
		case metadata.AuditUser:
			users = append(users, *record.User)
		case metadata.AuditGroup:
			groups = append(groups, *record.Group)
		case metadata.AuditNode:
			nodes = append(nodes, *record.Node)
		case metadata.AuditGC:
			gc = append(gc, record.GCChunk)
		case metadata.AuditInconsistency:
			reports = append(reports, *record.Report)
		}
		return nil
	})
	if err != nil {
		return
	}

	// 1. Identify Roots
	visited := make(map[string]bool)

	// Start with canonical root
	if r, ok := allInodes[metadata.RootID]; ok {
		roots = append(roots, r)
	}

	// Find implicit roots (0 links and not canonical root)
	for id, inode := range allInodes {
		if id == metadata.RootID {
			continue
		}
		if len(inode.Links) == 0 {
			roots = append(roots, inode)
		}
	}

	// 2. Mark visited nodes via DFS (to find orphans)
	var traverse func(id string, path map[string]bool)
	traverse = func(id string, path map[string]bool) {
		if visited[id] {
			return
		}
		visited[id] = true

		inode, ok := allInodes[id]
		if !ok {
			return
		}

		if inode.Type == metadata.DirType {
			newPath := make(map[string]bool)
			for k, v := range path {
				newPath[k] = v
			}
			newPath[id] = true

			for _, childID := range inode.Children {
				if newPath[childID] {
					reports = append(reports, metadata.InconsistencyReport{
						Type:     "CYCLE_DETECTED",
						TargetID: childID,
						Message:  fmt.Sprintf("infinite recursion at %s", childID),
					})
					continue
				}
				traverse(childID, newPath)
			}
		}
	}

	for _, root := range roots {
		traverse(root.ID, make(map[string]bool))
	}

	// 3. Identify Orphans
	for id, inode := range allInodes {
		if !visited[id] {
			orphans = append(orphans, inode)
		}
	}

	return
}

// AdminPromote grants administrative privileges to a user.
func (c *Client) AdminPromote(ctx context.Context, userID string) error {
	payload, _ := json.Marshal(map[string]string{"user_id": userID})
	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/promote", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// AdminJoinNode adds a new storage node to the cluster.
func (c *Client) AdminJoinNode(ctx context.Context, address string) error {
	payload, _ := json.Marshal(map[string]string{"address": address})
	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/join", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// AdminRemoveNode removes a storage node from the cluster by ID.
func (c *Client) AdminRemoveNode(ctx context.Context, id string) error {
	payload, _ := json.Marshal(map[string]string{"id": id})
	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/remove", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, req); err != nil {
			return err
		}
		if err := c.sealBody(ctx, req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// AdminSetUserLock locks or unlocks a user account.
func (c *Client) AdminSetUserLock(ctx context.Context, userID string, locked bool) error {
	req := metadata.AdminSetUserLockRequest{
		UserID: userID,
		Locked: locked,
	}
	data, _ := json.Marshal(req)
	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/lock", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, hReq); err != nil {
			return err
		}
		if err := c.sealBody(ctx, hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// AdminSetUserQuota updates the resource limits for a user.
func (c *Client) AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error {
	data, _ := json.Marshal(req)
	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/quota/user", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, hReq); err != nil {
			return err
		}
		if err := c.sealBody(ctx, hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// AdminSetGroupQuota updates the resource limits for a group.
func (c *Client) AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error {
	data, _ := json.Marshal(req)
	return c.withRetry(ctx, func() error {
		if err := c.acquireControl(ctx); err != nil {
			return err
		}
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/quota/group", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(ctx, hReq); err != nil {
			return err
		}
		if err := c.sealBody(ctx, hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(ctx, resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// IsResultError checks if a Raft command result is an error and returns it.
func (c *Client) IsResultError(data json.RawMessage) *APIError {
	var er metadata.APIErrorResponse
	if err := json.Unmarshal(data, &er); err == nil && er.Code != "" {
		// It is an error
		status := http.StatusInternalServerError
		switch er.Code {
		case metadata.ErrCodeNotFound:
			status = http.StatusNotFound
		case metadata.ErrCodeVersionConflict, metadata.ErrCodeExists:
			status = http.StatusConflict
		case metadata.ErrCodeUnauthorized:
			status = http.StatusUnauthorized
		case metadata.ErrCodeForbidden:
			status = http.StatusForbidden
		case metadata.ErrCodeNotLeader:
			status = http.StatusServiceUnavailable
		}
		return &APIError{StatusCode: status, Code: er.Code, Message: er.Message}
	}
	return nil
}

func (c *Client) signGroup(ctx context.Context, group *metadata.Group, isUpdate bool) error {
	// Re-encrypt ClientBlob if transient fields are set
	if name := group.GetName(); name != "" {
		c.keyMu.RLock()
		gdk, ok := c.groupKeys[group.ID]
		c.keyMu.RUnlock()

		if !ok {
			var err error
			gdk, err = c.GetGroupPrivateKey(ctx, group.ID)
			if err != nil {
				return fmt.Errorf("failed to fetch group key for signing: %w", err)
			}
		}

		blob := metadata.GroupClientBlob{Name: name}
		enc, err := c.encryptClientBlob(blob, gdk.EncapsulationKey())
		if err != nil {
			return fmt.Errorf("failed to encrypt group client blob: %w", err)
		}
		group.ClientBlob = enc
	}

	group.SignerID = c.userID
	hash := group.Hash()
	group.Signature = c.signKey.Sign(hash)
	return nil
}

// UpdateGroup performs an atomic read-modify-write operation on a group.
func (c *Client) PrepareCreateGroup(ctx context.Context, group metadata.Group) (metadata.LogCommand, error) {
	group.Version = 1
	if err := c.signGroup(ctx, &group, true); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(group)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdCreateGroup, Data: data, UserID: c.userID}, nil
}

func (c *Client) PrepareUpdateGroup(ctx context.Context, group metadata.Group) (metadata.LogCommand, error) {
	group.Version++
	if err := c.signGroup(ctx, &group, true); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(group)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdUpdateGroup, Data: data, UserID: c.userID}, nil
}

func (c *Client) UpdateGroup(ctx context.Context, id string, fn GroupUpdateFunc) (*metadata.Group, error) {
	unlock := c.lockMutation(id)
	defer unlock()

	for i := 0; i < 50; i++ {
		// 1. Fetch latest state
		group, err := c.getGroupInternal(ctx, id, true)
		if err != nil {
			return nil, err
		}

		// 2. Apply mutation
		if err := fn(group); err != nil {
			return nil, err
		}

		cmd, err := c.PrepareUpdateGroup(ctx, *group)
		if err != nil {
			return nil, err
		}

		results, err := c.ApplyBatch(ctx, []metadata.LogCommand{cmd})
		if err == nil {
			if len(results) == 0 {
				return nil, fmt.Errorf("empty results from updateGroup batch")
			}
			if err := c.IsResultError(results[0]); err != nil {
				return nil, err
			}
			var updated metadata.Group
			if err := json.Unmarshal(results[0], &updated); err != nil {
				return nil, fmt.Errorf("failed to decode updated group: %w", err)
			}
			return &updated, nil
		}

		if err != metadata.ErrConflict {
			return nil, err
		}
		// On conflict, wait a bit and retry
		time.Sleep(time.Duration(i*50) * time.Millisecond)
	}

	return nil, metadata.ErrConflict
}

// GetGroupMembers retrieves the list of members for a group.
// If the requester is an authorized manager, it returns emails. Otherwise, only UserIDs.
func (c *Client) GetGroupMembers(ctx context.Context, groupID string) iter.Seq2[metadata.MemberEntry, error] {
	return func(yield func(metadata.MemberEntry, error) bool) {
		group, err := c.GetGroup(ctx, groupID)
		if err != nil {
			yield(metadata.MemberEntry{}, err)
			return
		}

		var members []metadata.MemberEntry
		// Try to decrypt registry
		rk, err := c.getGroupRegistryKey(ctx, group)
		if err == nil {
			members, err = c.decryptRegistry(rk, group.EncryptedRegistry)
			if err != nil {
				yield(metadata.MemberEntry{}, err)
				return
			}
		} else {
			// Not a manager, return public member list (IDs only)
			for id := range group.Members {
				members = append(members, metadata.MemberEntry{UserID: id, Info: "[HIDDEN]"})
			}
		}

		for _, m := range members {
			if !yield(m, nil) {
				return
			}
		}
	}
}

// GroupChown changes the owner of a group.
func (c *Client) GroupChown(ctx context.Context, groupID, newOwnerID string) error {
	// Pre-fetch new owner's public key once outside the retry loop
	var newOwnerEK *mlkem.EncapsulationKey768
	newOwner, err := c.GetUser(ctx, newOwnerID)
	if err == nil {
		newOwnerEK, _ = crypto.UnmarshalEncapsulationKey(newOwner.EncKey)
	} else {
		// Try as group?
		targetGroup, err := c.GetGroup(ctx, newOwnerID)
		if err == nil {
			newOwnerEK, _ = crypto.UnmarshalEncapsulationKey(targetGroup.EncKey)
		}
	}

	_, err = c.UpdateGroup(ctx, groupID, func(group *metadata.Group) error {
		if newOwnerEK == nil {
			return fmt.Errorf("failed to fetch encryption key for new owner %s", newOwnerID)
		}
		// 1. Update RegistryLockbox (if we are a manager)
		rk, err := c.getGroupRegistryKey(ctx, group)
		if err == nil && newOwnerEK != nil {
			// Re-key Registry for new owner
			if group.RegistryLockbox == nil {
				group.RegistryLockbox = crypto.NewLockbox()
			}
			group.RegistryLockbox.AddRecipient(newOwnerID, newOwnerEK, rk)
		}

		// 2. Update Primary Lockbox (Encryption & Signing Keys)
		if newOwnerEK != nil {
			// Fetch group keys to re-key
			gk, err := c.GetGroupPrivateKey(ctx, groupID)
			if err == nil {
				group.Lockbox.AddRecipient(newOwnerID, newOwnerEK, crypto.MarshalDecapsulationKey(gk))
			}
			gsk, err := c.GetGroupSignKey(ctx, groupID)
			if err == nil {
				group.Lockbox.AddRecipient(newOwnerID+":sign", newOwnerEK, gsk.MarshalPrivate())
			}
		}

		// 3. Remove old owner access if they are not a member
		if group.Members == nil || !group.Members[c.userID] {
			delete(group.Lockbox, c.userID)
			delete(group.Lockbox, c.userID+":sign")
			delete(group.RegistryLockbox, c.userID)
		}

		group.OwnerID = newOwnerID
		return nil
	})
	return err
}

func (c *Client) lockMutation(id string) func() {
	c.mutationMu.Lock()
	mu, ok := c.mutationLocks[id]
	if !ok {
		mu = &sync.Mutex{}
		c.mutationLocks[id] = mu
	}
	c.mutationMu.Unlock()
	mu.Lock()
	return func() { mu.Unlock() }
}

func (c *Client) encryptClientBlob(v interface{}, key *mlkem.EncapsulationKey768) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return crypto.Seal(data, key, 0)
}

func (c *Client) decryptClientBlob(data []byte, key *mlkem.DecapsulationKey768, v interface{}) error {
	if len(data) == 0 {
		return nil
	}
	plain, err := crypto.Unseal(data, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

func (c *Client) encryptInodeClientBlob(v interface{}, key []byte) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return crypto.EncryptDEM(key, data)
}

func (c *Client) decryptInodeClientBlob(data []byte, key []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}
	plain, err := crypto.DecryptDEM(key, data)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}
