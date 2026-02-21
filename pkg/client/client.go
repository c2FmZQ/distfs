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
	"log"
	mrand "math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type contextKey string

const adminBypassContextKey contextKey = "admin-bypass"

func (c *Client) GetServerSignKey() ([]byte, error) {
	c.keyMu.RLock()
	sk := c.serverSignPK
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	resp, err := c.httpClient.Get(c.serverURL + "/v1/meta/key/sign")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get server sign key: %d", resp.StatusCode)
	}

	b, _ := io.ReadAll(resp.Body)
	c.keyMu.Lock()
	c.serverSignPK = b
	c.keyMu.Unlock()
	return b, nil
}

func (c *Client) GetServerKey() (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	sk := c.serverKey
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	resp, err := c.httpClient.Get(c.serverURL + "/v1/meta/key")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch server key: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
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
	linkTag string // "ParentID:NameHMAC"
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

	sessionToken  string
	sessionExpiry time.Time
	sessionKey    []byte // Cached shared secret for memoization
	sessionMu     *sync.RWMutex
	loginMu       *sync.Mutex

	// Root Anchoring (Phase 31)
	rootID      string
	rootOwner   string
	rootVersion uint64

	controlSem chan struct{}
	dataSem    chan struct{}

	admin bool

	mutationMu    *sync.Mutex
	mutationLocks map[string]*sync.Mutex
}

// NewClient creates a new DistFS client.
func NewClient(serverAddr string) *Client {
	t := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}
	return &Client{
		serverURL: serverAddr,
		httpClient: &http.Client{
			Transport: t,
			Timeout:   5 * time.Minute,
		},
		keyCache:      make(map[string]fileMetadata),
		keyMu:         &sync.RWMutex{},
		pathCache:     make(map[string]pathCacheEntry),
		pathMu:        &sync.RWMutex{},
		groupKeys:     make(map[string]*mlkem.DecapsulationKey768),
		groupSignKeys: make(map[string]*crypto.IdentityKey),
		sessionMu:     &sync.RWMutex{},
		loginMu:       &sync.Mutex{},
		controlSem:    make(chan struct{}, 128), // High throughput for metadata
		dataSem:       make(chan struct{}, 64),  // Limit chunk I/O
		mutationMu:    &sync.Mutex{},
		mutationLocks: make(map[string]*sync.Mutex),
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
	c2.rootID = id
	c2.rootOwner = owner
	c2.rootVersion = version
	return &c2
}

// WithAdmin returns a new client with the admin bypass enabled.
func (c *Client) WithAdmin(admin bool) *Client {
	c2 := *c
	c2.admin = admin
	return &c2
}

// GetRootAnchor returns the current root anchoring information.
func (c *Client) GetRootAnchor() (string, string, uint64) {
	return c.rootID, c.rootOwner, c.rootVersion
}

// UserID returns the current user ID.
func (c *Client) UserID() string {
	return c.userID
}

// Login performs the challenge-response handshake to obtain a session token.
func (c *Client) Login() error {
	// 1. Get Challenge
	reqData := metadata.AuthChallengeRequest{UserID: c.userID}
	b, _ := json.Marshal(reqData)
	resp, err := c.httpClient.Post(c.serverURL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("challenge request failed: %d %s", resp.StatusCode, string(b))
	}

	var challengeRes metadata.AuthChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeRes); err != nil {
		return err
	}

	// 2. Verify server signature over challenge
	serverSignPK, err := c.GetServerSignKey()
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

	resp, err = c.httpClient.Post(c.serverURL+"/v1/login", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: %d %s", resp.StatusCode, string(b))
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

func (c *Client) authenticateRequest(req *http.Request) error {
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
		// Acquire login lock to serialize handshakes
		c.loginMu.Lock()
		defer c.loginMu.Unlock()

		// Double check under RLock after acquiring loginMu
		c.sessionMu.RLock()
		token = c.sessionToken
		expiry = c.sessionExpiry
		c.sessionMu.RUnlock()

		if token == "" || time.Now().Add(5*time.Minute).After(expiry) {
			if err := c.Login(); err != nil {
				return fmt.Errorf("session login failed: %w", err)
			}
			c.sessionMu.RLock()
			token = c.sessionToken
			c.sessionMu.RUnlock()
		}
	}

	req.Header.Set("Session-Token", token)
	if c.admin {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	} else if bypass, _ := req.Context().Value(adminBypassContextKey).(bool); bypass {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	}
	return nil
}

func (c *Client) sealBody(req *http.Request, payload []byte) error {
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
		sk, err := c.GetServerKey()
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
func (c *Client) unsealResponse(resp *http.Response) (io.ReadCloser, error) {
	if resp.Header.Get("X-DistFS-Sealed") != "true" {
		return resp.Body, nil
	}

	defer resp.Body.Close()
	var sealed metadata.SealedResponse
	if err := json.NewDecoder(resp.Body).Decode(&sealed); err != nil {
		return nil, fmt.Errorf("failed to decode sealed response: %w", err)
	}

	serverSignPK, err := c.GetServerSignKey()
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
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/allocate", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, []byte("{}")); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests {
			return &APIError{StatusCode: resp.StatusCode, Message: "metadata server busy"}
		}

		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			return &APIError{StatusCode: resp.StatusCode}
		}
		return json.NewDecoder(body).Decode(&nodes)
	})

	if err != nil {
		return nil, fmt.Errorf("node allocation failed after retries: %w", err)
	}
	return nodes, nil
}

func (c *Client) issueToken(inodeID string, chunks []string, mode string) (string, error) {
	reqData := map[string]interface{}{
		"inode_id": inodeID,
		"chunks":   chunks,
		"mode":     mode,
	}
	data, _ := json.Marshal(reqData)

	var token string
	err := c.withRetry(context.Background(), func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequest("POST", c.serverURL+"/v1/meta/token", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
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

func (c *Client) uploadChunk(id string, data []byte, nodes []metadata.Node, token string) error {
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

	return c.withRetry(context.Background(), func() error {
		c.acquireData()
		defer c.releaseData()

		req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
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
				// Staggered start
				select {
				case <-lctx.Done():
					return lctx.Err()
				case <-time.After(1 * time.Second):
				}
			}
			go func(targetURL string) {
				c.acquireData()
				defer c.releaseData()

				req, err := http.NewRequestWithContext(lctx, "GET", targetURL+"/v1/data/"+id, nil)
				if err != nil {
					resCh <- result{err: err}
					return
				}
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}

				resp, err := c.httpClient.Do(req)
				if err != nil {
					resCh <- result{err: err}
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					resCh <- result{err: &APIError{StatusCode: resp.StatusCode, Message: "node error"}}
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
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error: %d %s", e.StatusCode, e.Message)
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
func (c *Client) ListGroups() ([]metadata.GroupListEntry, error) {
	var resp metadata.GroupListResponse
	err := c.withRetry(context.Background(), func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequest("GET", c.serverURL+"/v1/user/groups", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		res, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(res)
		if err != nil {
			return err
		}
		defer body.Close()

		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: res.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&resp)
	})

	if err != nil {
		return nil, err
	}
	return resp.Groups, nil
}

func (c *Client) GetUser(id string) (*metadata.User, error) {
	var user metadata.User
	err := c.withRetry(context.Background(), func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequest("GET", c.serverURL+"/v1/user/"+id, nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}

		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&user)
	})

	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (c *Client) signInode(inode *metadata.Inode) {
	// 1. Resolve encryption key for metadata fields
	// If it's a group file, use Group Encryption Key.
	// Otherwise, use Owner's Public Key.
	var encKey *mlkem.EncapsulationKey768

	if inode.GroupID != "" {
		gdk, err := c.GetGroupPrivateKey(inode.GroupID)
		if err == nil {
			encKey = gdk.EncapsulationKey()
		}
	} else if inode.OwnerID != "" {
		owner, err := c.GetUser(inode.OwnerID)
		if err == nil {
			encKey, _ = crypto.UnmarshalEncapsulationKey(owner.EncKey)
		}
	}

	// Default to self if no other key found (e.g. creating personal file)
	if encKey == nil {
		encKey = c.decKey.EncapsulationKey()
	}

	// 2. Prepare and Encrypt metadata fields
	authSigners := inode.GetAuthorizedSigners()
	if len(authSigners) == 0 && inode.OwnerID != "" {
		authSigners = []string{inode.OwnerID}
	}

	found := false
	for _, s := range authSigners {
		if s == c.userID {
			found = true
			break
		}
	}
	if !found {
		authSigners = append(authSigners, c.userID)
	}
	inode.SetAuthorizedSigners(authSigners)

	// Encrypt SignerID
	inode.EncryptedSignerID, _ = crypto.Seal([]byte(c.userID), encKey, 0)

	// Encrypt AuthorizedSigners
	authBytes, _ := json.Marshal(authSigners)
	inode.EncryptedAuthorizedSigners, _ = crypto.Seal(authBytes, encKey, 0)

	inode.Mode = metadata.SanitizeMode(inode.Mode, inode.Type)
	inode.Version++ // Sign the version that will be stored on the server
	hash := inode.ManifestHash()
	inode.UserSig = c.signKey.Sign(hash)

	// Group Signing (if applicable)
	if inode.GroupID != "" {
		gsk, err := c.GetGroupSignKey(inode.GroupID)
		if err == nil {
			inode.GroupSig = gsk.Sign(hash)
		}
	}
	inode.Version-- // Restore for the server's conflict check
}

func (c *Client) createInode(ctx context.Context, inode metadata.Inode) (*metadata.Inode, error) {
	now := time.Now().UnixNano()
	if inode.MTime == 0 {
		inode.MTime = now
	}
	if inode.CTime == 0 {
		inode.CTime = now
	}
	if inode.NLink == 0 {
		inode.NLink = 1
	}

	// Phase 31: Manifest Signing

	c.signInode(&inode)

	data, err := json.Marshal(inode)

	if err != nil {

		return nil, err

	}

	var created metadata.Inode

	err = c.withRetry(ctx, func() error {

		c.acquireControl()

		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/inode", nil)

		if err != nil {

			return err

		}

		if err := c.authenticateRequest(req); err != nil {

			return err

		}

		if err := c.sealBody(req, data); err != nil {

			return err

		}

		resp, err := c.httpClient.Do(req)

		if err != nil {

			return err

		}

		body, err := c.unsealResponse(resp)

		if err != nil {

			return err

		}

		defer body.Close()

		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {

			b, _ := io.ReadAll(body)

			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}

		}

		if err := json.NewDecoder(body).Decode(&created); err != nil {

			return err

		}

		// Phase 31: Root Anchoring

		if created.ID == metadata.RootID {

			c.rootOwner = created.OwnerID

			c.rootVersion = created.Version

		}

		return nil

	})

	if err != nil {
		return nil, err
	}

	// Phase 31: Verification (Decrypts transient fields)
	if err := c.VerifyInode(&created); err != nil {
		return nil, err
	}

	return &created, nil
}

func (c *Client) updateInode(ctx context.Context, inode metadata.Inode) (*metadata.Inode, error) {
	unlock := c.lockMutation(inode.ID)
	defer unlock()

	var updated metadata.Inode
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		// Phase 31: Manifest Signing
		// We must re-fetch and re-sign if we are retrying a conflict
		if i > 0 {
			latest, err := c.getInode(ctx, inode.ID)
			if err != nil {
				return nil, err
			}
			// Transfer updated fields to latest
			latest.Size = inode.Size
			latest.MTime = inode.MTime
			latest.Mode = inode.Mode
			latest.UID = inode.UID
			latest.GID = inode.GID
			latest.GroupID = inode.GroupID
			latest.InlineData = inode.InlineData
			latest.ChunkManifest = inode.ChunkManifest
			latest.ChunkPages = inode.ChunkPages
			latest.Children = inode.Children
			latest.Lockbox = inode.Lockbox
			latest.SetAuthorizedSigners(inode.GetAuthorizedSigners())
			inode = *latest
		}

		c.signInode(&inode)
		data, err := json.Marshal(inode)
		if err != nil {
			return nil, err
		}

		err = c.withRetry(ctx, func() error {
			c.acquireControl()
			defer c.releaseControl()

			req, err := http.NewRequestWithContext(ctx, "PUT", c.serverURL+"/v1/meta/inode/"+inode.ID, nil)
			if err != nil {
				return err
			}
			if err := c.authenticateRequest(req); err != nil {
				return err
			}
			if err := c.sealBody(req, data); err != nil {
				return err
			}

			resp, err := c.httpClient.Do(req)
			if err != nil {
				return err
			}
			body, err := c.unsealResponse(resp)
			if err != nil {
				return err
			}
			defer body.Close()

			if resp.StatusCode == http.StatusConflict {
				return metadata.ErrConflict
			}

			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(body)
				return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
			}

			if err := json.NewDecoder(body).Decode(&updated); err != nil {
				return err
			}

			// Phase 31: Verification (Decrypts transient fields)
			if err := c.VerifyInode(&updated); err != nil {
				return err
			}

			// Phase 31: Root Anchoring
			if updated.ID == metadata.RootID {
				c.rootOwner = updated.OwnerID
				c.rootVersion = updated.Version
			}
			return nil
		})

		if err == nil {
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

func (c *Client) ApplyBatch(ctx context.Context, cmds []metadata.LogCommand) error {
	data, err := json.Marshal(cmds)
	if err != nil {
		return err
	}

	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/batch", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) PrepareUpdate(inode metadata.Inode) (metadata.LogCommand, error) {
	c.signInode(&inode)
	data, err := json.Marshal(inode)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdUpdateInode, Data: data}, nil
}

func (c *Client) PrepareDelete(id string) (metadata.LogCommand, error) {
	return metadata.LogCommand{Type: metadata.CmdDeleteInode, Data: []byte(id)}, nil
}

func (c *Client) DeleteInode(ctx context.Context, id string) error {
	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "DELETE", c.serverURL+"/v1/meta/inode/"+id, nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			b, _ := io.ReadAll(resp.Body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) getInode(ctx context.Context, id string) (*metadata.Inode, error) {
	var inode metadata.Inode
	err := c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/meta/inode/"+id, nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}

		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		if err := json.NewDecoder(body).Decode(&inode); err != nil {
			return err
		}

		// Phase 31: Root Anchoring
		if id == metadata.RootID {
			if c.rootOwner != "" && inode.OwnerID != c.rootOwner {
				return fmt.Errorf("ROOT COMPROMISE DETECTED: expected owner %s, got %s", c.rootOwner, inode.OwnerID)
			}
			if c.rootVersion > 0 && inode.Version < c.rootVersion {
				return fmt.Errorf("ROOT ROLLBACK DETECTED: expected version >= %d, got %d", c.rootVersion, inode.Version)
			}
			// Update anchor
			c.rootOwner = inode.OwnerID
			c.rootVersion = inode.Version
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Phase 31: Verification
	if err := c.VerifyInode(&inode); err != nil {
		return nil, err
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
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/inodes", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return json.NewDecoder(body).Decode(&inodes)
	})

	if err != nil {
		return nil, err
	}

	// Phase 31: Verification
	for _, inode := range inodes {
		if err := c.VerifyInode(inode); err != nil {
			return nil, err
		}
	}

	return inodes, nil
}

func (c *Client) writeInodeContent(ctx context.Context, id string, iType metadata.InodeType, fileKey []byte, r io.Reader, size int64, encryptedName []byte, mode uint32, groupID string, parentID string, nameHMAC string) error {
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
			wpk, err := c.GetWorldPublicKey()
			if err == nil {
				inode.Lockbox.AddRecipient(metadata.WorldID, wpk, fileKey)
			}
		}
		if groupID != "" && (mode&0060) != 0 {
			group, err := c.GetGroup(groupID)
			if err == nil {
				gpk, _ := crypto.UnmarshalEncapsulationKey(group.EncKey)
				inode.Lockbox.AddRecipient(groupID, gpk, fileKey)
			}
		}
		if encryptedName != nil {
			inode.EncryptedName = encryptedName
		}
	} else if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
		lb := c.createLockbox(fileKey, mode, groupID)

		// Assume not found, create new
		inode = metadata.Inode{
			ID:   id,
			Type: iType,
			Links: map[string]bool{
				parentID + ":" + nameHMAC: true,
			},
			Mode:          mode,
			Size:          uint64(size),
			ChunkManifest: nil,
			Lockbox:       lb,
			EncryptedName: encryptedName,
			OwnerID:       c.userID,
			GroupID:       groupID,
		}
		created, err := c.createInode(ctx, inode)
		if err != nil {
			return err
		}
		inode = *created
	} else {
		return err
	}

	// 1. Inline Path
	if iType == metadata.FileType && size <= metadata.InlineLimit {
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		// Encrypt as single blob using DEM
		ciphertext, err := crypto.EncryptDEM(fileKey, data)
		if err != nil {
			return fmt.Errorf("failed to encrypt inline data: %w", err)
		}
		inode.InlineData = ciphertext
		inode.ChunkManifest = nil
		inode.ChunkPages = nil
		inode.Size = uint64(len(data))
	} else {
		// 2. Chunk Path
		inode.InlineData = nil
		var chunkEntries []metadata.ChunkEntry
		buf := make([]byte, crypto.ChunkSize)

		for {
			n, err := io.ReadFull(r, buf)
			if n > 0 {
				chunkData := buf[:n]
				cid, ct, err := crypto.EncryptChunk(fileKey, chunkData)
				if err != nil {
					return err
				}

				token, err := c.issueToken(id, []string{cid}, "W")
				if err != nil {
					return fmt.Errorf("token issue failed: %w", err)
				}
				nodes, err := c.allocateNodes(ctx)
				if err != nil {
					return fmt.Errorf("allocation failed: %w", err)
				}
				if err := c.uploadChunk(cid, ct, nodes, token); err != nil {
					return err
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
				return err
			}
		}
		inode.ChunkManifest = chunkEntries
		inode.Size = uint64(size)
	}

	// Final update using updateInode (uses version check)
	_, err = c.updateInode(ctx, inode)
	if err == nil {
		c.keyMu.Lock()
		c.keyCache[id] = fileMetadata{
			key:     fileKey,
			groupID: groupID,
			linkTag: parentID + ":" + nameHMAC,
			inlined: inode.InlineData != nil,
		}
		c.keyMu.Unlock()
	}
	return err
}

// WriteFile writes a file. Returns the FileKey used.
func (c *Client) WriteFile(id string, r io.Reader, size int64, mode uint32) ([]byte, error) {
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
		if inode, err := c.GetInode(context.Background(), id); err == nil {
			if key, err := c.UnlockInode(inode); err == nil {
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

	if err := c.writeInodeContent(context.Background(), id, metadata.FileType, fileKey, r, size, nil, mode, groupID, parentID, nameHMAC); err != nil {
		return nil, err
	}
	return fileKey, nil
}

type readAheadResult struct {
	data  []byte
	err   error
	ready chan struct{}
}

type FileReader struct {
	client          *Client
	inode           *metadata.Inode
	fileKey         []byte
	offset          int64
	currentChunkIdx int64
	currentChunk    []byte
	token           string
	mu              sync.Mutex

	readAhead   map[int64]*readAheadResult
	readAheadMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

// NewReader creates a new FileReader for the given inode.
// The caller MUST call Close() on the returned reader to release resources and cancel background prefetching.
func (c *Client) NewReader(id string, fileKey []byte) (*FileReader, error) {
	inode, err := c.getInode(context.Background(), id)
	if err != nil {
		return nil, err
	}

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
			inlined: inode.InlineData != nil,
		}
		c.keyMu.Unlock()
	}

	token, _ := c.issueToken(id, nil, "R")

	ctx, cancel := context.WithCancel(context.Background())
	return &FileReader{
		client:          c,
		inode:           inode,
		fileKey:         fileKey,
		offset:          0,
		currentChunkIdx: -1,
		token:           token,
		readAhead:       make(map[int64]*readAheadResult),
		ctx:             ctx,
		cancel:          cancel,
	}, nil
}

func (r *FileReader) Close() error {
	r.cancel()
	return nil
}

func (r *FileReader) triggerPrefetch(idx int64) {
	if idx < 0 || idx >= int64(len(r.inode.ChunkManifest)) {
		return
	}

	r.readAheadMu.Lock()
	if _, exists := r.readAhead[idx]; exists {
		r.readAheadMu.Unlock()
		return
	}
	res := &readAheadResult{ready: make(chan struct{})}
	r.readAhead[idx] = res
	r.readAheadMu.Unlock()

	go func() {
		chunkEntry := r.inode.ChunkManifest[idx]
		ct, err := r.client.downloadChunk(r.ctx, chunkEntry.ID, chunkEntry.URLs, r.token)
		var pt []byte
		if err == nil {
			pt, err = crypto.DecryptChunk(r.fileKey, ct)
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
		var err error
		if chunkIdx == r.currentChunkIdx && r.currentChunk != nil {
			pt = r.currentChunk
		} else if r.inode.InlineData != nil {
			// Handle Inlined File
			pt, err = crypto.DecryptDEM(r.fileKey, r.inode.InlineData)
			if err != nil {
				return totalRead, fmt.Errorf("failed to decrypt inline data: %w", err)
			}
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
					return totalRead, res.err
				}
				pt = res.data
			} else {
				if chunkIdx >= int64(len(r.inode.ChunkManifest)) {
					break
				}
				chunkEntry := r.inode.ChunkManifest[chunkIdx]

				// Unlock during network I/O
				r.mu.Unlock()
				ct, err := r.client.downloadChunk(context.Background(), chunkEntry.ID, chunkEntry.URLs, r.token)
				r.mu.Lock()

				if err != nil {
					return totalRead, err
				}
				pt, err = crypto.DecryptChunk(r.fileKey, ct)
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

// ReadFile returns a reader for the specified file ID.
// If fileKey is nil, it attempts to unlock it using the client's identity.
func (c *Client) ReadFile(id string, fileKey []byte) (io.ReadCloser, error) {
	r, err := c.NewReader(id, fileKey)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(r), nil
}

func (c *Client) OpenBlobRead(id string) (io.ReadCloser, error) {
	// 1. Try treating id as a direct Inode ID (fast path)
	rc, err := c.ReadFile(id, nil)
	if err == nil {
		return rc, nil
	}

	// 2. Try resolving as a path if direct read failed
	// Only try if it looks like a path or the previous error wasn't "not found"
	var inode *metadata.Inode
	var key []byte
	resolveErr := errors.New("resolution skipped")

	if strings.Contains(id, "/") {
		inode, key, resolveErr = c.ResolvePath(id)
		if resolveErr != nil {
			return nil, resolveErr
		}
		rc, err = c.ReadFile(inode.ID, key)
		if err == nil {
			return rc, nil
		}
	}

	// 3. Handle Placeholder (Leased) Files
	// If we hold the lease, and the file is empty/new, return empty reader.
	if errors.Is(err, crypto.ErrRecipientNotFound) {
		// Use the inode we resolved, or fetch if we didn't resolve yet
		if inode == nil {
			inode, _ = c.getInode(context.Background(), id)
		}

		if inode != nil {
			c.sessionMu.RLock()
			token := c.sessionToken
			c.sessionMu.RUnlock()
			// Strictly check if it's a new placeholder: Owned by us, Version 1, and Empty.
			if inode.LeaseOwner == token && inode.Version == 1 && inode.Size == 0 {
				return io.NopCloser(bytes.NewReader(nil)), nil
			}
		}
	}

	return nil, err
}

func (c *Client) OpenBlobWrite(id string) (io.WriteCloser, error) {
	ctx := context.Background()
	// Acquire lease first to prevent concurrent writers.
	// Note: We lease the input `id` (which might be a path) to lock the name.
	if err := c.AcquireLeases(ctx, []string{id}, 2*time.Minute, nil); err != nil {
		return nil, err
	}

	c.keyMu.RLock()
	meta, ok := c.keyCache[id]
	c.keyMu.RUnlock()

	var fileKey []byte
	var groupID string
	var parentID string
	var parentKey []byte
	var name string
	var nameHMAC string
	var inode *metadata.Inode

	if ok {
		fileKey = meta.key
		groupID = meta.groupID
		parts := strings.SplitN(meta.linkTag, ":", 2)
		if len(parts) == 2 {
			parentID = parts[0]
			nameHMAC = parts[1]
		}
		inode, _ = c.getInode(ctx, id)
	} else {
		// 1. Try getInode directly (Treating id as InodeID)
		inode, _ = c.getInode(ctx, id)
		if inode != nil {
			fileKey, _ = c.UnlockInode(inode)
		}

		if fileKey == nil {
			// 2. Try to resolve as Path
			dir, fileName := filepath.Split(id)
			name = fileName
			pInode, pKey, err := c.ResolvePath(dir)
			if err != nil {
				return nil, err
			}

			mac := hmac.New(sha256.New, pKey)
			mac.Write([]byte(name))
			nameHMAC = hex.EncodeToString(mac.Sum(nil))
			parentID = pInode.ID
			parentKey = pKey
			groupID = pInode.GroupID

			if childID, exists := pInode.Children[nameHMAC]; exists {
				inode, _ = c.getInode(ctx, childID)
				if inode != nil {
					fileKey, _ = c.UnlockInode(inode)
				}
			}
		}
	}

	if fileKey == nil {
		fileKey = make([]byte, 32)
		rand.Read(fileKey)
	}

	isNew := false
	if inode == nil {
		if parentID == "" {
			return nil, fmt.Errorf("cannot create file: parent directory not found or path invalid")
		}
		// Generate new UUID for the file
		uidBytes := make([]byte, 16)
		rand.Read(uidBytes)
		newID := hex.EncodeToString(uidBytes)

		inode = &metadata.Inode{
			ID:      newID,
			Type:    metadata.FileType,
			Mode:    0600,
			OwnerID: c.userID,
			GroupID: groupID,
			// We set links here, but we MUST also update the parent later.
			Links:   map[string]bool{parentID + ":" + nameHMAC: true},
			Lockbox: c.createLockbox(fileKey, 0600, groupID),
		}
		isNew = true
	}

	return &FileWriter{
		client:    c,
		ctx:       ctx,
		inode:     *inode,
		fileKey:   fileKey,
		parentID:  parentID,
		parentKey: parentKey,
		name:      name,
		nameHMAC:  nameHMAC,
		buf:       make([]byte, 0, crypto.ChunkSize),
		isNew:     isNew,
	}, nil
}

type FileWriter struct {
	client    *Client
	ctx       context.Context
	inode     metadata.Inode
	fileKey   []byte
	parentID  string
	parentKey []byte
	name      string
	nameHMAC  string
	buf       []byte
	manifest  []metadata.ChunkEntry
	written   int64
	closed    bool
	isNew     bool
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
	cid, ct, err := crypto.EncryptChunk(w.fileKey, w.buf)
	if err != nil {
		return err
	}
	token, err := w.client.issueToken(w.inode.ID, []string{cid}, "W")
	if err != nil {
		return err
	}
	nodes, err := w.client.allocateNodes(w.ctx)
	if err != nil {
		return err
	}
	if err := w.client.uploadChunk(cid, ct, nodes, token); err != nil {
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

func (w *FileWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	// Handle Inlining for small files
	if len(w.manifest) == 0 && len(w.buf) <= metadata.InlineLimit {
		ciphertext, err := crypto.EncryptDEM(w.fileKey, w.buf)
		if err != nil {
			return err
		}
		w.inode.InlineData = ciphertext
		w.inode.ChunkManifest = nil
		w.inode.Size = uint64(len(w.buf))
	} else {
		if err := w.flushChunk(); err != nil {
			return err
		}
		w.inode.InlineData = nil
		w.inode.ChunkManifest = w.manifest
		w.inode.Size = uint64(w.written)
	}

	// Final Metadata Update
	var err error
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
		parent, gerr := w.client.getInode(w.ctx, w.parentID)
		if gerr != nil {
			return fmt.Errorf("failed to get parent for link: %w", gerr)
		}
		if parent.Children == nil {
			parent.Children = make(map[string]string)
		}
		parent.Children[w.nameHMAC] = w.inode.ID
		_, err = w.client.updateInode(w.ctx, *parent)
	} else {
		_, err = w.client.updateInode(w.ctx, w.inode)
	}

	if releaseErr := w.client.ReleaseLeases(w.ctx, []string{w.inode.ID}); releaseErr != nil {
		if err == nil {
			err = fmt.Errorf("failed to release lease: %w", releaseErr)
		}
	}

	if err == nil {
		w.client.keyMu.Lock()
		w.client.keyCache[w.inode.ID] = fileMetadata{
			key:     w.fileKey,
			groupID: w.inode.GroupID,
			linkTag: w.parentID + ":" + w.nameHMAC,
			inlined: w.inode.InlineData != nil,
		}
		w.client.keyMu.Unlock()

		// Cache the path if we know it
		if w.name != "" && w.parentID != "" {
			// We don't have the full path here easily unless we passed it or reconstructing it.
			// But we updated keyCache, which is good enough for ID-based access.
			// Path cache population is tricky without full path.
		}
	}
	return err
}

func (c *Client) FetchChunk(ctx context.Context, id string, key []byte, chunkIdx int64) ([]byte, error) {
	inode, err := c.GetInode(ctx, id)
	if err != nil {
		return nil, err
	}
	// Handle inline data
	if inode.InlineData != nil {
		if chunkIdx == 0 {
			return crypto.DecryptDEM(key, inode.InlineData)
		}
		return nil, io.EOF
	}

	if chunkIdx < 0 || chunkIdx >= int64(len(inode.ChunkManifest)) {
		return nil, io.EOF
	}
	entry := inode.ChunkManifest[chunkIdx]
	token, err := c.issueToken(id, nil, "R")
	if err != nil {
		return nil, err
	}
	ct, err := c.downloadChunk(ctx, entry.ID, entry.URLs, token)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptChunk(key, ct)
}

func (c *Client) SyncFile(id string, r io.ReaderAt, size int64, dirtyChunks map[int64]bool) (*metadata.Inode, error) {
	ctx := context.Background()

	// 1. Get current inode state
	inode, err := c.GetInode(ctx, id)
	if err != nil {
		return nil, err
	}

	key, err := c.UnlockInode(inode)
	if err != nil {
		return nil, err
	}

	// 2. Handle Small File Inlining (Optimized Path)
	if size <= metadata.InlineLimit {
		buf := make([]byte, size)
		if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
			return nil, err
		}
		ciphertext, err := crypto.EncryptDEM(key, buf)
		if err != nil {
			return nil, err
		}
		inode.InlineData = ciphertext
		inode.ChunkManifest = nil
		inode.ChunkPages = nil
		inode.Size = uint64(size)
		return c.updateInode(ctx, *inode)
	}

	// 3. Handle Chunked File (Differential Update)
	inode.InlineData = nil
	numChunks := (size + crypto.ChunkSize - 1) / crypto.ChunkSize
	newManifest := make([]metadata.ChunkEntry, numChunks)
	buf := make([]byte, crypto.ChunkSize)

	for i := int64(0); i < numChunks; i++ {
		// Determine if we need to upload this chunk
		needUpload := false
		if dirtyChunks[i] {
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

			// Clear buffer for safety (avoid leaking previous chunk data in partial reads)
			for k := range buf {
				buf[k] = 0
			}

			n, err := r.ReadAt(buf[:chunkSize], offset)
			if err != nil && err != io.EOF {
				return nil, err
			}
			chunkData := buf[:n]

			// Encrypt
			cid, ct, err := crypto.EncryptChunk(key, chunkData)
			if err != nil {
				return nil, err
			}

			// Upload
			token, err := c.issueToken(id, []string{cid}, "W")
			if err != nil {
				return nil, err
			}
			nodes, err := c.allocateNodes(ctx)
			if err != nil {
				return nil, err
			}
			if err := c.uploadChunk(cid, ct, nodes, token); err != nil {
				return nil, err
			}

			var nodeIDs []string
			for _, node := range nodes {
				nodeIDs = append(nodeIDs, node.ID)
			}
			newManifest[i] = metadata.ChunkEntry{ID: cid, Nodes: nodeIDs}
		}
	}

	inode.ChunkManifest = newManifest
	inode.Size = uint64(size)
	return c.updateInode(ctx, *inode)
}

func (c *Client) ReadDataFile(name string, data any) error {
	// Map name to a full path if necessary, here we assume names are IDs or paths
	rc, err := c.OpenBlobRead(name)
	if err != nil {
		return err
	}
	defer rc.Close()
	err = json.NewDecoder(rc).Decode(data)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (c *Client) SaveDataFile(name string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	wc, err := c.OpenBlobWrite(name)
	if err != nil {
		return err
	}
	if _, err := wc.Write(b); err != nil {
		wc.Close()
		return err
	}
	return wc.Close()
}

func (c *Client) OpenForUpdate(name string, data any) (func(bool), error) {
	return c.OpenManyForUpdate([]string{name}, []any{data})
}

func (c *Client) OpenManyForUpdate(names []string, data []any) (func(bool), error) {
	if len(names) != len(data) {
		return nil, fmt.Errorf("names and data length mismatch")
	}

	ctx := context.Background()

	// 1. Resolve all paths to InodeIDs
	ids := make([]string, len(names))
	for i, name := range names {
		inode, _, err := c.ResolvePath(name)
		if err != nil {
			ids[i] = name // Fallback to path if not found (e.g. for creation)
		} else {
			ids[i] = inode.ID
		}
	}

	// Pre-create lockbox for potential new files
	fileKey := make([]byte, 32)
	rand.Read(fileKey)
	lb := c.createLockbox(fileKey, 0600, "")

	// 2. Acquire leases for all files
	if err := c.AcquireLeases(ctx, ids, 2*time.Minute, lb); err != nil {
		return nil, err
	}

	// 3. Read all files
	for i, name := range names {
		if err := c.ReadDataFile(name, data[i]); err != nil {
			c.ReleaseLeases(ctx, ids)
			return nil, err
		}
	}

	// 4. Return commit callback
	return func(commit bool) {
		if commit {
			for i, name := range names {
				if err := c.SaveDataFile(name, data[i]); err != nil {
					log.Printf("Failed to save %s during transactional update: %v", name, err)
				}
			}
		}
		c.ReleaseLeases(ctx, ids)
	}, nil
}

// GetInode fetches the inode metadata.
func (c *Client) GetInode(ctx context.Context, id string) (*metadata.Inode, error) {
	return c.getInode(ctx, id)
}

// GetInodes fetches metadata for multiple inodes in a single batch call.
func (c *Client) GetInodes(ctx context.Context, ids []string) ([]*metadata.Inode, error) {
	return c.getInodes(ctx, ids)
}

// VerifyInode verifies the manifest signatures and authorized signers.
func (c *Client) VerifyInode(inode *metadata.Inode) error {
	// 1. Decrypt Signer fields first
	var decKey *mlkem.DecapsulationKey768
	if inode.GroupID != "" {
		decKey, _ = c.GetGroupPrivateKey(inode.GroupID)
	} else if inode.OwnerID == c.userID {
		decKey = c.decKey
	}

	if decKey == nil && len(inode.EncryptedSignerID) > 0 {
		return fmt.Errorf("no decryption key for inode %s signer metadata", inode.ID)
	}

	if len(inode.EncryptedSignerID) > 0 {
		signerBytes, err := crypto.Unseal(inode.EncryptedSignerID, decKey)
		if err == nil {
			inode.SetSignerID(string(signerBytes))
		}
	}
	if len(inode.EncryptedAuthorizedSigners) > 0 {
		authBytes, err := crypto.Unseal(inode.EncryptedAuthorizedSigners, decKey)
		if err == nil {
			var auth []string
			if err := json.Unmarshal(authBytes, &auth); err == nil {
				inode.SetAuthorizedSigners(auth)
			}
		}
	}

	signerID := inode.GetSignerID()
	authSigners := inode.GetAuthorizedSigners()

	if signerID == "" {
		// If there are authorized signers, we expect a signature.
		if len(authSigners) > 0 {
			return fmt.Errorf("missing manifest signature for inode %s", inode.ID)
		}
		return nil
	}

	// 2. Verify Signatures
	hash := inode.ManifestHash()
	user, err := c.GetUser(signerID)
	if err != nil {
		return fmt.Errorf("failed to fetch signer %s: %w", signerID, err)
	}
	if !crypto.VerifySignature(user.SignKey, hash, inode.UserSig) {
		return fmt.Errorf("invalid manifest signature by %s", signerID)
	}

	groupValid := false
	if inode.GroupID != "" && len(inode.GroupSig) > 0 {
		group, err := c.GetGroup(inode.GroupID)
		if err == nil {
			if crypto.VerifySignature(group.SignKey, hash, inode.GroupSig) {
				groupValid = true
			}
		}
	}

	// 3. Check Authorization
	// Either the Signer must be in AuthorizedSigners OR we have a valid Group Signature from the owning group
	authorized := groupValid

	if !authorized {
		for _, s := range authSigners {
			if s == signerID {
				authorized = true
				break
			}
		}
		// Owner is implicitly authorized if no AuthorizedSigners listed
		if !authorized && len(authSigners) == 0 && signerID == inode.OwnerID {
			authorized = true
		}
	}

	if !authorized {
		return fmt.Errorf("signer %s is not authorized for inode %s (no valid group sig or ACL match)", signerID, inode.ID)
	}

	return nil
}

// UnlockInode attempts to decrypt the file key for the inode using the client's identity.
func (c *Client) UnlockInode(inode *metadata.Inode) ([]byte, error) {
	// Phase 31: Verification
	if err := c.VerifyInode(inode); err != nil {
		return nil, fmt.Errorf("integrity check failed: %w", err)
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
			inlined: inode.InlineData != nil,
		}
		c.keyMu.Unlock()
		return key, nil
	}
	lastErr = err

	// 2. Try group access if personal failed
	if inode.GroupID != "" {
		if _, exists := inode.Lockbox[inode.GroupID]; exists {
			gk, gerr := c.GetGroupPrivateKey(inode.GroupID)
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
		wk, err := c.GetWorldPrivateKey()
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
func (c *Client) GetGroupPrivateKey(groupID string) (*mlkem.DecapsulationKey768, error) {
	c.keyMu.RLock()
	gk, ok := c.groupKeys[groupID]
	c.keyMu.RUnlock()
	if ok {
		return gk, nil
	}

	req, err := http.NewRequest("GET", c.serverURL+"/v1/group/"+groupID+"/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch group private key: %d", resp.StatusCode)
	}

	var entry crypto.LockboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
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
func (c *Client) GetGroupSignKey(groupID string) (*crypto.IdentityKey, error) {
	c.keyMu.RLock()
	gk, ok := c.groupSignKeys[groupID]
	c.keyMu.RUnlock()
	if ok {
		return gk, nil
	}

	req, err := http.NewRequest("GET", c.serverURL+"/v1/group/"+groupID+"/sign/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch group signing key: %d", resp.StatusCode)
	}

	var entry crypto.LockboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
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
func (c *Client) GetWorldPublicKey() (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	wp := c.worldPublic
	c.keyMu.RUnlock()
	if wp != nil {
		return wp, nil
	}

	resp, err := c.httpClient.Get(c.serverURL + "/v1/meta/key/world")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch world pub key: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
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
func (c *Client) GetWorldPrivateKey() (*mlkem.DecapsulationKey768, error) {
	c.keyMu.RLock()
	wp := c.worldPrivate
	c.keyMu.RUnlock()
	if wp != nil {
		return wp, nil
	}

	req, err := http.NewRequest("GET", c.serverURL+"/v1/meta/key/world/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch world private key: %d", resp.StatusCode)
	}

	var data struct {
		KEM string `json:"kem"`
		DEM string `json:"dem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	kemCT, _ := base64.StdEncoding.DecodeString(data.KEM)
	demCT, _ := base64.StdEncoding.DecodeString(data.DEM)

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
func (c *Client) GetGroup(id string) (*metadata.Group, error) {
	req, err := http.NewRequest("GET", c.serverURL+"/v1/group/"+id, nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get group failed: %d", resp.StatusCode)
	}

	var group metadata.Group
	if err := json.NewDecoder(resp.Body).Decode(&group); err != nil {
		return nil, err
	}

	if err := c.VerifyGroup(&group); err != nil {
		return nil, fmt.Errorf("group integrity check failed: %w", err)
	}

	return &group, nil
}

// VerifyGroup verifies the group metadata signature and authorized signer.
func (c *Client) VerifyGroup(group *metadata.Group) error {
	if group.Signature == nil {
		return fmt.Errorf("missing group signature")
	}

	hash := group.Hash()
	if group.SignerID == "" {
		return fmt.Errorf("missing signer ID for group %s (server-signed metadata prohibited)", group.ID)
	}

	// User-signed
	user, err := c.GetUser(group.SignerID)
	if err != nil {
		return fmt.Errorf("failed to fetch group signer %s: %w", group.SignerID, err)
	}
	if !crypto.VerifySignature(user.SignKey, hash, group.Signature) {
		return fmt.Errorf("invalid manifest signature by %s", group.SignerID)
	}

	return nil
}

// GetGroupName retrieves and decrypts the human-readable name of a group.
func (c *Client) GetGroupName(group *metadata.Group) (string, error) {
	gk, err := c.GetGroupPrivateKey(group.ID)
	if err != nil {
		return "", err
	}
	nameBytes, err := crypto.Unseal(group.EncryptedName, gk)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt group name: %w", err)
	}
	return string(nameBytes), nil
}

// DecryptGroupName decrypts a group name from a list entry using cached or provided keys.
func (c *Client) DecryptGroupName(entry metadata.GroupListEntry) (string, error) {
	// 1. Try Cache
	c.keyMu.RLock()
	gdk, ok := c.groupKeys[entry.ID]
	c.keyMu.RUnlock()

	if !ok {
		// 2. Try to unlock group key from entry's lockbox
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
				if ogdk, gerr := c.GetGroupPrivateKey(entry.OwnerID); gerr == nil {
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

	nameBytes, err := crypto.Unseal(entry.EncryptedName, gdk)
	if err != nil {
		return "", err
	}
	return string(nameBytes), nil
}

// GetGroupRegistryKey retrieves and decrypts the group registry key.
func (c *Client) getGroupRegistryKey(group *metadata.Group) ([]byte, error) {
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
			gk, gerr := c.GetGroupPrivateKey(group.OwnerID)
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
func (c *Client) CreateGroup(name string) (*metadata.Group, error) {
	return c.createGroupInternal(name, false)
}

// CreateSystemGroup creates a new system group (Admin only).
func (c *Client) CreateSystemGroup(name string) (*metadata.Group, error) {
	return c.createGroupInternal(name, true)
}

func (c *Client) createGroupInternal(name string, isSystem bool) (*metadata.Group, error) {
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

	// Encrypt Group Name using Group Key (Sealed)
	encName, err := crypto.Seal([]byte(name), dk.EncapsulationKey(), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt group name: %w", err)
	}

	// 3. Generate Registry Key (Symmetric)
	rk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rk); err != nil {
		return nil, err
	}

	// 3.1 Fetch a GID from the server to ensure valid signature
	var gid uint32
	gidUrl := c.serverURL + "/v1/group/gid/allocate"
	hReq, err := http.NewRequest("GET", gidUrl, nil)
	if err == nil {
		if err := c.authenticateRequest(hReq); err == nil {
			gidResp, err := c.httpClient.Do(hReq)
			if err == nil && gidResp.StatusCode == http.StatusOK {
				var res struct {
					GID uint32 `json:"gid"`
				}
				if err := json.NewDecoder(gidResp.Body).Decode(&res); err == nil {
					gid = res.GID
				}
				gidResp.Body.Close()
			}
		}
	}

	rlb := crypto.NewLockbox()
	// Encrypt Registry Key for the owner
	if err := rlb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), rk); err != nil {
		return nil, err
	}

	// Initialize Registry with the owner (if email is known)
	// We might not know our own email from the config directly, but we can assume it's passed or available.
	// For now, let's assume we can add our own entry if we have it.
	// Actually, User struct has no email. The client might have it in memory or we can skip for now.
	// User said: "actual email of the group members to be visible by the group owner".
	// During onboarding we might have the email.

	// Let's assume for now we just store the UserID in the registry if email is missing.
	// Or we can add a way to pass email to CreateGroup.
	// But let's check how we get email.

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
		EncryptedName:     encName,
		GID:               gid,
		OwnerID:           c.userID,
		Members:           map[string]bool{c.userID: true},
		EncKey:            pk,
		SignKey:           spk,
		Lockbox:           lb,
		RegistryLockbox:   rlb,
		EncryptedRegistry: encRegistry,
		IsSystem:          isSystem,
		Version:           1,
	}

	// Client-side Signing
	c.signGroup(group, false)

	data, _ := json.Marshal(group)
	url := c.serverURL + "/v1/group/"
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}
	if err := c.sealBody(req, data); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := c.unsealResponse(resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		return nil, fmt.Errorf("create group failed: %d %s", resp.StatusCode, string(b))
	}

	var created metadata.Group
	if err := json.NewDecoder(body).Decode(&created); err != nil {
		return nil, err
	}

	// Verify the response integrity
	if err := c.VerifyGroup(&created); err != nil {
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
		user, err := c.GetUser(userID)
		if err != nil {
			return err
		}
		userEK, err = crypto.UnmarshalEncapsulationKey(user.EncKey)
		if err != nil {
			return err
		}
	}

	_, err := c.updateGroup(ctx, groupID, func(group *metadata.Group) error {
		// 1. Update Group Private Keys (Lockbox)
		gk, err := c.GetGroupPrivateKey(groupID)
		if err != nil {
			return err
		}
		priv := crypto.MarshalDecapsulationKey(gk)

		gsk, err := c.GetGroupSignKey(groupID)
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
		rk, err := c.getGroupRegistryKey(group)
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
	_, err := c.updateGroup(ctx, groupID, func(group *metadata.Group) error {
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
		rk, err := c.getGroupRegistryKey(group)
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
func (c *Client) SetAttr(path string, attr metadata.SetAttrRequest) error {
	inode, key, err := c.ResolvePath(path)
	if err != nil {
		return err
	}
	return c.SetAttrByID(inode, key, attr)
}

// SetAttrByID updates the attributes of an inode by ID.
// SetAttrByID updates the attributes of an inode by ID.
func (c *Client) SetAttrByID(inode *metadata.Inode, key []byte, attr metadata.SetAttrRequest) error {
	// 1. Update local fields
	if attr.Mode != nil {
		inode.Mode = *attr.Mode
	}
	if attr.UID != nil {
		inode.UID = *attr.UID
	}
	if attr.GID != nil {
		inode.GID = *attr.GID
	}
	if attr.GroupID != nil {
		inode.GroupID = *attr.GroupID
	}
	if attr.Size != nil {
		inode.Size = *attr.Size
	}
	if attr.MTime != nil {
		inode.MTime = *attr.MTime
	}

	// 2. Handle Lockbox updates (World & Group)
	worldRead := (inode.Mode & 0004) != 0
	groupRW := (inode.Mode & 0060) != 0

	// 2.1 World Access
	_, worldInLockbox := inode.Lockbox[metadata.WorldID]
	if worldRead && !worldInLockbox {
		wpk, err := c.GetWorldPublicKey()
		if err == nil {
			inode.Lockbox.AddRecipient(metadata.WorldID, wpk, key)
		}
	} else if !worldRead && worldInLockbox {
		delete(inode.Lockbox, metadata.WorldID)
	}

	// 2.2 Group Access
	if inode.GroupID != "" {
		_, groupInLockbox := inode.Lockbox[inode.GroupID]
		if groupRW && !groupInLockbox {
			group, err := c.GetGroup(inode.GroupID)
			if err == nil {
				gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
				if err == nil {
					inode.Lockbox.AddRecipient(inode.GroupID, gpk, key)
				}
			}
		} else if !groupRW && groupInLockbox {
			delete(inode.Lockbox, inode.GroupID)
		}
	}

	// 3. Final Metadata Update (Signs everything)
	updated, err := c.updateInode(context.Background(), *inode)
	if err == nil {
		*inode = *updated
	}
	return err
}

// Remove deletes an inode at the given path.
func (c *Client) Remove(path string) error {
	return c.RemoveEntry(path)
}

// PushKeySync uploads an encrypted configuration blob to the server.
// Requires a valid session and mandatory Layer 7 E2EE (Sealing).
func (c *Client) PushKeySync(blob *metadata.KeySyncBlob) error {
	data, _ := json.Marshal(blob)
	req, err := http.NewRequest("POST", c.serverURL+"/v1/user/keysync", nil)
	if err != nil {
		return err
	}

	if err := c.authenticateRequest(req); err != nil {
		return err
	}

	if err := c.sealBody(req, data); err != nil {
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
func (c *Client) PullKeySync(jwt string) (*metadata.KeySyncBlob, error) {
	req, err := http.NewRequest("GET", c.serverURL+"/v1/user/keysync", nil)
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

func (c *Client) acquireControl() {
	c.controlSem <- struct{}{}
}

func (c *Client) releaseControl() {
	<-c.controlSem
}

func (c *Client) acquireData() {
	c.dataSem <- struct{}{}
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
	msg := strings.ToLower(err.Error())
	// Network errors
	if strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "eof") {
		return true
	}
	// API errors
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusServiceUnavailable ||
			apiErr.StatusCode == http.StatusTooManyRequests ||
			apiErr.StatusCode == http.StatusInternalServerError {
			return true
		}
	}
	return false
}

func (c *Client) withConflictRetry(ctx context.Context, op func() error) error {
	backoff := 50 * time.Millisecond
	maxBackoff := 5 * time.Second

	for i := 0; i < 20; i++ {
		err := op()
		if err == nil {
			return nil
		}
		var apiErr *APIError
		isConflict := (errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict) || errors.Is(err, metadata.ErrConflict)

		if isConflict {
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

func (c *Client) GetClusterStats() (*metadata.ClusterStats, error) {
	var stats metadata.ClusterStats
	err := c.withRetry(context.Background(), func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequest("GET", c.serverURL+"/v1/cluster/stats", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(resp.Body).Decode(&stats)
	})

	if err != nil {
		return nil, err
	}
	return &stats, nil
}

func (c *Client) AcquireLeases(ctx context.Context, ids []string, duration time.Duration, lb crypto.Lockbox) error {
	req := metadata.LeaseRequest{
		InodeIDs: ids,
		Duration: int64(duration),
		Lockbox:  lb,
	}
	data, _ := json.Marshal(req)

	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/lease/acquire", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(hReq); err != nil {
			return err
		}
		if err := c.sealBody(hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) ReleaseLeases(ctx context.Context, ids []string) error {
	req := metadata.LeaseRequest{
		InodeIDs: ids,
	}
	data, _ := json.Marshal(req)

	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/meta/lease/release", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(hReq); err != nil {
			return err
		}
		if err := c.sealBody(hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) AdminListUsers(ctx context.Context) ([]metadata.User, error) {
	var users []metadata.User
	err := c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/users", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-DistFS-Sealed", "true") // Required
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&users)
	})
	return users, err
}

func (c *Client) AdminListGroups(ctx context.Context) ([]metadata.Group, error) {
	var groups []metadata.Group
	err := c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/groups", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-DistFS-Sealed", "true")
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&groups)
	})
	return groups, err
}

func (c *Client) AdminListLeases(ctx context.Context) ([]metadata.LeaseInfo, error) {
	var leases []metadata.LeaseInfo
	err := c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/leases", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-DistFS-Sealed", "true")
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&leases)
	})
	return leases, err
}

func (c *Client) AdminListNodes(ctx context.Context) ([]metadata.Node, error) {
	var nodes []metadata.Node
	err := c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/nodes", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-DistFS-Sealed", "true") // Required
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&nodes)
	})
	return nodes, err
}

func (c *Client) AdminClusterStatus(ctx context.Context) (map[string]interface{}, error) {
	var status map[string]interface{}
	err := c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/admin/status", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-DistFS-Sealed", "true") // Required
		if err := c.authenticateRequest(req); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&status)
	})
	return status, err
}

func (c *Client) AdminLookup(ctx context.Context, email, reason string) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"email":  email,
		"reason": reason,
	})
	var result struct {
		ID string `json:"id"`
	}
	err := c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/lookup", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&result)
	})
	return result.ID, err
}

func (c *Client) AdminPromote(ctx context.Context, userID string) error {
	payload, _ := json.Marshal(map[string]string{"user_id": userID})
	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/promote", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) AdminJoinNode(ctx context.Context, address string) error {
	payload, _ := json.Marshal(map[string]string{"address": address})
	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/join", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) AdminRemoveNode(ctx context.Context, id string) error {
	payload, _ := json.Marshal(map[string]string{"id": id})
	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/remove", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, payload); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error {
	data, _ := json.Marshal(req)
	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/quota/user", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(hReq); err != nil {
			return err
		}
		if err := c.sealBody(hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error {
	data, _ := json.Marshal(req)
	return c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		hReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/admin/quota/group", nil)
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(hReq); err != nil {
			return err
		}
		if err := c.sealBody(hReq, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(hReq)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}
		return nil
	})
}

func (c *Client) AdminChown(ctx context.Context, inodeID string, req metadata.AdminChownRequest) error {
	inode, err := c.getInode(ctx, inodeID)
	if err != nil {
		return err
	}

	// Try to unlock so we can re-key for the new owner/group
	key, unlockErr := c.UnlockInode(inode)

	if req.OwnerID != nil {
		inode.OwnerID = *req.OwnerID
		// Reset authorized signers to just the new owner to ensure clean hand-off
		inode.SetAuthorizedSigners([]string{inode.OwnerID})

		// If we have the key, add the new owner to the lockbox
		if unlockErr == nil {
			newUser, err := c.GetUser(inode.OwnerID)
			if err == nil {
				pubKey, err := crypto.UnmarshalEncapsulationKey(newUser.EncKey)
				if err == nil {
					inode.Lockbox.AddRecipient(inode.OwnerID, pubKey, key)
				}
			}
		}
	}
	if req.GroupID != nil {
		inode.GroupID = *req.GroupID
		// If we have the key, add the new group to the lockbox
		if unlockErr == nil && inode.GroupID != "" {
			group, err := c.GetGroup(inode.GroupID)
			if err == nil {
				gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
				if err == nil {
					inode.Lockbox.AddRecipient(inode.GroupID, gpk, key)
				}
			}
		}
	}
	if req.UID != nil {
		inode.UID = *req.UID
	}
	if req.GID != nil {
		inode.GID = *req.GID
	}

	_, err = c.updateInode(ctx, *inode)
	return err
}

func (c *Client) AdminChmod(ctx context.Context, inodeID string, mode uint32) error {
	inode, err := c.getInode(ctx, inodeID)
	if err != nil {
		return err
	}

	// 1. Try to unlock so we can re-key for group/world if bits changed
	key, unlockErr := c.UnlockInode(inode)

	inode.Mode = mode

	// 2. Handle Lockbox updates (World & Group)
	if unlockErr == nil {
		worldRead := (inode.Mode & 0004) != 0
		groupRW := (inode.Mode & 0060) != 0

		// 2.1 World Access
		_, worldInLockbox := inode.Lockbox[metadata.WorldID]
		if worldRead && !worldInLockbox {
			wpk, err := c.GetWorldPublicKey()
			if err == nil {
				inode.Lockbox.AddRecipient(metadata.WorldID, wpk, key)
			}
		} else if !worldRead && worldInLockbox {
			delete(inode.Lockbox, metadata.WorldID)
		}

		// 2.2 Group Access
		if inode.GroupID != "" {
			_, groupInLockbox := inode.Lockbox[inode.GroupID]
			if groupRW && !groupInLockbox {
				group, err := c.GetGroup(inode.GroupID)
				if err == nil {
					gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
					if err == nil {
						inode.Lockbox.AddRecipient(inode.GroupID, gpk, key)
					}
				}
			} else if !groupRW && groupInLockbox {
				delete(inode.Lockbox, inode.GroupID)
			}
		}
	}

	_, err = c.updateInode(ctx, *inode)
	return err
}

func (c *Client) signGroup(group *metadata.Group, isUpdate bool) {
	group.SignerID = c.userID
	if isUpdate {
		group.Version++
	}
	hash := group.Hash()
	group.Signature = c.signKey.Sign(hash)
	if isUpdate {
		group.Version--
	}
}

func (c *Client) updateGroupInternal(ctx context.Context, group *metadata.Group) (*metadata.Group, error) {
	var updated metadata.Group
	c.signGroup(group, true)
	data, err := json.Marshal(group)
	if err != nil {
		return nil, err
	}

	err = c.withRetry(ctx, func() error {
		c.acquireControl()
		defer c.releaseControl()

		req, err := http.NewRequestWithContext(ctx, "PUT", c.serverURL+"/v1/group/"+group.ID, bytes.NewReader(data))
		if err != nil {
			return err
		}
		if err := c.authenticateRequest(req); err != nil {
			return err
		}
		if err := c.sealBody(req, data); err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := c.unsealResponse(resp)
		if err != nil {
			return err
		}
		defer body.Close()

		if resp.StatusCode == http.StatusConflict {
			return metadata.ErrConflict
		}

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&updated)
	})

	if err == nil {
		return &updated, nil
	}
	return nil, err
}

// updateGroup handles optimistic concurrency and client-side serialization for group updates.
func (c *Client) updateGroup(ctx context.Context, id string, modifier func(*metadata.Group) error) (*metadata.Group, error) {
	unlock := c.lockMutation(id)
	defer unlock()

	var updated *metadata.Group
	err := c.withConflictRetry(ctx, func() error {
		latest, err := c.GetGroup(id)
		if err != nil {
			return err
		}

		if err := modifier(latest); err != nil {
			return err
		}

		updated, err = c.updateGroupInternal(ctx, latest)
		return err
	})
	return updated, err
}

// GetGroupMembers retrieves the list of members for a group.
// If the requester is an authorized manager, it returns emails. Otherwise, only UserIDs.
func (c *Client) GetGroupMembers(groupID string) ([]metadata.MemberEntry, error) {
	group, err := c.GetGroup(groupID)
	if err != nil {
		return nil, err
	}

	// Try to decrypt registry
	rk, err := c.getGroupRegistryKey(group)
	if err == nil {
		return c.decryptRegistry(rk, group.EncryptedRegistry)
	}

	// Not a manager, return public member list (IDs only)
	var members []metadata.MemberEntry
	for id := range group.Members {
		members = append(members, metadata.MemberEntry{UserID: id, Info: "[HIDDEN]"})
	}
	return members, nil
}

// GroupChown changes the owner of a group.
func (c *Client) GroupChown(ctx context.Context, groupID, newOwnerID string) error {
	// Pre-fetch new owner's public key once outside the retry loop
	var newOwnerEK *mlkem.EncapsulationKey768
	newOwner, err := c.GetUser(newOwnerID)
	if err == nil {
		newOwnerEK, _ = crypto.UnmarshalEncapsulationKey(newOwner.EncKey)
	} else {
		// Try as group?
		targetGroup, err := c.GetGroup(newOwnerID)
		if err == nil {
			newOwnerEK, _ = crypto.UnmarshalEncapsulationKey(targetGroup.EncKey)
		}
	}

	_, err = c.updateGroup(ctx, groupID, func(group *metadata.Group) error {
		// 1. Update RegistryLockbox (if we are a manager)
		rk, err := c.getGroupRegistryKey(group)
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
			gk, err := c.GetGroupPrivateKey(groupID)
			if err == nil {
				group.Lockbox.AddRecipient(newOwnerID, newOwnerEK, crypto.MarshalDecapsulationKey(gk))
			}
			gsk, err := c.GetGroupSignKey(groupID)
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
