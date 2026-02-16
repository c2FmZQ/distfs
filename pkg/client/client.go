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

	worldPublic  *mlkem.EncapsulationKey768
	worldPrivate *mlkem.DecapsulationKey768
	groupKeys    map[string]*mlkem.DecapsulationKey768

	sessionToken  string
	sessionExpiry time.Time
	sessionKey    []byte // Cached shared secret for memoization
	sessionMu     *sync.RWMutex
	loginMu       *sync.Mutex

	concurrencySem chan struct{}
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
		keyCache:       make(map[string]fileMetadata),
		keyMu:          &sync.RWMutex{},
		pathCache:      make(map[string]pathCacheEntry),
		pathMu:         &sync.RWMutex{},
		groupKeys:      make(map[string]*mlkem.DecapsulationKey768),
		sessionMu:      &sync.RWMutex{},
		loginMu:        &sync.Mutex{},
		concurrencySem: make(chan struct{}, 64), // Increased to 64 for higher throughput
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
		c.acquire()
		defer c.release()

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
		c.acquire()
		defer c.release()

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
			replicas = append(replicas, n.Address)
		}
		url += "?replicas=" + strings.Join(replicas, ",")
	}

	return c.withRetry(context.Background(), func() error {
		c.acquire()
		defer c.release()

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
				c.acquire()
				defer c.release()

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

				d, err := io.ReadAll(resp.Body)
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

func (c *Client) createInode(ctx context.Context, inode metadata.Inode) (*metadata.Inode, error) {
	data, err := json.Marshal(inode)
	if err != nil {
		return nil, err
	}

	var created metadata.Inode
	err = c.withRetry(ctx, func() error {
		c.acquire()
		defer c.release()

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

		return json.NewDecoder(body).Decode(&created)
	})

	if err != nil {
		return nil, err
	}
	return &created, nil
}
func (c *Client) updateInode(ctx context.Context, inode metadata.Inode) (*metadata.Inode, error) {
	data, err := json.Marshal(inode)
	if err != nil {
		return nil, err
	}

	var updated metadata.Inode
	err = c.withRetry(ctx, func() error {
		c.acquire()
		defer c.release()

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

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(body)
			return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
		}

		return json.NewDecoder(body).Decode(&updated)
	})

	if err != nil {
		return nil, err
	}
	return &updated, nil
}
func (c *Client) getInode(ctx context.Context, id string) (*metadata.Inode, error) {
	var inode metadata.Inode
	err := c.withRetry(ctx, func() error {
		c.acquire()
		defer c.release()

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
		return json.NewDecoder(body).Decode(&inode)
	})

	if err != nil {
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
		c.acquire()
		defer c.release()

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
		if resolveErr == nil {
			rc, err = c.ReadFile(inode.ID, key)
			if err == nil {
				return rc, nil
			}
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
		update := metadata.ChildUpdate{
			ParentID: w.parentID,
			Name:     w.nameHMAC,
			ChildID:  w.inode.ID,
		}
		data, _ := json.Marshal(update)
		err = w.client.withRetry(w.ctx, func() error {
			w.client.acquire()
			defer w.client.release()

			req, _ := http.NewRequestWithContext(w.ctx, "PUT", w.client.serverURL+"/v1/meta/directory/"+w.parentID+"/entry", nil)
			if err := w.client.authenticateRequest(req); err != nil {
				return err
			}
			if err := w.client.sealBody(req, data); err != nil {
				return err
			}

			resp, err := w.client.httpClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
			}
			return nil
		})
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

func (c *Client) SyncFile(id string, r io.ReaderAt, size int64, dirtyChunks map[int64]bool) error {
	ctx := context.Background()

	// 1. Get current inode state
	inode, err := c.GetInode(ctx, id)
	if err != nil {
		return err
	}

	key, err := c.UnlockInode(inode)
	if err != nil {
		return err
	}

	// 2. Handle Small File Inlining (Optimized Path)
	if size <= metadata.InlineLimit {
		buf := make([]byte, size)
		if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
			return err
		}
		ciphertext, err := crypto.EncryptDEM(key, buf)
		if err != nil {
			return err
		}
		inode.InlineData = ciphertext
		inode.ChunkManifest = nil
		inode.ChunkPages = nil
		inode.Size = uint64(size)
		_, err = c.updateInode(ctx, *inode)
		return err
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
				return err
			}
			chunkData := buf[:n]

			// Encrypt
			cid, ct, err := crypto.EncryptChunk(key, chunkData)
			if err != nil {
				return err
			}

			// Upload
			token, err := c.issueToken(id, []string{cid}, "W")
			if err != nil {
				return err
			}
			nodes, err := c.allocateNodes(ctx)
			if err != nil {
				return err
			}
			if err := c.uploadChunk(cid, ct, nodes, token); err != nil {
				return err
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
	_, err = c.updateInode(ctx, *inode)
	return err
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
	defer wc.Close()
	_, err = wc.Write(b)
	return err
}

func (c *Client) OpenForUpdate(name string, data any) (func(bool), error) {
	return c.OpenManyForUpdate([]string{name}, []any{data})
}

func (c *Client) OpenManyForUpdate(names []string, data []any) (func(bool), error) {
	if len(names) != len(data) {
		return nil, fmt.Errorf("names and data length mismatch")
	}

	ctx := context.Background()

	// Pre-create lockbox for potential new files
	fileKey := make([]byte, 32)
	rand.Read(fileKey)
	lb := c.createLockbox(fileKey, 0600, "")

	// 1. Acquire leases for all files
	if err := c.AcquireLeases(ctx, names, 2*time.Minute, lb); err != nil {
		return nil, err
	}

	// 2. Read all files
	for i, name := range names {
		if err := c.ReadDataFile(name, data[i]); err != nil {
			c.ReleaseLeases(ctx, names)
			return nil, err
		}
	}

	// 3. Return commit callback
	return func(commit bool) {
		if commit {
			for i, name := range names {
				if err := c.SaveDataFile(name, data[i]); err != nil {
					log.Printf("Failed to save %s during transactional update: %v", name, err)
				}
			}
		}
		c.ReleaseLeases(ctx, names)
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

// UnlockInode attempts to decrypt the file key for the inode using the client's identity.
func (c *Client) UnlockInode(inode *metadata.Inode) ([]byte, error) {
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
	return &group, nil
}

// CreateGroup creates a new cryptographic group.
func (c *Client) CreateGroup(name string) (*metadata.Group, error) {
	dk, _ := crypto.GenerateEncryptionKey()
	pk := dk.EncapsulationKey().Bytes()
	priv := crypto.MarshalDecapsulationKey(dk)

	lb := crypto.NewLockbox()
	// Encrypt group private key for the creator (owner)
	if err := lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), priv); err != nil {
		return nil, err
	}

	// Encrypt Group Name using Group Key (DEM)
	// Group private key is 64 bytes (mlkem), but DEM needs 32 bytes.
	// We hash the private key to get a 32-byte symmetric key.
	h := sha256.Sum256(priv)
	encName, err := crypto.EncryptDEM(h[:], []byte(name))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt group name: %w", err)
	}

	reqData := map[string]interface{}{
		"name":     name, // Server needs plaintext to compute GroupID = HMAC(Owner:Name)
		"enc_name": encName,
		"enc_key":  pk,
		"lockbox":  lb,
	}

	data, _ := json.Marshal(reqData)
	url := c.serverURL + "/v1/group/"
	req, err := http.NewRequest("POST", url, nil)
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
	return &created, nil
}

// AddUserToGroup adds a new member to an existing group.
func (c *Client) AddUserToGroup(groupID, userID string) error {
	group, err := c.GetGroup(groupID)
	if err != nil {
		return err
	}

	// We need the user's public key.
	// We need a GET /v1/user/{id} API.
	user, err := c.GetUser(userID)
	if err != nil {
		return err
	}

	// Decrypt group private key using our identity
	gk, err := c.GetGroupPrivateKey(groupID)
	if err != nil {
		return err
	}
	priv := crypto.MarshalDecapsulationKey(gk)

	// Add new member to lockbox
	userEK, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
	if err != nil {
		return err
	}
	if err := group.Lockbox.AddRecipient(userID, userEK, priv); err != nil {
		return err
	}

	group.Members[userID] = true

	data, _ := json.Marshal(group)
	req, err := http.NewRequest("PUT", c.serverURL+"/v1/group/"+groupID, nil)
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
		return fmt.Errorf("update group failed: %d %s", resp.StatusCode, string(b))
	}

	return nil
}

// GetUser fetches the user metadata (including public keys).
func (c *Client) GetUser(id string) (*metadata.User, error) {
	req, err := http.NewRequest("GET", c.serverURL+"/v1/user/"+id, nil)
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
		return nil, fmt.Errorf("get user failed: %d", resp.StatusCode)
	}

	var user metadata.User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
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
func (c *Client) SetAttrByID(inode *metadata.Inode, key []byte, attr metadata.SetAttrRequest) error {
	var err error
	// 1. Handle Cryptographic Access (World & Group)
	if attr.Mode != nil || attr.GroupID != nil {
		oldMode := inode.Mode
		newMode := inode.Mode
		if attr.Mode != nil {
			newMode = *attr.Mode
		}

		oldGroupID := inode.GroupID
		newGroupID := inode.GroupID
		if attr.GroupID != nil {
			newGroupID = *attr.GroupID
		}

		worldReadOld := (oldMode & 0004) != 0
		worldReadNew := (newMode & 0004) != 0

		groupRWOld := (oldMode & 0060) != 0
		groupRWNew := (newMode & 0060) != 0

		groupChanged := oldGroupID != newGroupID

		updated := false
		if worldReadOld != worldReadNew {
			if worldReadNew {
				wpk, err := c.GetWorldPublicKey()
				if err != nil {
					return err
				}
				if err := inode.Lockbox.AddRecipient(metadata.WorldID, wpk, key); err != nil {
					return err
				}
			} else {
				delete(inode.Lockbox, metadata.WorldID)
			}
			updated = true
		}

		// Handle Group Access Synchronization
		if groupChanged || groupRWOld != groupRWNew {
			// If group changed or was removed, delete the OLD recipient from the lockbox
			if oldGroupID != "" {
				delete(inode.Lockbox, oldGroupID)
				updated = true
			}

			// If we HAVE a new group and the new mode allows group access, add it
			if newGroupID != "" && groupRWNew {
				group, err := c.GetGroup(newGroupID)
				if err != nil {
					return fmt.Errorf("failed to fetch new group info: %w", err)
				}
				gk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
				if err != nil {
					return fmt.Errorf("failed to unmarshal group public key: %w", err)
				}
				if err := inode.Lockbox.AddRecipient(newGroupID, gk, key); err != nil {
					return err
				}
				updated = true
			}
		}

		if updated {
			// Update the local inode state before sending to server
			inode.Mode = newMode
			inode.GroupID = newGroupID
			_, err = c.updateInode(context.Background(), *inode)
			if err != nil {
				return err
			}
		}
	}

	// 2. Push remaining attributes to FSM SetAttr handler
	attr.InodeID = inode.ID
	var data []byte
	data, err = json.Marshal(attr)
	if err != nil {
		return err
	}

	var hReq *http.Request
	hReq, err = http.NewRequest("POST", c.serverURL+"/v1/meta/setattr", nil)
	if err != nil {
		return err
	}
	if err = c.authenticateRequest(hReq); err != nil {
		return err
	}
	if err = c.sealBody(hReq, data); err != nil {
		return err
	}

	var resp *http.Response
	resp, err = c.httpClient.Do(hReq)
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
}

// Remove deletes an inode at the given path.
func (c *Client) Remove(path string) error {
	inode, _, err := c.ResolvePath(path)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("DELETE", c.serverURL+"/v1/meta/inode/"+inode.ID, nil)
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
	c.invalidatePathCache(path)
	return nil
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

func (c *Client) acquire() {
	c.concurrencySem <- struct{}{}
}

func (c *Client) release() {
	<-c.concurrencySem
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

func (c *Client) GetClusterStats() (*metadata.ClusterStats, error) {
	var stats metadata.ClusterStats
	err := c.withRetry(context.Background(), func() error {
		c.acquire()
		defer c.release()

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
		c.acquire()
		defer c.release()

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
		c.acquire()
		defer c.release()

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

// RefreshNodeRegistry fetches the current node registry from the server.
