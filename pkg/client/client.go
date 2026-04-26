// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      httpCli://www.apache.org/licenses/LICENSE-2.0
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
	"io/fs"
	"iter"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	stdpath "path"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/logger"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type contextKey string

const (
	adminBypassContextKey contextKey = "admin-bypass"
	verificationStateKey  contextKey = "verification-state"
)

type verificationState struct {
	toVerify map[string]bool
	mu       sync.Mutex
}

func (s *verificationState) add(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.toVerify == nil {
		s.toVerify = make(map[string]bool)
	}
	s.toVerify[id] = true
}

func (s *verificationState) getPending() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id := range s.toVerify {
		ids = append(ids, id)
	}
	// Clear the map so subsequent calls don't re-process
	s.toVerify = make(map[string]bool)
	return ids
}

func withVerificationState(ctx context.Context) (context.Context, *verificationState, bool) {
	if s, ok := ctx.Value(verificationStateKey).(*verificationState); ok {
		return ctx, s, false
	}
	s := &verificationState{toVerify: make(map[string]bool)}
	return context.WithValue(ctx, verificationStateKey, s), s, true
}

func (c *Client) processVerificationQueue(ctx context.Context, state *verificationState) error {
	iters := 0
	for {
		if iters > 100 {
			return fmt.Errorf("registry verification loop exceeded maximum depth")
		}
		iters++
		pending := state.getPending()
		if len(pending) == 0 {
			break
		}

		for _, id := range pending {
			// First, check if it's a known group from the optimistic phase
			c.cacheMu.RLock()
			_, isVerifiedGroup := c.verifiedGroupCache[id]
			_, isUnverifiedGroup := c.unverifiedGroupCache[id]
			c.cacheMu.RUnlock()

			if isVerifiedGroup || isUnverifiedGroup || metadata.IsInodeID(id) {
				// Verify Group
				if isVerifiedGroup {
					continue
				}

				group, err := c.getGroupUnverifiedCached(ctx, id)
				if err != nil {
					return fmt.Errorf("failed to fetch optimistic group %s for confirmation: %w", id, err)
				}
				if err := c.verifyGroup(ctx, group); err != nil {
					return err
				}

				// Phase 69: Move to verified cache to break recursion
				c.cacheMu.Lock()
				c.verifiedGroupCache[id] = group
				delete(c.unverifiedGroupCache, id)
				c.cacheMu.Unlock()
			} else {
				// User
				c.cacheMu.RLock()
				_, verified := c.userCache[id]
				c.cacheMu.RUnlock()
				if verified {
					continue // Already in verified cache
				}

				user, err := c.getUserRaw(ctx, id)
				if err != nil {
					// Fallback: it might be a group that wasn't in the cache yet
					if isNotFound(err) {
						group, gerr := c.getGroupRaw(ctx, id)
						if gerr == nil {
							if err := c.verifyGroup(ctx, group); err != nil {
								return err
							}
							c.cacheMu.Lock()
							c.verifiedGroupCache[id] = group
							delete(c.unverifiedGroupCache, id)
							c.cacheMu.Unlock()
							continue
						}
					}
					return err
				}
				if err := c.verifyUser(ctx, user); err != nil {
					return err
				}

				// Phase 69: Move to verified cache
				c.cacheMu.Lock()
				c.userCache[id] = user
				c.cacheMu.Unlock()

				// Root Identity Pinning (TOFU)
				c.rootMu.Lock()
				if id == c.rootOwner {
					if len(c.rootOwnerPK) == 0 {
						c.rootOwnerPK = user.SignKey
						c.rootOwnerEK = user.EncKey
					} else if !bytes.Equal(c.rootOwnerPK, user.SignKey) {
						c.rootMu.Unlock()
						return fmt.Errorf("ROOT IDENTITY MISMATCH: pinned public key for %s does not match server", id)
					}
				}
				c.rootMu.Unlock()

				c.cacheMu.Lock()
				c.userCache[id] = user
				c.cacheMu.Unlock()
			}
		}
	}
	return nil
}

func (c *Client) invalidateUserCache(userID string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	delete(c.userCache, userID)
}

func (c *Client) invalidateGroupCache(groupID string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	delete(c.verifiedGroupCache, groupID)
	delete(c.unverifiedGroupCache, groupID)
}

// PushKeySyncJSON pushes a JSON-encoded key sync blob to the server.
func (c *Client) PushKeySyncJSON(ctx context.Context, jsonBlob string) error {
	var blob metadata.KeySyncBlob
	if err := json.Unmarshal([]byte(jsonBlob), &blob); err != nil {
		return fmt.Errorf("invalid keysync blob: %w", err)
	}
	return c.pushKeySync(ctx, &blob)
}

// PullKeySyncJSON pulls a key sync blob from the server and returns it as a JSON string.
func (c *Client) PullKeySyncJSON(ctx context.Context, jwt string) (string, error) {
	blob, err := c.pullKeySync(ctx, jwt)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(blob)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GetServerKeyBytes returns the server's public encryption key as raw bytes.
func (c *Client) GetServerKeyBytes(ctx context.Context) ([]byte, error) {
	key, err := c.getServerKey(ctx)
	if err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

// getServerKeys returns the server's public encryption and signing keys.

func (c *Client) getServerKeys() (*mlkem.EncapsulationKey768, []byte) {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	return c.serverKey, c.serverSignPK
}

// getServerSignKey fetches the server's public signing key (ML-DSA).
func (c *Client) getServerSignKey(ctx context.Context) ([]byte, error) {
	c.keyMu.RLock()
	sk := c.serverSignPK
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	bodyRC, _, err := c.doRequest(ctx, "GET", "/v1/meta/key/sign", nil, requestOptions{skipAuth: true, skipControl: true, retry: true}, nil)
	if err != nil {
		return nil, err
	}
	defer bodyRC.Close()

	b, err := io.ReadAll(io.LimitReader(bodyRC, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.keyMu.Lock()
	c.serverSignPK = b
	c.keyMu.Unlock()
	return b, nil
}

// getClusterSignKey fetches the cluster's public signing key (ML-DSA).
func (c *Client) getClusterSignKey(ctx context.Context) ([]byte, error) {
	c.keyMu.RLock()
	sk := c.clusterSignPK
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	bodyRC, _, err := c.doRequest(ctx, "GET", "/v1/meta/key/cluster/sign", nil, requestOptions{skipAuth: true, skipControl: true, retry: true}, nil)
	if err != nil {
		return nil, err
	}
	defer bodyRC.Close()

	b, err := io.ReadAll(io.LimitReader(bodyRC, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.keyMu.Lock()
	c.clusterSignPK = b
	c.keyMu.Unlock()
	return b, nil
}

// getGroupEpochSeed fetches the current epoch seed for a group.
func (c *Client) getGroupEpochSeed(ctx context.Context, groupID string) ([]byte, error) {
	group, err := c.getGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	return c.getGroupEpochSeedFromGroup(ctx, group)
}

// getGroupEpochSeedUnverified fetches the current epoch seed for a group (unverified).
func (c *Client) getGroupEpochSeedUnverified(ctx context.Context, groupID string) ([]byte, error) {
	group, err := c.getGroupUnverifiedCached(ctx, groupID)
	if err != nil {
		return nil, err
	}
	return c.getGroupEpochSeedFromGroup(ctx, group)
}

func (c *Client) getGroupEpochSeedFromGroup(ctx context.Context, group *metadata.Group) ([]byte, error) {
	// In Phase 71, every member has the Epoch Seed in their lockbox entry.
	// 1. Try Personal Access (HMAC for Phase 71 privacy)
	target := c.computeMemberHMAC(group.ID, c.userID)

	if key, err := group.Lockbox.GetFileKey(target, c.decKey); err == nil {
		return key, nil
	}

	// 2. Try Anonymous Access (Trial Decryption of AnonymousLockbox)
	if len(group.AnonymousLockbox) > 0 {
		for _, blob := range group.AnonymousLockbox {
			var lb crypto.Lockbox
			if err := json.Unmarshal(blob, &lb); err != nil {
				continue
			}
			// Anonymous entries use the key "seed" as established in AddAnonymousUserToGroup
			seed, err := lb.GetFileKey("seed", c.decKey)
			if err == nil {
				return seed, nil
			}
		}
	}

	// 3. Try Group-based Access (Nested Groups)
	// If the group is owned by another group, we might have access via the owning group ID
	if group.OwnerID != "" && group.OwnerID != metadata.SelfOwnedGroup {
		target := c.computeMemberHMAC(group.ID, group.OwnerID)
		if entry, ok := group.Lockbox[target]; ok {
			gk, gerr := c.getGroupPrivateKey(ctx, group.OwnerID, entry.Epoch)
			if gerr == nil {
				key, err := group.Lockbox.GetFileKey(target, gk)
				if err == nil {
					return key, nil
				}
			}
		}
	}

	// 3. Fallback for Managers: Try the Registry Lockbox
	rk, err := c.getGroupRegistryKey(ctx, group)
	if err == nil {
		masterSeed, err := crypto.DecryptDEM(rk, group.EncryptedEpochSeed)
		if err == nil {
			epochSeed, kerr := crypto.DeriveEpochKey(masterSeed, metadata.MaxEpochs, group.Epoch)
			if kerr == nil {
				return epochSeed, nil
			}
		}
	}

	return nil, fmt.Errorf("user %s is not a member or manager of group %s", c.userID, group.ID)
}

// GetServerKey fetches the cluster's current world public encryption key (ML-KEM).
func (c *Client) getServerKey(ctx context.Context) (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	sk := c.serverKey
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	bodyRC, _, err := c.doRequest(ctx, "GET", "/v1/meta/key", nil, requestOptions{skipAuth: true, skipControl: true, retry: true}, nil)
	if err != nil {
		return nil, err
	}
	defer bodyRC.Close()

	b, err := io.ReadAll(io.LimitReader(bodyRC, 1024*1024)) // 1MB limit
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

// InodeInfo provides a safe, exported representation of an inode's public metadata.
type InodeInfo struct {
	ID            string
	Type          metadata.InodeType
	Mode          uint32
	Size          uint64
	OwnerID       string
	GroupID       string
	NLink         uint32
	Version       uint64
	MTime         int64
	SymlinkTarget string
	AccessACL     *ACL
	DefaultACL    *ACL
	Lockbox       map[string]struct {
		KEM []byte
		DEM []byte
	}
}

func (i *InodeInfo) IsDir() bool {
	return i.Type == metadata.DirType
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

// ACL provides a safe representation of POSIX access controls.
type ACL struct {
	Users  map[string]uint32 `json:"users"`
	Groups map[string]uint32 `json:"groups"`
	Mask   *uint32           `json:"mask,omitempty"`
}

func (a *ACL) toInternal() *metadata.POSIXAccess {
	if a == nil {
		return nil
	}
	res := &metadata.POSIXAccess{
		Users:  make(map[string]uint32),
		Groups: make(map[string]uint32),
	}
	for k, v := range a.Users {
		res.Users[k] = v
	}
	for k, v := range a.Groups {
		res.Groups[k] = v
	}
	if a.Mask != nil {
		m := *a.Mask
		res.Mask = &m
	}
	return res
}

func fromInternalACL(a *metadata.POSIXAccess) *ACL {
	if a == nil {
		return nil
	}
	res := &ACL{
		Users:  make(map[string]uint32),
		Groups: make(map[string]uint32),
	}
	for k, v := range a.Users {
		res.Users[k] = v
	}
	for k, v := range a.Groups {
		res.Groups[k] = v
	}
	if a.Mask != nil {
		m := *a.Mask
		res.Mask = &m
	}
	return res
}

// InodeUpdateFunc is a callback used to modify an inode during an atomic update.
type InodeUpdateFunc func(*metadata.Inode) error

// GroupUpdateFunc is a callback used to modify a group during an atomic update.
type GroupUpdateFunc func(*metadata.Group) error

type groupKeyCacheID struct {
	id    string
	epoch uint32
}

// Client is the primary entry point for interacting with a DistFS cluster.
// It handles end-to-end encryption, chunking, and metadata coordination.
type Client struct {
	serverAddr    string
	httpCli       *http.Client
	userID        string
	decKey        *mlkem.DecapsulationKey768
	signKey       *crypto.IdentityKey
	serverKey     *mlkem.EncapsulationKey768
	serverSignPK  []byte
	clusterSignPK []byte
	keyCache      map[string]fileMetadata
	keyMu         *sync.RWMutex

	pathCache map[string]pathCacheEntry
	pathMu    *sync.RWMutex

	worldPublic   *mlkem.EncapsulationKey768
	worldPrivate  *mlkem.DecapsulationKey768
	groupKeys     map[groupKeyCacheID]*mlkem.DecapsulationKey768
	groupSignKeys map[groupKeyCacheID]*crypto.IdentityKey

	userCache            map[string]*metadata.User
	verifiedGroupCache   map[string]*metadata.Group
	unverifiedGroupCache map[string]*metadata.Group
	cacheMu              *sync.RWMutex

	sessionToken  string
	sessionExpiry time.Time
	sessionKey    []byte // Cached shared secret for memoization
	sessionMu     *sync.RWMutex
	loginMu       *sync.Mutex

	// Root Anchoring (Phase 31/69)
	rootID      string
	rootOwner   string
	rootOwnerPK []byte
	rootOwnerEK []byte
	rootVersion uint64
	rootMu      *sync.RWMutex

	controlSem chan struct{}
	dataSem    chan struct{}

	isAdmin bool

	mutationMu    *sync.Mutex
	mutationLocks map[string]*sync.Mutex

	onLeaseExpired func(id string, err error)

	registryDir string

	timelineSampleRate float64
	anchoredNodes      []metadata.ClusterNode
	anchoredNodesMu    *sync.RWMutex

	allocCache  []metadata.Node
	allocExpiry time.Time
	allocMu     *sync.RWMutex
}

// GetRootID returns the ID of the root directory.
func (c *Client) getRootID() string {
	c.rootMu.RLock()
	defer c.rootMu.RUnlock()
	return c.rootID
}

// NewClient creates a new DistFS client.
func NewClient(serverAddr string) *Client {
	transport := getDefaultTransport(serverAddr)

	return &Client{
		serverAddr:         serverAddr,
		timelineSampleRate: 0.0,
		httpCli: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Minute,
		},
		keyCache:             make(map[string]fileMetadata),
		keyMu:                &sync.RWMutex{},
		pathCache:            make(map[string]pathCacheEntry),
		pathMu:               &sync.RWMutex{},
		groupKeys:            make(map[groupKeyCacheID]*mlkem.DecapsulationKey768),
		groupSignKeys:        make(map[groupKeyCacheID]*crypto.IdentityKey),
		userCache:            make(map[string]*metadata.User),
		verifiedGroupCache:   make(map[string]*metadata.Group),
		unverifiedGroupCache: make(map[string]*metadata.Group),
		cacheMu:              &sync.RWMutex{},
		sessionMu:            &sync.RWMutex{},
		loginMu:              &sync.Mutex{},
		controlSem:           make(chan struct{}, 128), // High throughput for metadata
		dataSem:              make(chan struct{}, 64),  // Limit chunk I/O
		mutationMu:           &sync.Mutex{},
		mutationLocks:        make(map[string]*sync.Mutex),
		rootID:               metadata.RootID,
		rootMu:               &sync.RWMutex{},
		allocMu:              &sync.RWMutex{},
		registryDir:          "/registry",
		anchoredNodesMu:      &sync.RWMutex{},
	}
}

// WithIdentityBytes returns a new client with the specified user identity parsed from raw bytes.
func (c *Client) WithIdentityBytes(userID string, decKey []byte) (*Client, error) {
	key, err := crypto.UnmarshalDecapsulationKey(decKey)
	if err != nil {
		return nil, err
	}
	return c.withIdentity(userID, key), nil
}

// PublicEncryptionKey returns the client's public encryption key (ML-KEM).
func (c *Client) PublicEncryptionKey() *mlkem.EncapsulationKey768 {
	return c.decKey.EncapsulationKey()
}

func (c *Client) withIdentity(userID string, key *mlkem.DecapsulationKey768) *Client {
	c2 := *c
	c2.userID = userID
	c2.decKey = key
	c2.keyCache = make(map[string]fileMetadata) // New cache for new identity
	return &c2
}

// WithSignKeyBytes returns a new client with the specified signing key parsed from raw bytes.
func (c *Client) WithSignKeyBytes(signKey []byte) (*Client, error) {
	key := crypto.UnmarshalIdentityKey(signKey)
	if key == nil {
		return nil, errors.New("invalid signing key")
	}
	return c.withSignKey(key), nil
}

// withSignKey returns a new client with the specified signing key.
func (c *Client) withSignKey(key *crypto.IdentityKey) *Client {
	c2 := *c
	c2.signKey = key
	return &c2
}

// WithServerKeyBytes returns a new client with the pre-configured server public key parsed from raw bytes.
func (c *Client) WithServerKeyBytes(serverKey []byte) (*Client, error) {
	key, err := crypto.UnmarshalEncapsulationKey(serverKey)
	if err != nil {
		return nil, err
	}
	return c.withServerKey(key), nil
}

// withServerKey returns a new client with the pre-configured server public key.
func (c *Client) withServerKey(key *mlkem.EncapsulationKey768) *Client {
	c2 := *c
	c2.serverKey = key
	return &c2
}

// WithRootAnchorBytes returns a new client with the specified root anchoring information.
func (c *Client) WithRootAnchorBytes(id, owner string, pk, ek []byte, version uint64) *Client {
	return c.withRootAnchor(id, owner, pk, ek, version)
}

// withRootAnchor returns a new client with the specified root anchoring information.
func (c *Client) withRootAnchor(id, owner string, pk, ek []byte, version uint64) *Client {
	c2 := *c
	c2.rootMu = &sync.RWMutex{}
	if id != "" {
		c2.rootID = id
	}
	c2.rootOwner = owner
	c2.rootOwnerPK = pk
	c2.rootOwnerEK = ek
	c2.rootVersion = version
	return &c2
}

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
	c2.rootOwnerPK = nil
	c2.rootOwnerEK = nil
	c2.rootVersion = 0
	c2.pathCache = make(map[string]pathCacheEntry)
	c2.pathMu = &sync.RWMutex{}
	c2.rootMu = &sync.RWMutex{}
	return &c2
}

// WithAdmin returns a new client with the admin bypass enabled.
func (c *Client) WithAdmin(isAdmin bool) *Client {
	c2 := *c
	c2.isAdmin = isAdmin
	return &c2
}

// WithDisableDoH configures whether to disable DNS-over-HTTPS and use the system resolver instead.
func (c *Client) WithDisableDoH(disable bool) *Client {
	c2 := *c
	clonedClient := *c.httpCli
	c2.httpCli = &clonedClient
	c2.httpCli.Transport = applyDisableDoH(c2.httpCli.Transport, disable)
	return &c2
}

// WithAllowInsecure configures whether to allow insecure TLS connections (skip verification).
func (c *Client) WithAllowInsecure(allow bool) *Client {
	c2 := *c
	clonedClient := *c.httpCli
	c2.httpCli = &clonedClient
	c2.httpCli.Transport = applyAllowInsecure(c2.httpCli.Transport, allow)
	return &c2
}

// WithTimelineSampleRate configures the probability (0.0 to 1.0) of performing
// Byzantine-resistant timeline verification on every metadata response.
func (c *Client) WithTimelineSampleRate(v float64) *Client {
	c2 := *c
	c2.timelineSampleRate = v
	return &c2
}

// WithLeaseExpiredCallback returns a new client with the specified lease expiration callback.
func (c *Client) WithLeaseExpiredCallback(fn func(id string, err error)) *Client {
	c2 := *c
	c2.onLeaseExpired = fn
	return &c2
}

// GetRootAnchor returns the current root anchoring information.
func (c *Client) GetRootAnchor() (id, owner string, pk, ek []byte, version uint64) {
	c.rootMu.RLock()
	defer c.rootMu.RUnlock()
	return c.rootID, c.rootOwner, c.rootOwnerPK, c.rootOwnerEK, c.rootVersion
}

// UserID returns the current user ID.
func (c *Client) UserID() string {
	return c.userID
}

// HTTPClient returns the underlying HTTP client, useful for raw requests in WASM bridge.
func (c *Client) httpClient() *http.Client {
	return c.httpCli
}

// SignKey returns the current client's identity signing key.
func (c *Client) SignKey() *crypto.IdentityKey {
	return c.signKey
}

// DecKey returns the current client's identity decryption key.
func (c *Client) DecKey() *mlkem.DecapsulationKey768 {
	return c.decKey
}

// ServerURL returns the server URL of this client.
func (c *Client) serverURL() string {
	return c.serverAddr
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
	var challengeRes metadata.AuthChallengeResponse
	_, _, err := c.doRequest(ctx, "POST", "/v1/auth/challenge", b, requestOptions{skipAuth: true, skipControl: true, retry: true}, &challengeRes)
	if err != nil {
		return err
	}

	// 2. Verify server signature over challenge
	serverSignPK, err := c.getServerSignKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server sign key: %w", err)
	}
	if !crypto.VerifySignature(serverSignPK, challengeRes.Challenge, challengeRes.Signature) {
		return fmt.Errorf("invalid server signature on challenge")
	}

	// 3. Solve Challenge (Sign it) + Ephemeral Key for Forward Secrecy
	sig := c.signKey.Sign(challengeRes.Challenge)

	// Phase 53.1: Ephemeral PQC-KEM for Forward Secret Session Key
	sessionDK, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral session key: %w", err)
	}

	solve := metadata.AuthChallengeSolve{
		UserID:    c.userID,
		Challenge: challengeRes.Challenge,
		Signature: sig,
		EncKey:    sessionDK.EncapsulationKey().Bytes(),
	}
	b, _ = json.Marshal(solve)

	var res metadata.SessionResponse
	_, _, err = c.doRequest(ctx, "POST", "/v1/login", b, requestOptions{skipAuth: true, skipControl: true, retry: true}, &res)
	if err != nil {
		return err
	}

	// Phase 53.1: Derive Shared Secret for session
	var sharedSecret []byte
	if len(res.KEMCT) > 0 {
		sharedSecret, err = sessionDK.Decapsulate(res.KEMCT)
		if err != nil {
			return fmt.Errorf("failed to decapsulate session key: %w", err)
		}
	}

	c.sessionMu.Lock()
	c.sessionToken = res.Token
	c.sessionKey = sharedSecret
	c.sessionExpiry = time.Now().Add(55 * time.Minute) // Buffer
	c.sessionMu.Unlock()
	return nil
}

func (c *Client) getPathCache(fullPath string) (pathCacheEntry, bool) {
	c.pathMu.RLock()
	defer c.pathMu.RUnlock()
	entry, ok := c.pathCache[fullPath]
	return entry, ok
}

func (c *Client) putPathCache(fullPath string, entry pathCacheEntry) {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	c.pathCache[fullPath] = entry
}

func (c *Client) invalidatePathCache(fullPath string) {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	delete(c.pathCache, fullPath)
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

func (c *Client) authenticateRequest(ctx context.Context, req *http.Request) error {
	// 1. Special cases: registration, login, and keys don't need session auth.
	if strings.HasSuffix(req.URL.Path, "/v1/user/register") ||
		strings.HasSuffix(req.URL.Path, "/v1/auth/challenge") ||
		strings.HasSuffix(req.URL.Path, "/v1/login") ||
		strings.HasSuffix(req.URL.Path, "/v1/meta/key") ||
		strings.HasSuffix(req.URL.Path, "/v1/timeline") {
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
	if c.isAdmin {
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
		if c.signKey == nil {
			return errors.New("client identity required for sealed requests")
		}
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
		sk, err := c.getServerKey(ctx)
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
		if c.signKey == nil {
			return errors.New("client identity required for sealed requests")
		}
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
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	req.Header.Set("X-DistFS-Sealed", "true")
	req.Header.Set("Content-Type", "application/json")
	if c.isAdmin {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	} else if bypass, _ := req.Context().Value(adminBypassContextKey).(bool); bypass {
		req.Header.Set("X-DistFS-Admin-Bypass", "true")
	}
	return nil
}
func (c *Client) unsealResponse(ctx context.Context, resp *http.Response) (io.ReadCloser, error) {
	if resp.Header.Get("X-DistFS-Sealed") != "true" {
		// If the server rejected our sealed request before unsealing it (e.g. 403 Forbidden),
		// it did not cache our session key. We must invalidate our local cache to
		// ensure the next request falls back to Full KEM.
		// Only apply this to requests that were actually sealed (mutations).
		if resp.StatusCode >= 400 && resp.Request != nil && resp.Request.Method != http.MethodGet {
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

	// Phase 71: Response Binding (Verifiable Timeline)
	if len(sealed.BindingSignature) > 0 {
		cPK, err := c.getClusterSignKey(ctx)
		if err == nil && len(cPK) > 0 {
			h := crypto.NewHash()
			h.Write(sealed.Sealed)
			idxBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(idxBuf, sealed.TimelineIndex)
			h.Write(idxBuf)
			h.Write(sealed.ClusterStateHash)
			if !crypto.VerifySignature(cPK, h.Sum(nil), sealed.BindingSignature) {
				return nil, fmt.Errorf("INVALID CLUSTER BINDING: response signature mismatch")
			}

			// Byzantine-resistant Quorum Verification (Probabilistic)
			if mrand.Float64() < c.timelineSampleRate {
				if err := c.VerifyTimelineReceipt(ctx, sealed); err != nil {
					// We only fail if it was a legitimate fork detection.
					// Discovery failures (e.g. during bootstrap) are ignored.
					if errors.Is(err, metadata.ErrCryptographicFork) {
						return nil, err
					}
				}
			}
		}
	}

	serverSignPK, err := c.getServerSignKey(ctx)
	if err != nil {
		return nil, err
	}

	// Phase 53.1: Try symmetric decryption if session key is available (Forward Secrecy)
	c.sessionMu.RLock()
	sessionKey := c.sessionKey
	c.sessionMu.RUnlock()

	var ts int64
	var payload []byte
	var opened bool

	if sessionKey != nil {
		ts, payload, err = crypto.OpenResponseSymmetric(sessionKey, serverSignPK, sealed.Sealed)
		if err == nil {
			opened = true
		}
	}

	if !opened {
		// 1. Open (Full KEM Fallback)
		ts, payload, err = crypto.OpenResponse(c.decKey, serverSignPK, sealed.Sealed)
		if err != nil {
			return nil, fmt.Errorf("failed to open response: %w", err)
		}
	}

	// 2. Replay/Staleness Protection
	now := time.Now().UnixNano()
	if ts < now-int64(5*time.Minute) || ts > now+int64(5*time.Minute) {
		return nil, fmt.Errorf("response timestamp out of range")
	}

	return io.NopCloser(bytes.NewReader(payload)), nil
}

// ClearNodeCache clears the internal cache of allocated storage nodes.
func (c *Client) ClearNodeCache() {
	c.allocMu.Lock()
	defer c.allocMu.Unlock()
	c.allocCache = nil
	c.allocExpiry = time.Time{}
}

// ClearMetadataCache clears the internal cache of verified and unverified users and groups.
func (c *Client) ClearMetadataCache() {
	c.cacheMu.Lock()
	clear(c.userCache)
	clear(c.verifiedGroupCache)
	clear(c.unverifiedGroupCache)
	clear(c.pathCache)
	c.cacheMu.Unlock()

	c.keyMu.Lock()
	clear(c.keyCache)
	clear(c.groupKeys)
	c.keyMu.Unlock()
}

func (c *Client) allocateNodes(ctx context.Context) ([]metadata.Node, error) {
	c.allocMu.RLock()
	if time.Now().Before(c.allocExpiry) && len(c.allocCache) > 0 {
		nodes := c.allocCache
		c.allocMu.RUnlock()
		return nodes, nil
	}
	c.allocMu.RUnlock()

	var nodes []metadata.Node
	_, _, err := c.doRequest(ctx, "POST", "/v1/meta/allocate", nil, requestOptions{action: metadata.ActionAllocateChunk, sealed: true, unseal: true, retry: true}, &nodes)
	if err != nil {
		return nil, err
	}

	c.allocMu.Lock()
	c.allocCache = nodes
	c.allocExpiry = time.Now().Add(1 * time.Minute)
	c.allocMu.Unlock()

	return nodes, nil
}

func (c *Client) issueToken(ctx context.Context, inodeID string, chunks []string, mode string) (string, error) {
	reqData := map[string]interface{}{
		"inode_id": inodeID,
		"chunks":   chunks,
		"mode":     mode,
	}
	data, _ := json.Marshal(reqData)

	// Special case: Token is raw bytes, not JSON
	bodyRC, _, err := c.doRequest(ctx, "POST", "/v1/meta/token", data, requestOptions{action: metadata.ActionIssueToken, sealed: true, unseal: true, retry: true}, nil)
	if err != nil {
		return "", err
	}
	defer bodyRC.Close()

	respBytes, err := io.ReadAll(bodyRC)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(respBytes), nil
}

func (c *Client) uploadChunk(ctx context.Context, id string, data []byte, nodes []metadata.Node, token string) error {
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes allocated")
	}

	return c.withRetry(ctx, func() error {
		// Pick primary based on attempt count (via loop variable in withRetry if we had it,
		// but we can just use a local counter or random shuffle here.
		// Actually, let's just try them in order and rotate on each retry.
		// Since withRetry doesn't expose attempt index, we'll use a local atomic or just random.
		// Better: just try the first one, if it fails, withRetry will call us again.
		// To make progress, we can shuffle nodes here.

		// Phase 69: Improved robustness - shuffle nodes on each retry attempt
		// to ensure we eventually pick a functional primary.
		localNodes := make([]metadata.Node, len(nodes))
		copy(localNodes, nodes)
		if len(localNodes) > 1 {
			for i := len(localNodes) - 1; i > 0; i-- {
				j := mrand.Intn(i + 1)
				localNodes[i], localNodes[j] = localNodes[j], localNodes[i]
			}
		}

		primary := localNodes[0]
		url := fmt.Sprintf("%s/v1/data/%s", primary.Address, id)
		if len(localNodes) > 1 {
			var replicas []string
			for _, n := range localNodes[1:] {
				if n.Address != "" {
					replicas = append(replicas, n.Address)
				}
			}
			if len(replicas) > 0 {
				url += "?replicas=" + strings.Join(replicas, ",")
			}
		}

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

		resp, err := c.httpCli.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			body, _ := c.unsealResponse(ctx, resp)
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

// deleteChunk removes a chunk from its primary node.
func (c *Client) deleteChunk(ctx context.Context, id string, nodes []metadata.Node, token string) error {
	if len(nodes) == 0 {
		return nil
	}

	return c.withRetry(ctx, func() error {
		// Phase 69: Rotate nodes on each retry
		localNodes := make([]metadata.Node, len(nodes))
		copy(localNodes, nodes)
		if len(localNodes) > 1 {
			for i := len(localNodes) - 1; i > 0; i-- {
				j := mrand.Intn(i + 1)
				localNodes[i], localNodes[j] = localNodes[j], localNodes[i]
			}
		}

		primary := localNodes[0]
		url := fmt.Sprintf("%s/v1/data/%s", primary.Address, id)

		req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if sess := c.getSessionToken(); sess != "" {
			req.Header.Set("Session-Token", sess)
		}

		resp, err := c.httpCli.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			body, _ := c.unsealResponse(ctx, resp)
			return c.newAPIError(resp, body)
		}
		return nil
	})
}

func (c *Client) cleanupChunks(ctx context.Context, inodeID string, chunks []metadata.ChunkEntry) {
	if len(chunks) == 0 {
		return
	}

	// Use a detached context for cleanup to ensure it runs even if the original request was canceled.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// We need a delete token
	ids := make([]string, 0, len(chunks))
	for _, ch := range chunks {
		ids = append(ids, ch.ID)
	}

	token, err := c.issueToken(cleanupCtx, inodeID, ids, "D")
	if err != nil {
		return
	}

	// Resolve Node IDs to Addresses
	activeNodes, err := c.getNodes(cleanupCtx)
	if err != nil {
		return
	}
	nodeMap := make(map[string]metadata.Node)
	for _, n := range activeNodes {
		nodeMap[n.ID] = n
	}

	for _, ch := range chunks {
		var targetNodes []metadata.Node
		for _, nid := range ch.Nodes {
			if n, ok := nodeMap[nid]; ok {
				targetNodes = append(targetNodes, n)
			}
		}
		if err := c.deleteChunk(cleanupCtx, ch.ID, targetNodes, token); err != nil {
		}
	}
}

// GetNodes returns all storage nodes in the cluster.
func (c *Client) getNodes(ctx context.Context) ([]metadata.Node, error) {
	var res struct {
		Nodes []metadata.Node `json:"nodes"`
	}
	_, _, err := c.doRequest(ctx, "GET", "/v1/node", nil, requestOptions{skipControl: true, retry: true}, &res)
	if err != nil {
		return nil, err
	}
	return res.Nodes, nil
}

var downloadBufPool = sync.Pool{
	New: func() interface{} {
		b := bytes.NewBuffer(make([]byte, 0, crypto.ChunkSize+4096))
		return b
	},
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

				resp, err := c.httpCli.Do(req)
				if err != nil {
					resCh <- result{err: err}
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					body, _ := c.unsealResponse(lctx, resp)
					resCh <- result{err: c.newAPIError(resp, body)}
					return
				}

				limit := int64(crypto.ChunkSize + 4096) // 1MB + overhead buffer

				buf := downloadBufPool.Get().(*bytes.Buffer)
				buf.Reset()
				_, err = io.Copy(buf, io.LimitReader(resp.Body, limit))

				var d []byte
				if err == nil {
					d = make([]byte, buf.Len())
					copy(d, buf.Bytes())
				}
				downloadBufPool.Put(buf)

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

func (e *APIError) ToFS() error {
	switch e.StatusCode {
	case http.StatusNotFound:
		return fs.ErrNotExist
	case http.StatusUnauthorized, http.StatusForbidden:
		return fs.ErrPermission
	case http.StatusConflict:
		return fs.ErrExist
	default:
		return e
	}
}

// ListGroups retrieves all groups associated with the current user.
func (c *Client) ListGroups(ctx context.Context) iter.Seq2[metadata.GroupListEntry, error] {
	return func(yield func(metadata.GroupListEntry, error) bool) {
		var resp metadata.GroupListResponse
		_, _, err := c.doRequest(ctx, "GET", "/v1/user/groups", nil, requestOptions{action: metadata.ActionListGroups, unseal: true, retry: true}, &resp)
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

// verifyUser verifies a user's identity against the registry anchor.
func (c *Client) verifyUser(ctx context.Context, user *metadata.User) error {
	if c.registryDir == "" {
		return nil
	}

	attestationPath := c.registryDir + "/" + user.ID + ".user-id"

	// Tier 2: Functional Integrity
	// We resolve and read the attestation file.
	// Note: We use GetInodeUnverified/ReadFile logic that bypasses the full verification
	// of the registry path components to avoid recursion, relying instead on
	// the fact that we can successfully decrypt the files (AEAD).
	inode, key, err := c.resolvePathInternal(ctx, attestationPath, true)
	if err != nil {
		return fmt.Errorf("failed to resolve registry entry for user %s: %w", user.ID, err)
	}

	rc, err := c.newReaderWithInode(ctx, inode, key, "")
	if err != nil {
		return fmt.Errorf("failed to read registry entry for user %s: %w", user.ID, err)
	}
	defer rc.Close()

	var entry DirectoryEntry
	if err := json.NewDecoder(rc).Decode(&entry); err != nil {
		return fmt.Errorf("failed to decode registry entry for user %s: %w", user.ID, err)
	}

	// Tier 3: Registry Cross-Check (Confirmation)
	// Fetch the verifier's keys OPTIMISTICALLY from the server.
	verifier, err := c.getUserUnverified(ctx, entry.VerifierID)
	if err != nil {
		return fmt.Errorf("failed to fetch optimistic verifier %s for user %s: %w", entry.VerifierID, user.ID, err)
	}

	vpk, err := crypto.UnmarshalIdentityPublicKey(verifier.SignKey)
	if err != nil {
		return fmt.Errorf("invalid verifier public key: %w", err)
	}

	if !vpk.Verify(entry.Hash(), entry.Signature) {
		return fmt.Errorf("high-severity: registry attestation signature invalid for user %s (verifier=%s)", user.ID, entry.VerifierID)
	}

	// Final comparison
	if !bytes.Equal(user.SignKey, entry.SignKey) {
		return fmt.Errorf("high-severity: user signing key hijacking detected for %s", user.ID)
	}
	if !bytes.Equal(user.EncKey, entry.EncKey) {
		return fmt.Errorf("high-severity: user encryption key hijacking detected for %s", user.ID)
	}

	return nil
}

// getUserUnverified fetches the user metadata skipping registry verification.
func (c *Client) getUserUnverified(ctx context.Context, id string) (*metadata.User, error) {
	return c.getUserRaw(ctx, id)
}

func (c *Client) getUser(ctx context.Context, id string) (*metadata.User, error) {
	return c.getUserInternal(ctx, id, false)
}

// GetQuota returns the current user's quota and usage.
func (c *Client) GetQuota(ctx context.Context) (metadata.UserQuota, metadata.UserUsage, error) {
	user, err := c.getUser(ctx, c.UserID())
	if err != nil {
		return metadata.UserQuota{}, metadata.UserUsage{}, err
	}
	return user.Quota, user.Usage, nil
}

func (c *Client) getUserRaw(ctx context.Context, id string) (*metadata.User, error) {
	var user metadata.User
	req := metadata.GetUserRequest{ID: id}
	data, _ := json.Marshal(req)
	_, _, err := c.doRequest(ctx, "GET", "/v1/user/"+id, data, requestOptions{action: metadata.ActionGetUser, unseal: true, retry: true}, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (c *Client) getUserInternal(ctx context.Context, id string, bypassCache bool) (*metadata.User, error) {
	// Phase 69: Root Owner Pinning Check (Fast Path to break circularity)
	c.rootMu.RLock()
	isRootOwner := id == c.rootOwner
	pinnedPK := c.rootOwnerPK
	pinnedEK := c.rootOwnerEK
	c.rootMu.RUnlock()

	if isRootOwner && len(pinnedPK) > 0 && !bypassCache {
		// If we only need the SignKey (for signature verification), the pinned version is enough.
		// However, pinning is CRITICAL to break circularity during ResolvePath(/registry/...).
		// We assume IsAdmin: true for the RootOwner because they are the cluster sovereign.
		return &metadata.User{
			ID:      id,
			SignKey: pinnedPK,
			EncKey:  pinnedEK,
			IsAdmin: true,
		}, nil
	}

	if !bypassCache {
		c.cacheMu.RLock()
		if u, ok := c.userCache[id]; ok {
			c.cacheMu.RUnlock()
			return u, nil
		}
		c.cacheMu.RUnlock()
	}

	user, err := c.getUserRaw(ctx, id)
	if err != nil {
		return nil, err
	}

	// Phase 69: Aggregate Optimistic Verification
	// If a verification queue is active, we return the optimistic (server-signed) user
	// and add it to the queue for deferred confirmation.
	if s, ok := ctx.Value(verificationStateKey).(*verificationState); ok {
		s.add(id)
		return user, nil
	}

	// Legacy/Immediate Path: MUST Verify the user against the registry
	if c.registryDir != "" {
		if err := c.verifyUser(ctx, user); err != nil {
			return nil, fmt.Errorf("user integrity check failed: %w", err)
		}
	}

	// Phase 69: Root Identity Pinning (TOFU)
	c.rootMu.Lock()
	if id == c.rootOwner {
		if len(c.rootOwnerPK) == 0 {
			c.rootOwnerPK = user.SignKey
			c.rootOwnerEK = user.EncKey
		} else if !bytes.Equal(c.rootOwnerPK, user.SignKey) {
			c.rootMu.Unlock()
			return nil, fmt.Errorf("ROOT IDENTITY MISMATCH: pinned public key for %s does not match server", id)
		}
	}
	c.rootMu.Unlock()

	c.cacheMu.Lock()
	c.userCache[id] = user
	c.cacheMu.Unlock()

	return user, nil
}

func (c *Client) signInode(ctx context.Context, inode *metadata.Inode) error {
	// 1. Resolve File Key for encryption
	fileKey := inode.GetFileKey()
	if len(fileKey) == 0 {
		c.keyMu.RLock()
		meta, ok := c.keyCache[inode.ID]
		c.keyMu.RUnlock()
		if ok {
			fileKey = meta.key
			inode.SetFileKey(fileKey)
		}
	}

	if len(fileKey) == 0 {
		return fmt.Errorf("signInode: file key not found for inode %s", inode.ID)
	}

	// 2. Set Authorization Metadata
	inode.SetSignerID(c.userID)
	inode.Mode = metadata.SanitizeMode(inode.Mode, inode.Type)

	// Phase 50.2 & 51.1: Owner Delegation Signature
	if c.userID == inode.OwnerID {
		if inode.GroupID != "" || inode.AccessACL != nil || inode.DefaultACL != nil {
			inode.OwnerDelegationSig = c.signKey.Sign(inode.DelegationHash())
		}
	}

	// 3. Group Selection (Determine signer BEFORE hashing)
	var groupKey *crypto.IdentityKey
	if c.userID != inode.OwnerID {
		var groups []string
		if inode.GroupID != "" && (inode.Mode&0020) != 0 {
			groups = append(groups, inode.GroupID)
		}
		if inode.AccessACL != nil {
			for gid, perms := range inode.AccessACL.Groups {
				if (perms & 2) != 0 {
					groups = append(groups, gid)
				}
			}
		}

		for _, gid := range groups {
			group, err := c.getGroupUnverifiedCached(ctx, gid)
			if err != nil {
				continue
			}
			gsk, err := c.getGroupSignKey(ctx, gid, group.Epoch)
			if err == nil {
				groupKey = gsk
				inode.GroupSignerID = gid
				break
			}
		}
	} else {
		// Owner can still sign with primary group if available
		if inode.GroupID != "" {
			group, err := c.getGroupUnverifiedCached(ctx, inode.GroupID)
			if err == nil {
				gsk, err := c.getGroupSignKey(ctx, inode.GroupID, group.Epoch)
				if err == nil {
					groupKey = gsk
					inode.GroupSignerID = inode.GroupID
				}
			}
		}
	}
	// 4. Prepare and Encrypt ClientBlob (Only once per update)
	// We check if it's already set to avoid re-encrypting with a new random nonce
	// which would invalidate the hash.
	if len(inode.ClientBlob) == 0 {
		blob := metadata.InodeClientBlob{
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

	// 5. Final Manifest Hash and Signatures
	hash := inode.ManifestHash()

	inode.UserSig = c.signKey.Sign(hash)
	if groupKey != nil {
		inode.GroupSig = groupKey.Sign(hash)
	} else {
		inode.GroupSig = nil
		inode.GroupSignerID = ""
		// Re-hash if we just cleared GroupSignerID, since it's included in ManifestHash
		hash = inode.ManifestHash()
		inode.UserSig = c.signKey.Sign(hash)
	}

	return nil
}

// createInode initializes a new inode.
func (c *Client) createInode(ctx context.Context, inode *metadata.Inode) (*metadata.Inode, error) {
	cmd, err := c.prepareCreate(ctx, inode)
	if err != nil {
		return nil, err
	}

	results, err := c.applyBatch(ctx, []metadata.LogCommand{cmd})
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("empty results from createInode batch")
	}

	if err := c.isResultError(results[0]); err != nil {
		return nil, err
	}

	var created metadata.Inode
	if err := json.Unmarshal(results[0], &created); err != nil {
		return nil, fmt.Errorf("failed to decode created inode: %w", err)
	}

	// Preserve transient fields
	created.SetFileKey(inode.GetFileKey())
	created.SetSymlinkTarget(inode.GetSymlinkTarget())
	created.SetInlineData(inode.GetInlineData())
	created.SetMTime(inode.GetMTime())
	created.SetUID(inode.GetUID())
	created.SetGID(inode.GetGID())

	// Phase 31: Root Anchoring
	if created.ID == c.rootID {
		c.rootMu.Lock()
		c.rootOwner = created.OwnerID
		c.rootVersion = created.Version
		c.rootMu.Unlock()
	}

	return &created, nil
}

// updateInode performs an atomic read-modify-write operation on an inode.
func (c *Client) updateInode(ctx context.Context, id string, fn InodeUpdateFunc) (*metadata.Inode, error) {
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
		cmd, err := c.prepareUpdate(ctx, inode)
		if err != nil {
			return nil, err
		}

		results, err := c.applyBatch(ctx, []metadata.LogCommand{cmd})
		if err != nil {
			if isConflict(err) {
				continue
			}
			return nil, err
		}
		if err == nil {
			if len(results) == 0 {
				return nil, fmt.Errorf("empty results from updateInode batch")
			}
			if err := c.isResultError(results[0]); err != nil {
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

			// Update Path Cache with the notarized inode from the server
			c.pathMu.Lock()
			for path, entry := range c.pathCache {
				if entry.inodeID == id {
					entry.inode = &updated
					c.pathCache[path] = entry
				}
			}
			c.pathMu.Unlock()

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

func (c *Client) applyBatch(ctx context.Context, cmds []metadata.LogCommand) ([]json.RawMessage, error) {
	for i := range cmds {
		if cmds[i].UserID == "" {
			cmds[i].UserID = c.userID
		}
	}

	data, err := json.Marshal(cmds)
	if err != nil {
		return nil, err
	}

	var results []json.RawMessage
	_, _, err = c.doRequest(ctx, "POST", "/v1/meta/batch", data, requestOptions{action: metadata.ActionBatch, sealed: true, unseal: true, retry: true, conflict: false}, &results)

	if err != nil {
		return nil, err
	}
	c.clearPathCache()
	return results, nil
}

func (c *Client) prepareCreate(ctx context.Context, inode *metadata.Inode) (metadata.LogCommand, error) {
	inode.ClientBlob = nil // Force re-encryption in signInode
	if err := c.signInode(ctx, inode); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(inode)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdCreateInode, Data: data, UserID: c.userID}, nil
}

func (c *Client) prepareUpdate(ctx context.Context, inode *metadata.Inode) (metadata.LogCommand, error) {
	inode.Version++        // Increment before signing
	inode.ClientBlob = nil // Force re-encryption in signInode
	if err := c.signInode(ctx, inode); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(inode)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdUpdateInode, Data: data, UserID: c.userID}, nil
}

// DeleteInode deletes an inode by ID. It performs an atomic update setting NLink to 0.
func (c *Client) deleteInode(ctx context.Context, id string) error {
	_, err := c.updateInode(ctx, id, func(i *metadata.Inode) error {
		i.NLink = 0
		return nil
	})
	return err
}

func (c *Client) getInode(ctx context.Context, id string) (*metadata.Inode, error) {
	return c.getInodeInternal(ctx, id, true)
}

func (c *Client) getInodeInternal(ctx context.Context, id string, verify bool) (*metadata.Inode, error) {
	ctx, state, created := withVerificationState(ctx)

	req := metadata.GetInodeRequest{ID: id}
	data, _ := json.Marshal(req)

	var inode metadata.Inode
	_, _, err := c.doRequest(ctx, "GET", "/v1/meta/inode/"+id, data, requestOptions{action: metadata.ActionGetInode, unseal: true, retry: true}, &inode)
	if err != nil {
		return nil, err
	}

	// Phase 31: Root Anchoring
	if id == c.rootID {
		c.rootMu.Lock()
		owner := c.rootOwner
		version := c.rootVersion

		if owner != "" && inode.OwnerID != owner {
			c.rootMu.Unlock()
			return nil, fmt.Errorf("ROOT COMPROMISE DETECTED: expected owner %s, got %s", owner, inode.OwnerID)
		}
		if version > 0 && inode.Version < version {
			c.rootMu.Unlock()
			return nil, fmt.Errorf("ROOT ROLLBACK DETECTED: expected version >= %d, got %d", version, inode.Version)
		}

		// Update anchor
		c.rootOwner = inode.OwnerID
		c.rootVersion = inode.Version
		needKeys := len(c.rootOwnerPK) == 0
		c.rootMu.Unlock()

		if needKeys {
			// TOFU: Capture owner's keys
			user, err := c.getUserInternal(ctx, inode.OwnerID, true)
			if err == nil {
				c.rootMu.Lock()
				c.rootOwnerPK = user.SignKey
				c.rootOwnerEK = user.EncKey
				c.rootMu.Unlock()
			}
		}
	}

	// Phase 31: Verification
	if verify {
		if err := c.verifyInode(ctx, &inode); err != nil {
			return nil, err
		}
	}

	// 1. Decrypt ClientBlob if present
	if len(inode.ClientBlob) > 0 {
		if fileKey, err := c.unlockInode(ctx, &inode); err == nil {
			inode.SetFileKey(fileKey)
			var blob metadata.InodeClientBlob
			if err := c.decryptInodeClientBlob(inode.ClientBlob, fileKey, &blob); err == nil {
				inode.SetSymlinkTarget(blob.SymlinkTarget)
				inode.SetInlineData(blob.InlineData)
				inode.SetMTime(blob.MTime)
				inode.SetUID(blob.UID)
				inode.SetGID(blob.GID)
			}
		}
	}

	if created {
		if err := c.processVerificationQueue(ctx, state); err != nil {
			return nil, fmt.Errorf("inode %s integrity check failed: %w", id, err)
		}
	}

	return &inode, nil
}

func (c *Client) getInodes(ctx context.Context, ids []string) ([]*metadata.Inode, error) {
	ctx, state, created := withVerificationState(ctx)

	if len(ids) == 0 {
		return nil, nil
	}

	var allInodes []*metadata.Inode
	const chunkSize = 1000

	for i := 0; i < len(ids); i += chunkSize {
		end := i + chunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunkIDs := ids[i:end]

		data, err := json.Marshal(chunkIDs)
		if err != nil {
			return nil, err
		}

		var chunkInodes []*metadata.Inode
		_, _, err = c.doRequest(ctx, "POST", "/v1/meta/inodes", data, requestOptions{action: metadata.ActionGetInodes, sealed: true, unseal: true, retry: true}, &chunkInodes)
		if err != nil {
			return nil, err
		}

		// Phase 31: Verification
		for _, inode := range chunkInodes {
			if err := c.verifyInode(ctx, inode); err != nil {
				return nil, fmt.Errorf("structural inconsistency: inode %s verification failed: %w", inode.ID, err)
			}

			// Decrypt FileKey if available so ClientBlob (Name) can be read
			if inode.Lockbox != nil {
				if fileKey, err := inode.Lockbox.GetFileKey(c.userID, c.decKey); err == nil {
					inode.SetFileKey(fileKey)
					c.keyMu.Lock()
					c.keyCache[inode.ID] = fileMetadata{
						key:     fileKey,
						groupID: inode.GroupID,
						inlined: inode.GetInlineData() != nil,
					}
					c.keyMu.Unlock()
				}
			}

			allInodes = append(allInodes, inode)
		}
	}

	if created {
		if err := c.processVerificationQueue(ctx, state); err != nil {
			return nil, fmt.Errorf("batch inode verification failed: %w", err)
		}
	}

	return allInodes, nil
}

func (c *Client) writeInodeContent(ctx context.Context, id string, nonce []byte, iType metadata.InodeType, fileKey []byte, r io.Reader, size int64, name string, encryptedName []byte, mode uint32, groupID string, parentID string, nameHMAC string, uid, gid uint32, accessACL *metadata.POSIXAccess) error {
	if r == nil {
		r = bytes.NewReader(nil)
	}

	var inode metadata.Inode
	// Try to get existing inode
	existing, err := c.getInode(ctx, id)
	if err == nil {
		inode = *existing
		// 2. Initialize Inode Lockbox
		// Phase 71: Use provisionRecipient for all entries.
		if inode.Lockbox == nil {
			inode.Lockbox = crypto.NewLockbox()
		}

		// A. Owner Access
		if err := c.provisionRecipient(ctx, inode.Lockbox, inode.OwnerID, fileKey, nil); err != nil {
			return err
		}

		// B. World Access
		if (mode & 0004) != 0 {
			if err := c.provisionRecipient(ctx, inode.Lockbox, metadata.WorldID, fileKey, nil); err != nil {
				// Non-fatal warning
				logger.Debugf("createInodeInternal: failed to provision world: %v", err)
			}
		}

		// C. Primary Group Access
		if groupID != "" && (mode&0060) != 0 {
			if err := c.provisionRecipient(ctx, inode.Lockbox, groupID, fileKey, nil); err != nil {
				// Non-fatal warning
				logger.Debugf("createInodeInternal: failed to provision primary group %s: %v", groupID, err)
			}
		}

		// D. ACL Access
		if inode.AccessACL != nil {
			for uid, bits := range inode.AccessACL.Users {
				if (bits & 4) != 0 {
					if err := c.provisionRecipient(ctx, inode.Lockbox, uid, fileKey, nil); err != nil {
						logger.Debugf("createInodeInternal: failed to provision ACL user %s: %v", uid, err)
					}
				}
			}
			for gid, bits := range inode.AccessACL.Groups {
				if (bits & 4) != 0 {
					if err := c.provisionRecipient(ctx, inode.Lockbox, gid, fileKey, nil); err != nil {
						logger.Debugf("createInodeInternal: failed to provision ACL group %s: %v", gid, err)
					}
				}
			}
		}

		if uid != 0 || gid != 0 {
			inode.SetUID(uid)
			inode.SetGID(gid)
		}
		inode.SetMTime(time.Now().UnixNano())
		inode.SetFileKey(fileKey)
	} else if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
		lb, err := c.createLockbox(ctx, fileKey, mode, c.userID, groupID, accessACL)
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
			Nonce:         nonce,
			Type:          iType,
			Links:         links,
			Mode:          mode,
			Size:          uint64(size),
			ChunkManifest: nil,
			Lockbox:       lb,
			OwnerID:       c.userID,
			GroupID:       groupID,
			AccessACL:     accessACL,
			CTime:         time.Now().UnixNano(),
			NLink:         1,
			Version:       1,
		}
		inode.SetUID(uid)
		inode.SetGID(gid)
		inode.SetMTime(time.Now().UnixNano())
		inode.SetFileKey(fileKey)
		created, err := c.createInode(ctx, &inode)
		if err != nil {
			return err
		}
		inode = *created
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
	updated, err := c.updateInode(ctx, id, func(i *metadata.Inode) error {
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

	// Phase 53.3: Cleanup orphans if metadata update failed
	if len(chunkEntries) > 0 {
		go c.cleanupChunks(ctx, id, chunkEntries)
	}

	return fmt.Errorf("writeInodeContent UpdateInode failed for %s: %w", id, err)
}

func (c *Client) uploadDataInternal(ctx context.Context, id string, fileKey []byte, r io.Reader, size int64) ([]byte, []metadata.ChunkEntry, error) {
	if size <= metadata.InlineLimit {
		inlineData, err := io.ReadAll(r)
		if err != nil {
			return nil, nil, err
		}
		return inlineData, nil, nil
	}

	type chunkResult struct {
		index uint64
		entry metadata.ChunkEntry
		err   error
	}

	resCh := make(chan chunkResult)
	var wg sync.WaitGroup
	var chunkIndex uint64
	var readErr error

	// Worker semaphore to limit concurrency
	workerSem := make(chan struct{}, 8)

	go func() {
		defer close(resCh)
		buf := make([]byte, crypto.ChunkSize)
		for {
			n, err := io.ReadFull(r, buf)
			if n > 0 {
				chunkData := make([]byte, n)
				copy(chunkData, buf[:n])
				idx := chunkIndex
				chunkIndex++

				wg.Add(1)
				go func(data []byte, i uint64) {
					defer wg.Done()
					workerSem <- struct{}{}
					defer func() { <-workerSem }()

					cid, ct, err := crypto.EncryptChunk(fileKey, data, i)
					if err != nil {
						resCh <- chunkResult{err: err}
						return
					}

					token, err := c.issueToken(ctx, id, []string{cid}, "W")
					if err != nil {
						resCh <- chunkResult{err: fmt.Errorf("token issue failed: %w", err)}
						return
					}
					nodes, err := c.allocateNodes(ctx)
					if err != nil {
						resCh <- chunkResult{err: fmt.Errorf("allocation failed: %w", err)}
						return
					}
					if err := c.uploadChunk(ctx, cid, ct, nodes, token); err != nil {
						resCh <- chunkResult{err: err}
						return
					}

					var nodeIDs []string
					for _, node := range nodes {
						nodeIDs = append(nodeIDs, node.ID)
					}
					resCh <- chunkResult{index: i, entry: metadata.ChunkEntry{ID: cid, Nodes: nodeIDs}}
				}(chunkData, idx)
			}
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			if err != nil {
				readErr = err
				break
			}
		}
		wg.Wait()
	}()

	results := make(map[uint64]metadata.ChunkEntry)
	var firstErr error
	var count uint64

	for res := range resCh {
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		results[res.index] = res.entry
		count++
	}

	if readErr != nil {
		return nil, nil, readErr
	}
	if firstErr != nil {
		return nil, nil, firstErr
	}

	var chunkEntries []metadata.ChunkEntry
	for i := uint64(0); i < chunkIndex; i++ {
		chunkEntries = append(chunkEntries, results[i])
	}

	return nil, chunkEntries, nil
}

// WriteFile writes a file. Returns the FileKey used.
func (c *Client) writeFile(ctx context.Context, id string, nonce []byte, r io.Reader, size int64, mode uint32) ([]byte, error) {
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
			if key, err := c.unlockInode(ctx, inode); err == nil {
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

	if err := c.writeInodeContent(ctx, id, nonce, metadata.FileType, fileKey, r, size, "", nil, mode, groupID, parentID, nameHMAC, 0, 0, nil); err != nil {
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

	lastChunkIdx   int64
	sequentialHits int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	onExpired func(id string, err error)
}

// NewReader creates a new FileReader for the given inode.
// The caller MUST call Close() on the returned reader to release resources and cancel background prefetching.
func (c *Client) newReader(ctx context.Context, id string, fileKey []byte) (*FileReader, error) {
	inode, err := c.getInode(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.newReaderWithInode(ctx, inode, fileKey, "")
}

// NewReaderWithInode creates a new FileReader from an already fetched Inode.
// If leaseNonce is empty, it will acquire a new shared usage lease.
func (c *Client) newReaderWithInode(ctx context.Context, inode *metadata.Inode, fileKey []byte, leaseNonce string) (*FileReader, error) {
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
		nonce = generateNonce()
		// POSIX compliance: acquire shared usage lease
		err := c.acquireLeases(ctx, []string{id}, 2*time.Minute, LeaseOptions{Type: metadata.LeaseShared, Nonce: nonce})
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
		lastChunkIdx:    -1,
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
	_ = r.client.releaseLeases(ctx, []string{r.inode.ID}, r.leaseNonce)
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
			err := r.client.acquireLeases(ctx, []string{id}, leaseDuration, LeaseOptions{Type: lType, Nonce: r.leaseNonce})
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
	return r.readInternal(p, false, 0)
}

func (r *FileReader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.readInternal(p, true, off)
}

func (r *FileReader) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = r.offset + offset
	case io.SeekEnd:
		newOffset = int64(r.inode.Size) + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newOffset < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	r.offset = newOffset
	return newOffset, nil
}

func (r *FileReader) readInternal(p []byte, isReadAt bool, off int64) (int, error) {
	currentOff := r.offset
	if isReadAt {
		currentOff = off
	}

	if currentOff >= int64(r.inode.Size) {
		return 0, io.EOF
	}

	remaining := int64(r.inode.Size) - currentOff
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	totalRead := 0
	chunkSize := int64(crypto.ChunkSize)

	for len(p) > 0 {
		chunkIdx := currentOff / chunkSize
		chunkOffset := currentOff % chunkSize

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
			// Phase 52.5: FUSE Pre-fetching Thresholds (Sequential Heuristic)
			if chunkIdx == r.lastChunkIdx+1 || chunkIdx == r.lastChunkIdx {
				if chunkIdx != r.lastChunkIdx {
					r.sequentialHits++
				}
			} else {
				r.sequentialHits = 0
			}
			r.lastChunkIdx = chunkIdx

			// Only trigger aggressive network pre-fetching if the last N reads were strictly sequential
			if r.sequentialHits >= 1 { // After reading 2 consecutive chunks
				for i := int64(1); i <= 3; i++ {
					r.triggerPrefetch(chunkIdx + i)
				}
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
						if updated, terr := r.client.getInode(r.ctx, inodeID); terr == nil {
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
		currentOff += int64(n)
		totalRead += n
		if !isReadAt {
			r.offset = currentOff
		}
	}
	return totalRead, nil
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
func (c *Client) readFile(ctx context.Context, id string, fileKey []byte) (io.ReadCloser, error) {
	return c.newReader(ctx, id, fileKey)
}

func (c *Client) OpenBlobRead(ctx context.Context, fullPath string) (io.ReadCloser, error) {
	// 1. Resolve path to Inode
	inode, key, err := c.resolvePath(ctx, fullPath)
	if err != nil {
		return nil, err
	}

	// 2. Open Reader
	rc, err := c.readFile(ctx, inode.ID, key)
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

func (c *Client) OpenBlobWrite(ctx context.Context, fullPath string) (io.WriteCloser, error) {
	return c.OpenBlobWriteWithLease(ctx, fullPath, "")
}

// OpenBlobWriteWithLease creates a writer for a blob.
// If leaseNonce is empty, it will acquire a new exclusive path lease.
func (c *Client) OpenBlobWriteWithLease(ctx context.Context, fullPath string, leaseNonce string) (io.WriteCloser, error) {
	// 1. Resolve Path and compute PathID
	dir, fileName := stdpath.Split(strings.TrimRight(fullPath, "/"))
	if dir == "" {
		dir = "/"
	}

	pInode, pKey, err := c.resolvePath(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve parent dir: %w", err)
	}

	mac := hmac.New(sha256.New, pKey)
	mac.Write([]byte(fileName))
	nameHMAC := hex.EncodeToString(mac.Sum(nil))
	parentID := pInode.ID
	groupID := pInode.GroupID

	pathID := "path:" + parentID + ":" + nameHMAC
	if fullPath == "/" {
		pathID = "path:root:" + c.rootID
	}

	var fileKey []byte
	var oldInodeID string

	if entry, exists := pInode.Children[nameHMAC]; exists {
		oldInodeID = entry.ID
		oldInode, _ := c.getInode(ctx, entry.ID)
		if oldInode != nil {
			fileKey, _ = c.unlockInode(ctx, oldInode)
		}
	}

	if fileKey == nil {
		fileKey = make([]byte, 32)
		rand.Read(fileKey)
	}

	// Always generate new ID for atomic swap via cryptographic commitment
	inodeNonce := make([]byte, 16)
	rand.Read(inodeNonce)
	newID := metadata.GenerateInodeID(c.userID, inodeNonce)

	// Phase 51.5: Default ACL Inheritance
	var accessACL *metadata.POSIXAccess
	if pInode.DefaultACL != nil {
		accessACL = &metadata.POSIXAccess{
			Users:  make(map[string]uint32),
			Groups: make(map[string]uint32),
		}
		for k, v := range pInode.DefaultACL.Users {
			accessACL.Users[k] = v
		}
		for k, v := range pInode.DefaultACL.Groups {
			accessACL.Groups[k] = v
		}
		if pInode.DefaultACL.Mask != nil {
			m := *pInode.DefaultACL.Mask
			accessACL.Mask = &m
		}
	}

	lb, err := c.createLockbox(ctx, fileKey, 0600, c.userID, groupID, accessACL)
	if err != nil {
		return nil, err
	}

	inode := &metadata.Inode{
		ID:        newID,
		Nonce:     inodeNonce,
		Type:      metadata.FileType,
		Mode:      0600,
		OwnerID:   c.userID,
		GroupID:   groupID,
		AccessACL: accessACL,
		// Links will be updated during commit
		Links:   map[string]bool{parentID + ":" + nameHMAC: true},
		Lockbox: lb,
		Version: 1,
	}
	inode.SetFileKey(fileKey)
	// Acquire lease first to prevent concurrent writers on this stdpath.
	nonce := leaseNonce
	if nonce == "" {
		nonce = generateNonce()
		err := c.withConflictRetry(ctx, func() error {
			return c.acquireLeases(ctx, []string{pathID}, 2*time.Minute, LeaseOptions{
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
		parentKey:  pKey,
		name:       fileName,
		nameHMAC:   nameHMAC,
		swapMode:   true,
		swapPath:   fullPath,
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
	onExpired  func(id string, err error)
	nodes      []metadata.Node
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
	if len(w.nodes) == 0 {
		nodes, err := w.client.allocateNodes(w.ctx)
		if err != nil {
			return err
		}
		w.nodes = nodes
	}

	if err := w.client.uploadChunk(w.ctx, cid, ct, w.nodes, token); err != nil {
		return err
	}
	var nodeIDs []string
	for _, node := range w.nodes {
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
			cmdNew, err := w.client.prepareCreate(w.ctx, &w.inode)
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
					parent.Children = make(map[string]metadata.ChildEntry)
				}
				encName, nameNonce, err := w.client.encryptEntryName(w.parentKey, w.name)
				if err != nil {
					return fmt.Errorf("failed to encrypt name: %w", err)
				}
				parent.Children[w.nameHMAC] = metadata.ChildEntry{
					ID:            w.inode.ID,
					EncryptedName: encName,
					Nonce:         nameNonce,
				}
				cmdParent, err := w.client.prepareUpdate(w.ctx, parent)
				if err != nil {
					return err
				}
				cmdParent.LeaseBindings = map[string]string{w.nameHMAC: w.pathID}
				cmds = append(cmds, cmdParent)
			}

			// 3. Optional: Unlink Old Inode (Decrement NLink)
			if w.oldInodeID != "" && w.oldInodeID != w.inode.ID {
				oldInode, err := w.client.getInode(w.ctx, w.oldInodeID)
				if err != nil {
					return fmt.Errorf("failed to fetch old inode for swap: %w", err)
				}
				if oldInode.NLink > 0 {
					oldInode.NLink--
				}
				// We update the old inode with NLink=0 (if it was 1).
				// If we don't have permission to sign the update, the batch will fail.
				// In DistFS, overwriting a file you don't own is only possible if you
				// have permission to modify its metadata.
				cmdOld, err := w.client.prepareUpdate(w.ctx, oldInode)
				if err != nil {
					return fmt.Errorf("failed to sign old inode for swap: %w", err)
				}
				cmds = append(cmds, cmdOld)
			}

			// Execute Atomic Batch
			_, err = w.client.applyBatch(w.ctx, cmds)
			return err
		})
	} else {
		if w.isNew {
			if w.parentID == "" {
				return fmt.Errorf("cannot link new file: parentID missing")
			}
			// 1. Create Inode
			_, err = w.client.createInode(w.ctx, &w.inode)
			if err != nil {
				return err
			}
			// 2. Link to Parent
			_, err = w.client.updateInode(w.ctx, w.parentID, func(p *metadata.Inode) error {
				if p.Children == nil {
					p.Children = make(map[string]metadata.ChildEntry)
				}
				// MERGE: Only add our entry
				encName, nameNonce, err := w.client.encryptEntryName(w.parentKey, w.name)
				if err != nil {
					return err
				}
				p.Children[w.nameHMAC] = metadata.ChildEntry{
					ID:            w.inode.ID,
					EncryptedName: encName,
					Nonce:         nameNonce,
				}
				return nil
			})
		} else {
			_, err = w.client.updateInode(w.ctx, w.inode.ID, func(i *metadata.Inode) error {
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
	if releaseErr := w.client.releaseLeases(w.ctx, []string{leaseTarget}, w.leaseNonce); releaseErr != nil {
		logger.Debugf("Warning: Failed to release lease for %s: %v", leaseTarget, releaseErr)
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
	w.client.releaseLeases(w.ctx, []string{leaseTarget}, w.leaseNonce)
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
			err := w.client.acquireLeases(ctx, []string{id}, leaseDuration, LeaseOptions{Type: lType, Nonce: w.leaseNonce})
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

// fetchChunk retrieves and decrypts a specific chunk of a file by index.
func (c *Client) fetchChunk(ctx context.Context, id string, key []byte, chunkIdx int64) ([]byte, error) {
	inode, err := c.getInode(ctx, id)
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

// downloadChunkData downloads and decrypts a single chunk from a set of node URLs.
func (c *Client) downloadChunkData(ctx context.Context, inodeID string, chunkID string, urls []string, key []byte, chunkIndex uint64) ([]byte, error) {
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

// uploadChunkData encrypts and uploads a single chunk to the cluster.
func (c *Client) uploadChunkData(ctx context.Context, id string, key []byte, chunkIndex uint64, data []byte) (metadata.ChunkEntry, error) {
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

// commitInodeManifest updates the chunk manifest and size of an inode.
func (c *Client) commitInodeManifest(ctx context.Context, id string, manifest []metadata.ChunkEntry, size uint64) (*metadata.Inode, error) {
	return c.updateInode(ctx, id, func(i *metadata.Inode) error {
		i.ChunkManifest = manifest
		i.Size = size
		i.SetInlineData(nil) // Ensure we are not inline if we have chunks
		return nil
	})
}

// syncFile synchronizes local dirty chunks to the cluster and updates the manifest.
func (c *Client) syncFile(ctx context.Context, id string, r io.ReaderAt, size int64, dirtyChunks map[int64]bool) (*metadata.Inode, error) {
	// 1. Get current inode state
	inode, err := c.getInode(ctx, id)
	if err != nil {
		return nil, err
	}

	key, err := c.unlockInode(ctx, inode)
	if err != nil {
		return nil, err
	}

	// 2. Handle Small File Inlining (Optimized Path)
	if size <= metadata.InlineLimit {
		buf := make([]byte, size)
		if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
			return nil, err
		}
		return c.updateInode(ctx, id, func(i *metadata.Inode) error {
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

	return c.updateInode(ctx, id, func(i *metadata.Inode) error {
		i.ChunkManifest = newManifest
		i.Size = uint64(size)
		i.SetInlineData(nil)
		return nil
	})
}

// ReadDataFile reads and unmarshals a single JSON data file.
func (c *Client) readDataFile(ctx context.Context, name string, data any) error {
	return c.readDataFiles(ctx, []string{name}, []any{data})
}

// ReadDataFiles reads and unmarshals multiple files atomically.
// It uses shared filename leases to ensure a consistent snapshot of the namespace.
func (c *Client) readDataFiles(ctx context.Context, names []string, targets []any) error {
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

// ClearCache clears all of the client's internal caches (keys, paths, nodes, and metadata).
func (c *Client) ClearCache() {
	c.keyMu.Lock()
	clear(c.keyCache)
	c.keyMu.Unlock()

	c.pathMu.Lock()
	clear(c.pathCache)
	c.pathMu.Unlock()

	c.ClearNodeCache()
	c.ClearMetadataCache()
}

// NewReaders returns a collection of Readers for the given paths, ensuring a consistent point-in-time snapshot.
func (c *Client) NewReaders(ctx context.Context, paths []string) ([]*FileReader, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	pathIDs := make([]string, len(paths))
	for i, path := range paths {
		pid, err := c.getPathID(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate path ID for %s: %w", path, err)
		}
		pathIDs[i] = pid
	}

	// 1. Acquire shared filename leases for all path IDs to "freeze" the namespace.
	nonce := generateNonce()
	lctx, lcancel := context.WithTimeout(ctx, 30*time.Second)
	err := c.withConflictRetry(lctx, func() error {
		return c.acquireLeases(lctx, pathIDs, 2*time.Minute, LeaseOptions{Type: metadata.LeaseShared, Nonce: nonce})
	})
	lcancel()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire namespace snapshot: %w", err)
	}
	defer c.releaseLeases(ctx, pathIDs, nonce)

	// Clear cache to ensure we see the state as of when leases were acquired
	c.ClearCache()

	// 2. Resolve all paths sequentially.
	ids := make([]string, len(paths))
	keys := make([][]byte, len(paths))
	for i, path := range paths {
		_, key, err := c.resolvePath(ctx, path)
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
	inodeNonce := generateNonce()
	err = c.acquireLeases(ctx, ids, 2*time.Minute, LeaseOptions{Type: metadata.LeaseShared, Nonce: inodeNonce})
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
			c.releaseLeases(ctx, ids, inodeNonce)
			return nil, fmt.Errorf("inode %s not found in batch fetch", id)
		}

		r, err := c.newReaderWithInode(ctx, inode, keys[i], inodeNonce)
		if err != nil {
			// Cleanup
			for j := 0; j < i; j++ {
				readers[j].Close()
			}
			c.releaseLeases(ctx, ids, inodeNonce)
			return nil, fmt.Errorf("failed to open %s: %w", paths[i], err)
		}
		readers[i] = r
	}

	return readers, nil
}

// SaveDataFile serializes data to JSON and performs an atomic write to the cluster.
func (c *Client) saveDataFile(ctx context.Context, name string, data any) error {
	return c.saveDataFiles(ctx, []string{name}, []any{data})
}

// SaveDataFiles writes multiple files atomically in a single Raft transaction.
func (c *Client) saveDataFiles(ctx context.Context, names []string, data []any) error {
	if len(names) != len(data) {
		return fmt.Errorf("names and data length mismatch")
	}

	pathIDs := make([]string, len(names))
	for i, name := range names {
		pid, err := c.getPathID(ctx, name)
		if err != nil {
			return fmt.Errorf("failed to calculate path ID for %s: %w", name, err)
		}
		pathIDs[i] = pid
	}

	// Phase 41: Batch acquire all path leases first to prevent livelock with readers.
	nonce := generateNonce()
	lctx, lcancel := context.WithTimeout(ctx, 30*time.Second)
	err := c.withConflictRetry(lctx, func() error {
		return c.acquireLeases(lctx, pathIDs, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce})
	})
	lcancel()
	if err != nil {
		return err
	}
	defer c.releaseLeases(ctx, pathIDs, nonce)

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
			cmdNew, err := c.prepareCreate(ctx, &w.inode)
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
					parent.Children = make(map[string]metadata.ChildEntry)
				}
				encName, nameNonce, err := c.encryptEntryName(w.parentKey, w.name)
				if err != nil {
					return err
				}
				parent.Children[w.nameHMAC] = metadata.ChildEntry{
					ID:            w.inode.ID,
					EncryptedName: encName,
					Nonce:         nameNonce,
				}

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
				cmdOld, err := c.prepareUpdate(ctx, oldInode)
				if err != nil {
					return err
				}
				allCmds = append(allCmds, cmdOld)
			}
		}

		// Add all parent updates to the batch
		for pid, parent := range parents {
			cmdParent, err := c.prepareUpdate(ctx, parent)
			if err != nil {
				return err
			}
			cmdParent.LeaseBindings = parentBindings[pid]
			allCmds = append(allCmds, cmdParent)
		}

		_, err := c.applyBatch(ctx, allCmds)
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

func (c *Client) openForUpdate(ctx context.Context, name string, data any) (func(bool), error) {
	return c.openManyForUpdate(ctx, []string{name}, []any{data})
}

func (c *Client) openManyForUpdate(ctx context.Context, names []string, data []any) (func(bool), error) {
	if len(names) != len(data) {
		return nil, fmt.Errorf("names and data length mismatch")
	}

	pathIDs := make([]string, len(names))
	for i, name := range names {
		pid, err := c.getPathID(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate path ID for %s: %w", name, err)
		}
		pathIDs[i] = pid
	}

	// 1. Acquire path-based exclusive leases for all files
	nonce := generateNonce()
	if err := c.acquireLeases(ctx, pathIDs, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce}); err != nil {
		return nil, err
	}

	// 2. Read all files
	for i, name := range names {
		if err := c.readDataFile(ctx, name, data[i]); err != nil {
			c.releaseLeases(ctx, pathIDs, nonce)
			return nil, err
		}
	}

	// 3. Return commit callback
	return func(commit bool) {
		if commit {
			if err := c.saveDataFiles(ctx, names, data); err != nil {
				logger.Debugf("Failed to save files during transactional update: %v", err)
			}
		}
		c.releaseLeases(ctx, pathIDs, nonce)
	}, nil
}

// GetInode fetches the inode metadata.

// InodeDump provides a safe, exported representation of an inode for administrative tools.
type InodeDump struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	Mode          uint32            `json:"mode"`
	Size          uint64            `json:"size"`
	OwnerID       string            `json:"owner_id"`
	GroupID       string            `json:"group_id"`
	Version       uint64            `json:"version"`
	SignerID      string            `json:"signer_id"`
	SymlinkTarget string            `json:"symlink_target,omitempty"`
	HasUserSig    bool              `json:"has_user_sig"`
	UserSigLen    int               `json:"user_sig_len"`
	UserSigPref   string            `json:"user_sig_pref,omitempty"`
	Links         []string          `json:"links"`
	NumChunks     int               `json:"num_chunks"`
	NumPages      int               `json:"num_pages"`
	InlineSize    int               `json:"inline_size"`
	Children      map[string]string `json:"children"` // HMAC -> ID
}

// AdminGetInodeDump fetches an inode and returns a safe dump representation.
func (c *Client) AdminGetInodeDump(ctx context.Context, id string) (*InodeDump, error) {
	inode, err := c.getInodeUnverified(ctx, id)
	if err != nil {
		return nil, err
	}

	dump := &InodeDump{
		ID:            inode.ID,
		Type:          string(inode.Type),
		Mode:          inode.Mode,
		Size:          inode.Size,
		OwnerID:       inode.OwnerID,
		GroupID:       inode.GroupID,
		Version:       inode.Version,
		SignerID:      inode.GetSignerID(),
		SymlinkTarget: inode.GetSymlinkTarget(),
		HasUserSig:    len(inode.UserSig) > 0,
		UserSigLen:    len(inode.UserSig),
		NumChunks:     len(inode.ChunkManifest),
		NumPages:      len(inode.ChunkPages),
		InlineSize:    len(inode.GetInlineData()),
		Children:      make(map[string]string),
	}

	if len(inode.UserSig) >= 8 {
		dump.UserSigPref = hex.EncodeToString(inode.UserSig[:8])
	}

	for tag := range inode.Links {
		dump.Links = append(dump.Links, tag)
	}

	for hmac, entry := range inode.Children {
		dump.Children[hmac] = entry.ID
	}

	return dump, nil
}

// GetUserVerificationCode returns a deterministic verification code for a user based on their public keys.
func (c *Client) GetUserVerificationCode(ctx context.Context, userID string) (string, error) {
	user, err := c.getUserUnverified(ctx, userID)
	if err != nil {
		return "", err
	}
	h := crypto.NewHash()
	h.Write(user.EncKey)
	h.Write(user.SignKey)
	codeBytes := h.Sum(nil)
	return fmt.Sprintf("%02X-%02X-%02X", codeBytes[0], codeBytes[1], codeBytes[2]), nil
}

// DumpInode returns a JSON representation of an inode for administrative debugging.
func (c *Client) DumpInode(ctx context.Context, id string) (string, error) {
	inode, err := c.getInodeUnverified(ctx, id)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(inode, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// EnsureFileKey ensures the client has the decryption key for the given stdpath.
func (c *Client) EnsureFileKey(ctx context.Context, fullPath string) error {
	inode, _, err := c.resolvePath(ctx, fullPath)
	if err != nil {
		return err
	}
	return c.verifyInode(ctx, inode)
}

// AdminGetUserInfo returns a JSON representation of a user for administrative debugging.
func (c *Client) AdminGetUserInfo(ctx context.Context, id string) (string, error) {
	user, err := c.getUserUnverified(ctx, id)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// AdminGetGroupInfo returns a JSON representation of a group for administrative debugging.
func (c *Client) AdminGetGroupInfo(ctx context.Context, id string) (string, error) {
	group, err := c.getGroupUnverifiedCached(ctx, id)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(group, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// AdminGetGroupMembers returns the list of group members.
func (c *Client) AdminGetGroupMembers(ctx context.Context, id string) (map[string]string, error) {
	members, err := c.AdminGetGroupMembersList(ctx, id)
	if err != nil {
		return nil, err
	}
	res := make(map[string]string)
	for _, m := range members {
		res[m.UserID] = m.Info
	}
	return res, nil
}

// AdminGetGroupMembersList returns the list of group members as raw entries.
func (c *Client) AdminGetGroupMembersList(ctx context.Context, id string) ([]metadata.MemberEntry, error) {
	var members []metadata.MemberEntry
	for m, err := range c.getGroupMembers(ctx, id) {
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, nil
}

// AdminGetGroup fetches raw group metadata.
func (c *Client) AdminGetGroup(ctx context.Context, id string) (*metadata.Group, error) {
	return c.getGroupUnverifiedCached(ctx, id)
}

// AdminGetServerSignKey returns the server's public signing key.
func (c *Client) AdminGetServerSignKey(ctx context.Context) ([]byte, error) {
	return c.getServerSignKey(ctx)
}

// getInodeUnverified retrieves inode metadata by ID without verifying its integrity signatures.
// Use this only for administrative tasks or when the decryption key is unavailable.
func (c *Client) getInodeUnverified(ctx context.Context, id string) (*metadata.Inode, error) {
	return c.getInodeInternal(ctx, id, false)
}

// GetInodes fetches metadata for multiple inodes in a single batch call.

// verifyInode verifies the manifest signatures and authorized signers.
func (c *Client) verifyInode(ctx context.Context, inode *metadata.Inode) error {
	// 1. Resolve File Key from Lockbox (Needed for both ClientBlob and Phase 67 Names)
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
		// 1. Try to unlock file key from lockbox (Personal Access)
		// We try this FIRST because it's the most common and fastest stdpath.
		if c.decKey != nil {
			key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
			if err == nil {
				fileKey = key
				inode.SetFileKey(key)
			}
		}

		if len(fileKey) == 0 {
			// 2. Trial Decryption via all recipients in the lockbox
			for recipientID := range inode.Lockbox {
				if recipientID == c.userID || recipientID == metadata.WorldID {
					continue
				}

				entry := inode.Lockbox[recipientID]

				// Try as a Group Recipient (Asymmetric)
				// Any recipient in an Inode Lockbox that isn't a User ID or World ID is likely a Group ID.
				// We check if we have access to this group.
				// getGroupPrivateKey internally handles checking if we are a member (via stable HMAC in the Group's lockbox).
				gdk, err := c.getGroupPrivateKey(ctx, recipientID, entry.Epoch)
				if err == nil {
					key, err := inode.Lockbox.GetFileKey(recipientID, gdk)
					if err == nil {
						fileKey = key
						inode.SetFileKey(key)
						break
					}
				}
			}
		}

		// 3. Try World Access
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

	// 2. Decrypt ClientBlob if present
	if len(inode.ClientBlob) > 0 {
		if len(fileKey) == 0 {
			// If we can't decrypt, we can't verify the full integrity.
			return fmt.Errorf("failed to decrypt file key for client blob: %w", crypto.ErrRecipientNotFound)
		}

		var blob metadata.InodeClientBlob
		if err := c.decryptInodeClientBlob(inode.ClientBlob, fileKey, &blob); err != nil {
			return fmt.Errorf("failed to decrypt client blob: %w", err)
		}

		// Populate transient fields
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

	// Phase 50.1: Cryptographic ID Commitment
	if inode.ID != metadata.RootID {
		if len(inode.Nonce) != metadata.NonceLength {
			return fmt.Errorf("invalid cryptographic nonce length for inode %s: expected %d, got %d", inode.ID, metadata.NonceLength, len(inode.Nonce))
		}
		expectedID := metadata.GenerateInodeID(inode.OwnerID, inode.Nonce)
		if inode.ID != expectedID {
			return fmt.Errorf("inode ID commitment mismatch for %s: expected %s", inode.ID, expectedID)
		}
	}

	// 2. Verify Signatures
	hash := inode.ManifestHash()
	var signKey []byte

	if inode.ID == c.rootID {
		c.rootMu.RLock()
		owner := c.rootOwner
		pk := c.rootOwnerPK
		c.rootMu.RUnlock()

		if owner != "" && signerID != owner {
			return fmt.Errorf("root inode integrity violation: signer %s is not the sovereign owner %s", signerID, owner)
		}
		signKey = pk
	}

	// Fetch signer metadata OPTIMISTICALLY from the server.
	signer, err := c.getUserUnverified(ctx, signerID)
	if err != nil {
		return fmt.Errorf("failed to fetch optimistic signer %s for inode %s: %w", signerID, inode.ID, err)
	}

	if len(signKey) == 0 {
		signKey = signer.SignKey
	}

	if !crypto.VerifySignature(signKey, hash, inode.UserSig) {
		return fmt.Errorf("invalid manifest signature by %s", signerID)
	}

	// Queue signer for deferred registry verification
	if s, ok := ctx.Value(verificationStateKey).(*verificationState); ok {
		s.add(signerID)
	}

	groupSigValid := false
	if len(inode.GroupSig) > 0 {
		signerGID := inode.GroupSignerID
		if signerGID == "" {
			signerGID = inode.GroupID
		}
		if signerGID != "" {
			group, err := c.getGroupUnverifiedCached(ctx, signerGID)
			if err != nil {
				return fmt.Errorf("failed to fetch optimistic group %s for inode %s: %w", signerGID, inode.ID, err)
			}

			if crypto.VerifySignature(group.SignKey, hash, inode.GroupSig) {
				groupSigValid = true
			} else {
				// The group key may have rotated since this inode was signed.
				// Check historical signing keys.
				usedHistorical := false
				for _, oldSignKey := range group.HistoricalSignKeys {
					if crypto.VerifySignature(oldSignKey, hash, inode.GroupSig) {
						usedHistorical = true
						break
					}
				}

				if usedHistorical {
					// Option A: Trust the Server for Timeline Notarization
					// If the GroupSig used a historical key, it MUST be notarized by the server
					// via ClusterSig to prove it was submitted before the key was revoked.
					if len(inode.ClusterSig) > 0 {
						csk, err := c.getClusterSignKey(ctx)
						if err == nil && csk != nil && crypto.VerifySignature(csk, hash, inode.ClusterSig) {
							groupSigValid = true
						}
					}
				}
			}

			// Queue group for deferred registry verification
			if s, ok := ctx.Value(verificationStateKey).(*verificationState); ok {
				s.add(signerGID)
			}
		}
	}

	// 3. Check Authorization
	authorized := false
	if signerID == inode.OwnerID {
		authorized = true
	} else {
		// Non-Owner Authorization
		// Check A: Valid Group Signature
		if groupSigValid {
			// We already verified the signature against the group's sign key above.
			// This proves someone with the group key (member/manager) authorized this.
			authorized = true
		}

		// Check B: User is a member/owner of the authorized group
		if !authorized {
			// If no GroupSig, check if the signer themselves is authorized via membership.
			// 1. Check Primary Group
			if inode.GroupID != "" && (inode.Mode&0020) != 0 {
				inGroup, err := c.IsUserInGroup(ctx, signerID, inode.GroupID)
				if err == nil && inGroup {
					authorized = true
				}
			}
			// 2. Check ACLs
			if !authorized && inode.AccessACL != nil {
				// Named User
				if perms, ok := inode.AccessACL.Users[signerID]; ok && (perms&2) != 0 {
					authorized = true
				}
				// Named Group
				if !authorized && inode.AccessACL.Groups != nil {
					for gid, perms := range inode.AccessACL.Groups {
						if (perms & 2) != 0 {
							inGroup, err := c.IsUserInGroup(ctx, signerID, gid)
							if err == nil && inGroup {
								authorized = true
								break
							}
						}
					}
				}
			}
		}
	}

	if authorized && signerID != inode.OwnerID {
		// Phase 50.3 & 51.1: Strict Verification Engine
		// Any delegation of write authority (Primary Group, ACL, etc) MUST be backed by the Owner's signature over the delegation state.
		if len(inode.OwnerDelegationSig) == 0 {
			return fmt.Errorf("missing owner delegation signature on inode %s", inode.ID)
		}

		// Verify delegation signature using unverified owner key (deferred verification added below)
		owner, err := c.getUserUnverified(ctx, inode.OwnerID)
		if err != nil {
			return fmt.Errorf("failed to fetch optimistic owner %s for delegation check: %w", inode.OwnerID, err)
		}
		if !crypto.VerifySignature(owner.SignKey, inode.DelegationHash(), inode.OwnerDelegationSig) {
			return fmt.Errorf("invalid owner delegation signature on inode %s", inode.ID)
		}
		// Ensure owner is also queued for verification
		if s, ok := ctx.Value(verificationStateKey).(*verificationState); ok {
			s.add(inode.OwnerID)
		}
	}

	if !authorized {
		// Admin Bypass for mkdir --owner:
		// If signer is an admin, they are authorized to sign empty directories
		// (this is for initial administrative setup/provisioning).
		if signer.IsAdmin && inode.Type == metadata.DirType && len(inode.Children) == 0 {
			authorized = true
		}
	}

	if !authorized {
		return fmt.Errorf("signer %s is not authorized for inode %s", signerID, inode.ID)
	}

	return nil
}

// provisionRecipient adds a recipient to a lockbox, automatically handling
// identity types, key fetching, and Phase 71 HMAC privacy.
// If groupContext is provided, it assumes the lockbox is for Group Membership (Phase 71 anonymity).
// If groupContext is nil, it assumes an Inode Lockbox (standard POSIX access).
func (c *Client) provisionRecipient(ctx context.Context, lb crypto.Lockbox, recipientID string, payload []byte, groupContext *metadata.Group) error {
	// 1. World Access
	if recipientID == metadata.WorldID {
		wpk, err := c.getWorldPublicKey(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch world public key: %w", err)
		}
		return lb.AddRecipient(metadata.WorldID, wpk, payload, 0)
	}

	// 2. Group Membership Context (Phase 71 Anonymity)
	if groupContext != nil {
		// Use HMAC for the recipient key
		target := c.computeMemberHMAC(groupContext.ID, recipientID)

		// For Group Lockboxes, the payload is usually the Epoch Seed
		user, err := c.getUserUnverified(ctx, recipientID)
		if err == nil {
			upk, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
			if err != nil {
				return err
			}
			return lb.AddRecipient(target, upk, payload, groupContext.Epoch)
		}

		// Recipient might be a Group (Hierarchical Ownership)
		group, err := c.getGroupUnverifiedCached(ctx, recipientID)
		if err == nil {
			upk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
			if err != nil {
				return err
			}
			return lb.AddRecipient(target, upk, payload, groupContext.Epoch)
		}

		return fmt.Errorf("failed to fetch member %s for group lockbox: %w", recipientID, err)
	}
	// 3. Inode Access Context (Standard POSIX)
	// In an Inode lockbox, we use the literal UserID or GroupID as the recipient key
	// so that they are discoverable during trial decryption.

	// 2a. Special: World Access
	if recipientID == metadata.WorldID {
		wpk, err := c.getWorldPublicKey(ctx)
		if err != nil {
			return err
		}
		return lb.AddRecipient(metadata.WorldID, wpk, payload, 0)
	}

	// 3b. Try as User
	user, err := c.getUserUnverified(ctx, recipientID)
	if err == nil {
		upk, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
		if err != nil {
			return fmt.Errorf("invalid user encryption key for %s: %w", recipientID, err)
		}
		return lb.AddRecipient(recipientID, upk, payload, 0)
	}

	// 3c. Try as Group (Asymmetric Encryption using Group Public Key)
	group, err := c.getGroupUnverifiedCached(ctx, recipientID)
	if err == nil {
		gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
		if err != nil {
			return fmt.Errorf("invalid group encryption key for %s: %w", recipientID, err)
		}
		// We encrypt against the group's public key.
		// We store the group's current Epoch so members know which key to derive to decrypt it.
		return lb.AddRecipient(recipientID, gpk, payload, group.Epoch)
	}

	return fmt.Errorf("failed to provision recipient %s: not found as user or group", recipientID)
}

// unlockInode attempts to decrypt the file key for the inode using the client's identity.
// It performs a trial decryption across Personal, Group, and World access entries.
func (c *Client) unlockInode(ctx context.Context, inode *metadata.Inode) ([]byte, error) {
	// 1. Integrity Check & Signature Verification
	if err := c.verifyInode(ctx, inode); err != nil {
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}

	// 2. Check if already unlocked (populated by verifyInode/ClientBlob decryption)
	if key := inode.GetFileKey(); len(key) > 0 {
		c.updateKeyCache(inode, key)
		return key, nil
	}

	if c.decKey == nil {
		return nil, fmt.Errorf("client has no identity to unlock file")
	}

	var lastErr error

	// A. Try Personal Access (Asymmetric)
	key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
	if err == nil {
		c.updateKeyCache(inode, key)
		return key, nil
	}
	lastErr = err

	// B. Try Group Access
	// Build unique list of groups to try from GroupID and ACLs
	gids := make(map[string]bool)
	if inode.GroupID != "" {
		gids[inode.GroupID] = true
	}
	if inode.AccessACL != nil {
		for gid := range inode.AccessACL.Groups {
			gids[gid] = true
		}
	}

	for gid := range gids {
		// 1. Try via Group ID (Asymmetric - provisioned by Admin or other non-members)
		if entry, exists := inode.Lockbox[gid]; exists {
			gdk, err := c.getGroupPrivateKey(ctx, gid, entry.Epoch)
			if err == nil {
				key, err = inode.Lockbox.GetFileKey(gid, gdk)
				if err == nil {
					c.updateKeyCache(inode, key)
					return key, nil
				}
				lastErr = err
			}
		}

		// 2. Try via Member HMAC (Phase 71 - provisioned by a group manager)
		// MUST fetch fresh group metadata to avoid stale SignKey
		group, err := c.getGroup(ctx, gid)
		if err == nil {
			target := c.computeMemberHMAC(group.ID, c.userID)
			if entry, exists := inode.Lockbox[target]; exists {
				gdk, err := c.getGroupPrivateKey(ctx, gid, entry.Epoch)
				if err == nil {
					key, err = inode.Lockbox.GetFileKey(target, gdk)
					if err == nil {
						c.updateKeyCache(inode, key)
						return key, nil
					}
					lastErr = err
				}
			}
		}
	}

	// C. Try World Access
	if _, exists := inode.Lockbox[metadata.WorldID]; exists {
		wk, err := c.GetWorldPrivateKey(ctx)
		if err == nil {
			key, err = inode.Lockbox.GetFileKey(metadata.WorldID, wk)
			if err == nil {
				c.updateKeyCache(inode, key)
				return key, nil
			}
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("access denied: no applicable recipient in lockbox")
	}
	return nil, lastErr
}

func (c *Client) updateKeyCache(inode *metadata.Inode, key []byte) {
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
}

// getGroupPrivateKey retrieves the group private key by deriving it from the epoch seed.
func (c *Client) getGroupPrivateKey(ctx context.Context, groupID string, epoch uint32) (*mlkem.DecapsulationKey768, error) {
	cacheKey := groupKeyCacheID{id: groupID, epoch: epoch}
	c.keyMu.RLock()
	gk, ok := c.groupKeys[cacheKey]
	c.keyMu.RUnlock()
	if ok {
		return gk, nil
	}

	group, err := c.getGroupUnverifiedCached(ctx, groupID)
	if err != nil {
		return nil, err
	}

	epochSeed, err := c.getGroupEpochSeedFromGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current epoch seed for group %s: %w", groupID, err)
	}

	if epoch > group.Epoch {
		return nil, fmt.Errorf("requested epoch %d is in the future (current: %d)", epoch, group.Epoch)
	}

	// 2. Ratchet backwards if necessary
	targetSeed := epochSeed
	for i := group.Epoch; i > epoch; i-- {
		targetSeed = crypto.DerivePreviousEpochKey(targetSeed)
	}

	keys, err := crypto.DeriveGroupKeys(targetSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys from ratcheted seed: %w", err)
	}

	c.keyMu.Lock()
	c.groupKeys[cacheKey] = keys.EncKey
	c.groupSignKeys[cacheKey] = keys.SignKey
	c.keyMu.Unlock()
	return keys.EncKey, nil
}

// getGroupSignKey retrieves the group signing key by deriving it from the epoch seed.
func (c *Client) getGroupSignKey(ctx context.Context, groupID string, epoch uint32) (*crypto.IdentityKey, error) {
	cacheKey := groupKeyCacheID{id: groupID, epoch: epoch}
	c.keyMu.RLock()
	gk, ok := c.groupSignKeys[cacheKey]
	c.keyMu.RUnlock()
	if ok {
		return gk, nil
	}

	_, err := c.getGroupPrivateKey(ctx, groupID, epoch)
	if err != nil {
		return nil, err
	}

	c.keyMu.RLock()
	gk = c.groupSignKeys[cacheKey]
	c.keyMu.RUnlock()
	return gk, nil
}

// getWorldPublicKey fetches the cluster's world public key.
func (c *Client) getWorldPublicKey(ctx context.Context) (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	wp := c.worldPublic
	c.keyMu.RUnlock()
	if wp != nil {
		return wp, nil
	}

	bodyRC, _, err := c.doRequest(ctx, "GET", "/v1/meta/key/world", nil, requestOptions{sealed: true, unseal: true, retry: true}, nil)
	if err != nil {
		return nil, err
	}
	defer bodyRC.Close()

	keyBytes, err := io.ReadAll(bodyRC)
	if err != nil {
		return nil, err
	}

	pk, err := crypto.UnmarshalEncapsulationKey(keyBytes)
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

	bodyRC, _, err := c.doRequest(ctx, "GET", "/v1/meta/key/world/private", nil, requestOptions{action: metadata.ActionGetWorldPrivate, unseal: true, retry: true}, nil)
	if err != nil {
		return nil, err
	}
	defer bodyRC.Close()

	var data struct {
		KEM string `json:"kem"`
		DEM string `json:"dem"`
	}
	if err := json.NewDecoder(bodyRC).Decode(&data); err != nil {
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

// IsUserInGroup checks if a user is a member or owner of a group.
func (c *Client) IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error) {
	group, err := c.getGroupUnverifiedCached(ctx, groupID)
	if err != nil {
		return false, err
	}

	// Queue group for deferred registry verification if we are in a verification context
	if s, ok := ctx.Value(verificationStateKey).(*verificationState); ok {
		s.add(groupID)
	}

	if group.OwnerID == userID {
		return true, nil
	}

	if _, ok := group.Lockbox[userID]; ok {
		return true, nil
	}

	return false, nil
}

// getGroup fetches the group metadata and fully verifies its registry attestation.
// This must be used for any operation requiring trust (e.g., sharing, checking ownership).
func (c *Client) getGroup(ctx context.Context, id string) (*metadata.Group, error) {
	return c.getGroupInternal(ctx, id, false)
}

func (c *Client) getGroupInternal(ctx context.Context, id string, bypassCache bool) (*metadata.Group, error) {
	if !bypassCache {
		c.cacheMu.RLock()
		if g, ok := c.verifiedGroupCache[id]; ok {
			c.cacheMu.RUnlock()
			return g, nil
		}
		c.cacheMu.RUnlock()
	}

	// Fetch raw group
	group, err := c.getGroupRaw(ctx, id)
	if err != nil {
		return nil, err
	}

	// Phase 69: Aggregate Optimistic Verification
	if s, ok := ctx.Value(verificationStateKey).(*verificationState); ok {
		s.add(id)
		// We store in unverified cache so decryptGroupKey can find it
		c.cacheMu.Lock()
		c.unverifiedGroupCache[id] = group
		c.cacheMu.Unlock()
		return group, nil
	}

	// MUST Verify the group against the registry
	if err := c.verifyGroup(ctx, group); err != nil {
		return nil, fmt.Errorf("group integrity check failed: %w", err)
	}

	// 1. Decrypt ClientBlob if present
	if len(group.ClientBlob) > 0 {
		gk, err := c.getGroupPrivateKey(ctx, group.ID, group.Epoch) // Safe to use unverified for read
		if err == nil {
			var blob metadata.GroupClientBlob
			if err := c.decryptClientBlob(group.ClientBlob, gk, &blob); err == nil {
				group.SetName(blob.Name)
			}
		}
	}

	// Cache in verified cache
	c.cacheMu.Lock()
	c.verifiedGroupCache[id] = group
	// Remove from unverified cache if it was there
	delete(c.unverifiedGroupCache, id)
	c.cacheMu.Unlock()

	return group, nil
}

// getGroupUnverified fetches the group metadata skipping cache and VERIFICATION.
// Useful for integrity verification tests or initial bootstrap anchoring.

// getGroupUnverifiedCached fetches a group from the unverified (or verified) cache,
// falling back to the server if necessary. It DOES NOT verify the group.
func (c *Client) getGroupUnverifiedCached(ctx context.Context, id string) (*metadata.Group, error) {
	c.cacheMu.RLock()
	if g, ok := c.verifiedGroupCache[id]; ok {
		c.cacheMu.RUnlock()
		return g, nil
	}
	if g, ok := c.unverifiedGroupCache[id]; ok {
		c.cacheMu.RUnlock()
		return g, nil
	}
	c.cacheMu.RUnlock()

	group, err := c.getGroupRaw(ctx, id)
	if err != nil {
		return nil, err
	}

	c.cacheMu.Lock()
	c.unverifiedGroupCache[id] = group
	c.cacheMu.Unlock()

	return group, nil
}

func (c *Client) getGroupRaw(ctx context.Context, id string) (*metadata.Group, error) {
	var group metadata.Group
	req := metadata.GetGroupRequest{ID: id}
	data, _ := json.Marshal(req)
	_, _, err := c.doRequest(ctx, "GET", "/v1/group/"+id, data, requestOptions{action: metadata.ActionGetGroup, unseal: true, retry: true}, &group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// verifyGroup verifies the group metadata signature and cross-checks it against the registry attestation.
func (c *Client) verifyGroup(ctx context.Context, group *metadata.Group) error {
	if group.Signature == nil {
		return fmt.Errorf("missing group signature")
	}

	// 1. Verify ML-DSA Signature on Group Metadata (Tier 1: Server Authenticity)
	// We fetch the signer's metadata OPTIMISTICALLY from the server.
	signer, err := c.getUserUnverified(ctx, group.SignerID)
	if err != nil {
		return fmt.Errorf("failed to fetch optimistic signer %s for group %s: %w", group.SignerID, group.ID, err)
	}

	spk, err := crypto.UnmarshalIdentityPublicKey(signer.SignKey)
	if err != nil {
		return fmt.Errorf("invalid signer public key: %w", err)
	}

	if !spk.Verify(group.Hash(), group.Signature) {
		return fmt.Errorf("high-severity: invalid group signature for group %s (signer=%s)", group.ID, group.SignerID)
	}

	if c.registryDir == "" {
		return nil // Non-registry mode trusts server authenticity
	}

	// 2. Fetch and Verify Registry Attestation for the Group (Tier 3: Confirmation)
	idPath := c.registryDir + "/" + group.ID + ".group-id"
	attestationInode, attestationKey, err := c.resolvePathInternal(ctx, idPath, true)
	if err != nil {
		return fmt.Errorf("failed to resolve registry attestation for group %s: %w", group.ID, err)
	}

	attestationRC, err := c.newReaderWithInode(ctx, attestationInode, attestationKey, "")
	if err != nil {
		return fmt.Errorf("failed to fetch registry attestation for group %s: %w", group.ID, err)
	}
	defer attestationRC.Close()

	var entry GroupDirectoryEntry
	if err := json.NewDecoder(attestationRC).Decode(&entry); err != nil {
		return fmt.Errorf("failed to decode registry entry for group %s: %w", group.ID, err)
	}

	// Verify attestation signature using verifier key OPTIMISTICALLY from server
	verifier, err := c.getUserUnverified(ctx, entry.VerifierID)
	if err != nil {
		return fmt.Errorf("failed to fetch optimistic verifier %s for group %s: %w", entry.VerifierID, group.ID, err)
	}

	vpk, err := crypto.UnmarshalIdentityPublicKey(verifier.SignKey)
	if err != nil {
		return fmt.Errorf("invalid verifier public key: %w", err)
	}

	if !vpk.Verify(entry.Hash(), entry.Attestation) {
		return fmt.Errorf("high-severity: registry attestation signature invalid for group %s (verifier=%s)", group.ID, entry.VerifierID)
	}

	// Cross-check keys against Tier 1
	if !bytes.Equal(group.EncKey, entry.EncKey) {
		return fmt.Errorf("high-severity: group encryption key hijacking detected for %s", group.ID)
	}
	if !bytes.Equal(group.SignKey, entry.SignKey) {
		return fmt.Errorf("high-severity: group signing key hijacking detected for %s", group.ID)
	}

	// 3. Cache Promotion (Tier 4)
	c.cacheMu.Lock()
	c.verifiedGroupCache[group.ID] = group
	delete(c.unverifiedGroupCache, group.ID)
	c.cacheMu.Unlock()

	// Phase 69.7: Cryptographic ID Commitment
	if len(group.Nonce) != metadata.NonceLength {
		return fmt.Errorf("invalid cryptographic nonce length for group %s: expected %d, got %d", group.ID, metadata.NonceLength, len(group.Nonce))
	}
	expectedID := metadata.GenerateGroupID(group.OwnerID, group.Nonce)
	if group.ID != expectedID {
		return fmt.Errorf("group ID commitment mismatch for %s: expected %s (owner=%s)", group.ID, expectedID, group.OwnerID)
	}

	return nil
}

// getGroupName retrieves and decrypts the human-readable name of a group.
func (c *Client) getGroupName(ctx context.Context, group *metadata.Group) (string, error) {
	gk, err := c.getGroupPrivateKey(ctx, group.ID, group.Epoch)
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
func (c *Client) AdminDecryptGroupName(ctx context.Context, entry metadata.GroupListEntry) (string, error) {
	// 1. Get Group Private Key (asymmetric)
	gdk, err := c.getGroupPrivateKey(ctx, entry.ID, entry.Epoch)
	if err != nil {
		// If we can't get the group key directly from cache/server,
		// try to bootstrap it from the list entry itself if we have access.
		g := &metadata.Group{
			ID:               entry.ID,
			Lockbox:          entry.Lockbox,
			AnonymousLockbox: entry.AnonymousLockbox,
			Epoch:            entry.Epoch,
		}
		seed, serr := c.getGroupEpochSeedFromGroup(ctx, g)
		if serr == nil {
			keys, kerr := crypto.DeriveGroupKeys(seed)
			if kerr == nil {
				gdk = keys.EncKey
				// Cache it
				cacheKey := groupKeyCacheID{id: entry.ID, epoch: entry.Epoch}
				c.keyMu.Lock()
				c.groupKeys[cacheKey] = gdk
				c.keyMu.Unlock()
			}
		}
	}

	if gdk == nil {
		return "", fmt.Errorf("failed to obtain group private key for name decryption")
	}

	if len(entry.ClientBlob) > 0 {
		var blob metadata.GroupClientBlob
		if err := c.decryptClientBlob(entry.ClientBlob, gdk, &blob); err == nil {
			return blob.Name, nil
		}
	}

	return "", fmt.Errorf("failed to decrypt group name: client blob missing or invalid")
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
		if entry, exists := group.RegistryLockbox[group.OwnerID]; exists {
			gk, gerr := c.getGroupPrivateKey(ctx, group.OwnerID, entry.Epoch)
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
func (c *Client) createGroup(ctx context.Context, name string, quotaEnabled bool) (*metadata.Group, error) {
	return c.createGroupInternal(ctx, name, false, quotaEnabled, "")
}

// CreateSystemGroup creates a new system group (Admin only).
func (c *Client) createSystemGroup(ctx context.Context, name string, quotaEnabled bool) (*metadata.Group, error) {
	return c.createGroupInternal(ctx, name, true, quotaEnabled, "")
}

// CreateGroupWithOptions creates a new group with specified owner and flags.
// GroupInfo provides a safe, exported representation of a group's metadata.
type GroupInfo struct {
	ID           string
	GID          uint32
	OwnerID      string
	QuotaEnabled bool
}

// CreateGroup creates a new self-owned group for the current user.
func (c *Client) CreateGroup(ctx context.Context, name string, quotaEnabled bool) (*GroupInfo, error) {
	g, err := c.createGroupWithOptions(ctx, name, quotaEnabled, metadata.SelfOwnedGroup)
	if err != nil {
		return nil, err
	}
	return &GroupInfo{ID: g.ID, GID: g.GID, OwnerID: g.OwnerID, QuotaEnabled: g.QuotaEnabled}, nil
}

// CreateSystemGroup creates a new system group (Admin only).
func (c *Client) CreateSystemGroup(ctx context.Context, name string, quotaEnabled bool) (*GroupInfo, error) {
	g, err := c.createGroupInternal(ctx, name, true, quotaEnabled, metadata.SelfOwnedGroup)
	if err != nil {
		return nil, err
	}
	return &GroupInfo{ID: g.ID, GID: g.GID, OwnerID: g.OwnerID, QuotaEnabled: g.QuotaEnabled}, nil
}

// CreateGroupWithOptions creates a new group with a specified owner.
func (c *Client) CreateGroupWithOptions(ctx context.Context, name string, quotaEnabled bool, ownerID string) (*GroupInfo, error) {
	g, err := c.createGroupWithOptions(ctx, name, quotaEnabled, ownerID)
	if err != nil {
		return nil, err
	}
	return &GroupInfo{ID: g.ID, GID: g.GID, OwnerID: g.OwnerID, QuotaEnabled: g.QuotaEnabled}, nil
}

func (c *Client) createGroupWithOptions(ctx context.Context, name string, quotaEnabled bool, ownerID string) (*metadata.Group, error) {
	return c.createGroupInternal(ctx, name, false, quotaEnabled, ownerID)
}

func (c *Client) allocateGID(ctx context.Context) (uint32, error) {
	var res struct {
		GID uint32 `json:"gid"`
	}
	_, _, err := c.doRequest(ctx, "GET", "/v1/group/gid/allocate", nil, requestOptions{action: metadata.ActionAllocateGID, unseal: true, retry: true}, &res)
	return res.GID, err
}

// AnchorClusterInRegistry writes the current cluster topology to the registry.
func (c *Client) AnchorClusterInRegistry(ctx context.Context) error {
	regDir := c.registryDir
	if regDir == "" {
		return nil // Registry not configured
	}

	var clusterNodes []metadata.ClusterNode
	for n := range c.AdminListNodes(ctx) {
		if n.Status == metadata.NodeStatusActive && n.RaftAddress != "" {
			clusterNodes = append(clusterNodes, metadata.ClusterNode{
				ID:      n.ID,
				Address: n.Address,
			})
		}
	}

	if len(clusterNodes) == 0 {
		return fmt.Errorf("no active nodes found to anchor")
	}

	cfg := metadata.ClusterConfig{
		Nodes: clusterNodes,
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")

	path := regDir + "/cluster.json"
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	wc, err := c.OpenBlobWrite(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to open registry cluster config for writing: %w", err)
	}

	if _, err := wc.Write(data); err != nil {
		wc.Close()
		return fmt.Errorf("failed to write cluster config to registry: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close registry cluster config: %w", err)
	}

	// 2. Set Permissions: writable by 'admin' group, readable by 'users' group
	adminGID, _, err := c.ResolveGroupName(ctx, "admin")
	if err != nil {
		return fmt.Errorf("failed to resolve admin group: %w", err)
	}
	usersGID, _, err := c.ResolveGroupName(ctx, "users")
	if err != nil {
		return fmt.Errorf("failed to resolve users group: %w", err)
	}

	if err := c.Chgrp(ctx, path, adminGID); err != nil {
		return fmt.Errorf("failed to set group for %s: %w", path, err)
	}

	acl := ACL{
		Groups: map[string]uint32{
			usersGID: 0004, // Read-only
		},
	}
	if err := c.Setfacl(ctx, path, acl); err != nil {
		return fmt.Errorf("failed to set ACL for %s: %w", path, err)
	}

	// 3. Clear cache
	c.anchoredNodesMu.Lock()
	c.anchoredNodes = nil
	c.anchoredNodesMu.Unlock()

	return nil
}

// AnchorGroupInRegistry creates a signed attestation for a group in the registry.
func (c *Client) AnchorGroupInRegistry(ctx context.Context, name string, groupID string) error {
	group, err := c.getGroupUnverifiedCached(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to fetch group for anchoring: %w", err)
	}
	regDir := c.registryDir
	if regDir == "" {
		return nil // Registry not configured, skip anchoring
	}
	if !strings.HasSuffix(regDir, "/") {
		regDir += "/"
	}

	attestationPath := regDir + group.ID + ".group-id"

	// 2. Prepare Registry Attestation
	entry := &GroupDirectoryEntry{
		GroupName:  name,
		GroupID:    group.ID,
		OwnerID:    group.OwnerID,
		EncKey:     group.EncKey,
		SignKey:    group.SignKey,
		VerifierID: c.userID,
	}

	// Sign the attestation with the current user's key (the admin anchoring it)
	entry.Attestation = c.signKey.Sign(entry.Hash())

	attestationBytes, _ := json.Marshal(entry)

	// 3. Define Permissions
	// File is owned by the creator (the one anchoring).
	// The group manager (group.OwnerID) gets RW access via ACL.
	acl := &ACL{
		Users:  make(map[string]uint32),
		Groups: make(map[string]uint32),
	}

	managerID := group.OwnerID
	if managerID == metadata.SelfOwnedGroup {
		managerID = group.ID
	}

	// Determine if manager is a user or group
	if _, err := c.getUserUnverified(ctx, managerID); err == nil {
		acl.Users[managerID] = 0006 // Read + Write
	} else {
		acl.Groups[managerID] = 0006 // Read + Write
	}

	exists := true
	_, _, err = c.resolvePath(ctx, attestationPath)
	if err != nil {
		if isNotFound(err) {
			exists = false
		} else {
			return fmt.Errorf("failed to resolve attestation path %s: %w", attestationPath, err)
		}
	}

	if exists {
		// Update in place - ONLY update the content.
		// We use writeFile directly to avoid touching Inode metadata like ACLs
		// which would invalidate the OwnerDelegationSig.
		inode, _, err := c.resolvePath(ctx, attestationPath)
		if err != nil {
			return fmt.Errorf("failed to resolve existing attestation for update: %w", err)
		}

		// Note: writeFile handles the lockbox update (to remove revoked members)
		// and signs the manifest with the manager's key.
		_, err = c.writeFile(ctx, inode.ID, inode.Nonce, bytes.NewReader(attestationBytes), int64(len(attestationBytes)), inode.Mode)
		if err != nil {
			return fmt.Errorf("failed to overwrite existing group attestation: %w", err)
		}
	} else {
		// Create new. Inherits 'users' Read access from /registry DefaultACL.
		// We grant the manager RW access via ACL.
		acl := &ACL{
			Users:  make(map[string]uint32),
			Groups: make(map[string]uint32),
		}
		managerID := group.OwnerID
		if managerID == metadata.SelfOwnedGroup {
			managerID = group.ID
		}
		if _, err := c.getUserUnverified(ctx, managerID); err == nil {
			acl.Users[managerID] = 0006 // Read + Write
		} else {
			acl.Groups[managerID] = 0006 // Read + Write
		}

		opts := MkdirOptions{
			Mode:      ptr(uint32(0640)), // Owner RW, Group R
			AccessACL: acl,
		}
		if err := c.CreateFileExtended(ctx, attestationPath, bytes.NewReader(attestationBytes), int64(len(attestationBytes)), opts); err != nil {
			if !isConflict(err) {
				return fmt.Errorf("failed to create group attestation file %s: %w", attestationPath, err)
			}
		}
	}

	// 4. Update the name link (if it doesn't exist)
	namePath := regDir + name + ".group"
	_, _, err = c.resolvePath(ctx, namePath)
	if err != nil && isNotFound(err) {
		if err := c.Link(ctx, attestationPath, namePath); err != nil && !isConflict(err) {
			logger.Debugf("AnchorGroupInRegistry: failed to create group attestation link %s: %v", namePath, err)
		}
	}

	return nil
}

func (c *Client) AnchorUserInRegistry(ctx context.Context, username string, userID string, verifierID string) error {
	if username == "" {
		return fmt.Errorf("username is required to anchor a user in the registry")
	}

	// 1. Fetch User Metadata (Unverified)
	user, err := c.getUserUnverified(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to fetch user %s for anchoring: %w", userID, err)
	}

	regDir := c.registryDir
	if regDir == "" {
		return nil // Registry not configured, skip anchoring
	}
	if !strings.HasSuffix(regDir, "/") {
		regDir += "/"
	}

	attestationPath := regDir + user.ID + ".user-id"

	entry := DirectoryEntry{
		Username:   username,
		UserID:     user.ID,
		SignKey:    user.SignKey,
		EncKey:     user.EncKey,
		VerifierID: verifierID,
		Timestamp:  time.Now().Unix(),
	}
	entry.Signature = c.signKey.Sign(entry.Hash())

	data, _ := json.Marshal(entry)

	exists := true
	_, _, err = c.resolvePath(ctx, attestationPath)
	if err != nil {
		if isNotFound(err) {
			exists = false
		} else {
			return fmt.Errorf("failed to resolve user attestation path %s: %w", attestationPath, err)
		}
	}

	if exists {
		// Update in place
		wc, err := c.OpenBlobWrite(ctx, attestationPath)
		if err != nil {
			return fmt.Errorf("failed to open existing user attestation for write: %w", err)
		}
		if _, err := io.Copy(wc, bytes.NewReader(data)); err != nil {
			wc.Close()
			return fmt.Errorf("failed to write existing user attestation: %w", err)
		}
		if err := wc.Close(); err != nil {
			return fmt.Errorf("failed to close existing user attestation: %w", err)
		}

		// Ensure ownership and mode is correct
		if err := c.setAttr(ctx, attestationPath, metadata.SetAttrRequest{
			Mode: ptr(uint32(0640)),
		}); err != nil {
			return fmt.Errorf("failed to update attributes on existing user attestation: %w", err)
		}
	} else {
		// Create new with restricted permissions (inherits users group access from /registry)
		opts := MkdirOptions{
			Mode:    ptr(uint32(0640)),
			OwnerID: c.userID,
		}
		if err := c.CreateFileExtended(ctx, attestationPath, bytes.NewReader(data), int64(len(data)), opts); err != nil {
			if !isConflict(err) {
				return fmt.Errorf("failed to create user attestation file %s: %w", attestationPath, err)
			}
		}
	}
	namePath := regDir + username + ".user"
	_, _, err = c.resolvePath(ctx, namePath)
	if err != nil && isNotFound(err) {
		if err := c.Link(ctx, attestationPath, namePath); err != nil && !isConflict(err) {
			logger.Debugf("AnchorUserInRegistry: failed to create user attestation link %s: %v", namePath, err)
		}
	}

	return nil
}

func (c *Client) createGroupInternal(ctx context.Context, name string, isSystem bool, quotaEnabled bool, ownerID string) (*metadata.Group, error) {
	if c.registryDir != "" {
		regPath := c.registryDir
		if !strings.HasSuffix(regPath, "/") {
			regPath += "/"
		}
		// Check if name is already anchored
		if _, _, err := c.resolvePathInternal(ctx, regPath+name+".group", false); err == nil {
			return nil, fmt.Errorf("group '%s' already exists in registry", name)
		}
	}

	if ownerID == "" {
		ownerID = c.userID
	}

	// Allocate numeric GID
	gid, err := c.allocateGID(ctx)
	if err != nil {
		return nil, fmt.Errorf("GID allocation failed: %w", err)
	}

	// 1. Generate Encryption Key (ML-KEM)
	dk, _ := crypto.GenerateEncryptionKey()
	_ = dk // Still used for encryptClientBlob below
	// 2. Generate Initial Epoch Seed (Master Seed)
	masterSeed := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, masterSeed); err != nil {
		return nil, err
	}
	epochSeed, err := crypto.DeriveEpochKey(masterSeed, metadata.MaxEpochs, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive initial epoch key: %w", err)
	}
	keys, err := crypto.DeriveGroupKeys(epochSeed)

	if err != nil {
		return nil, fmt.Errorf("failed to derive initial group keys: %w", err)
	}

	// 3. Generate Registry Key (Symmetric)
	rk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rk); err != nil {
		return nil, err
	}

	encMasterSeed, err := crypto.EncryptDEM(rk, masterSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt master seed: %w", err)
	}

	// 3.2 Prepare ClientBlob
	blob := metadata.GroupClientBlob{Name: name}
	encBlob, err := c.encryptClientBlob(blob, keys.EncKey.EncapsulationKey())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt group client blob: %w", err)
	}

	// Phase 69.7: Generate Binding Nonce and GroupID
	nonce := metadata.GenerateNonce()
	groupID := metadata.GenerateGroupID(ownerID, nonce)

	group := &metadata.Group{
		ID:                 groupID,
		GID:                gid,
		OwnerID:            ownerID,
		Nonce:              nonce,
		EncKey:             keys.EncKey.EncapsulationKey().Bytes(),
		SignKey:            keys.SignKey.Public(),
		RegistryLockbox:    nil, // Populated below
		EncryptedRegistry:  nil, // Populated below
		ClientBlob:         encBlob,
		IsSystem:           isSystem,
		QuotaEnabled:       quotaEnabled,
		Version:            1,
		Epoch:              0,
		EncryptedEpochSeed: encMasterSeed,
	}
	group.SetName(name)

	lb := crypto.NewLockbox()
	// 3.1 Encrypt group Epoch Seed for the creator
	// Phase 71: Use provisionRecipient with group context for HMAC privacy.
	if err := c.provisionRecipient(ctx, lb, c.userID, epochSeed, group); err != nil {
		return nil, fmt.Errorf("failed to provision creator in group lockbox: %w", err)
	}

	// If owner is different from creator, also give them access
	if ownerID != c.userID && ownerID != metadata.SelfOwnedGroup {
		if err := c.provisionRecipient(ctx, lb, ownerID, epochSeed, group); err != nil {
			return nil, fmt.Errorf("failed to provision owner in group lockbox: %w", err)
		}
	}
	group.Lockbox = lb

	rlb := crypto.NewLockbox()
	// Encrypt Registry Key for the creator (raw UserID for management)
	if err := c.provisionRecipient(ctx, rlb, c.userID, rk, nil); err != nil {
		return nil, err
	}
	// And for the owner if different and not self-owned
	if ownerID != c.userID && ownerID != metadata.SelfOwnedGroup {
		if err := c.provisionRecipient(ctx, rlb, ownerID, rk, nil); err != nil {
			return nil, err
		}
	}
	group.RegistryLockbox = rlb

	// Determine initial member for MembersHMAC and Registry
	ownerIsUser := false
	if ownerID != metadata.SelfOwnedGroup {
		if ownerID == c.userID {
			ownerIsUser = true
		} else {
			// Check if ownerID is a user
			if _, err := c.getUser(ctx, ownerID); err == nil {
				ownerIsUser = true
			}
		}
	}

	initialMembers := []metadata.MemberEntry{}
	if ownerID == metadata.SelfOwnedGroup {
		initialMembers = append(initialMembers, metadata.MemberEntry{UserID: c.userID, Info: "Creator (Initial Manager)"})
	} else if ownerIsUser {
		initialMembers = append(initialMembers, metadata.MemberEntry{UserID: ownerID, Info: "Owner"})
	}

	encRegistry, err := c.encryptRegistry(rk, initialMembers)
	if err != nil {
		return nil, err
	}
	group.EncryptedRegistry = encRegistry

	// Cache keys for signing
	cacheKey := groupKeyCacheID{id: groupID, epoch: group.Epoch}
	c.keyMu.Lock()
	c.groupKeys[cacheKey] = keys.EncKey
	c.groupSignKeys[cacheKey] = keys.SignKey
	c.keyMu.Unlock()

	// Sign the Group
	if err := c.signGroup(ctx, group, false); err != nil {
		return nil, err
	}

	// Atomic Batch Creation
	cmds := []metadata.LogCommand{}
	createGrpCmd, err := c.prepareCreateGroup(ctx, group)
	if err != nil {
		return nil, err
	}
	cmds = append(cmds, createGrpCmd)

	results, err := c.applyBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}

	// Verify the first result (Group Creation)
	if err := c.isResultError(results[0]); err != nil {
		return nil, err
	}

	// Update cache with the newly created group
	c.cacheMu.Lock()
	c.verifiedGroupCache[group.ID] = group
	c.cacheMu.Unlock()

	// 2. Anchor in Registry (Phase 69)
	if err := c.AnchorGroupInRegistry(ctx, name, group.ID); err != nil {
		logger.Debugf("Warning: failed to anchor group %s in registry: %v", name, err)
	}

	return group, nil
}

func (c *Client) computeMemberHMAC(hmacKey string, userID string) string {
	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(userID))
	res := hex.EncodeToString(mac.Sum(nil))
	return res
}

// AddUserToGroup adds a new member to an existing group.
func (c *Client) AddUserToGroup(ctx context.Context, groupID, userID, info string, ci *ContactInfo) error {
	_, err := c.updateGroup(ctx, groupID, func(group *metadata.Group) error {
		// 1. Fetch current Epoch Seed
		epochSeed, err := c.getGroupEpochSeed(ctx, groupID)
		if err != nil {
			return err
		}

		// Phase 71: Use provisionRecipient with group context for HMAC privacy.
		if err := c.provisionRecipient(ctx, group.Lockbox, userID, epochSeed, group); err != nil {
			return err
		}

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

// AddAnonymousUserToGroup adds an anonymous member using their ML-KEM public key.
func (c *Client) AddAnonymousUserToGroup(ctx context.Context, groupID string, pubKey *mlkem.EncapsulationKey768) error {
	_, err := c.updateGroup(ctx, groupID, func(group *metadata.Group) error {
		epochSeed, err := c.getGroupEpochSeed(ctx, groupID)
		if err != nil {
			return err
		}

		// Encapsulate and encrypt the Epoch Seed for this anonymous user
		tempLB := crypto.NewLockbox()
		if err := tempLB.AddRecipient("seed", pubKey, epochSeed, group.Epoch); err != nil {
			return err
		}

		anonBlob, err := json.Marshal(tempLB)
		if err != nil {
			return err
		}

		group.AnonymousLockbox = append(group.AnonymousLockbox, anonBlob)

		// Update AnonymousRegistry (encrypted with Registry Key)
		rk, err := c.getGroupRegistryKey(ctx, group)
		if err == nil {
			var pubKeys [][]byte
			if len(group.AnonymousRegistry) > 0 {
				plainReg, err := crypto.DecryptDEM(rk, group.AnonymousRegistry)
				if err == nil {
					json.Unmarshal(plainReg, &pubKeys)
				}
			}
			pubKeys = append(pubKeys, pubKey.Bytes())
			newPlainReg, _ := json.Marshal(pubKeys)
			encReg, _ := crypto.EncryptDEM(rk, newPlainReg)
			group.AnonymousRegistry = encReg
		}

		return nil
	})
	return err
}

// RevokeGroupMember removes a member (named or anonymous) and performs O(1) key ratchet revocation.
func (c *Client) RevokeGroupMember(ctx context.Context, groupID string, targetUserID string, targetAnonPubKey []byte) error {
	var groupName string

	updatedGroup, err := c.updateGroup(ctx, groupID, func(group *metadata.Group) error {
		// We are a manager, update the registry
		rk, err := c.getGroupRegistryKey(ctx, group)
		if err != nil {
			return fmt.Errorf("must be a manager to revoke members: %w", err)
		}

		name, err := c.getGroupName(ctx, group)
		if err == nil {
			groupName = name
		}

		// 1. Resolve remaining members
		retainUsers := make(map[string]bool)
		if targetUserID != "" {
			members, err := c.decryptRegistry(rk, group.EncryptedRegistry)
			if err == nil {
				var newMembers []metadata.MemberEntry
				for _, m := range members {
					if m.UserID != targetUserID {
						newMembers = append(newMembers, m)
						retainUsers[m.UserID] = true
					}
				}
				encRegistry, err := c.encryptRegistry(rk, newMembers)
				if err != nil {
					return err
				}
				group.EncryptedRegistry = encRegistry
			}
		}
		retainUsers[c.userID] = true
		if group.OwnerID != metadata.SelfOwnedGroup {
			retainUsers[group.OwnerID] = true
		}

		// (Implement anonymous registry parsing here later when we add AddAnonymousUserToGroup)

		// New Epoch Seed (O(1) Ratchet)
		masterSeed, err := c.getGroupMasterSeed(ctx, group)
		if err != nil {
			return fmt.Errorf("failed to fetch master seed for revocation: %w", err)
		}

		group.Epoch++
		if group.Epoch >= metadata.MaxEpochs {
			return fmt.Errorf("maximum number of revocations reached for this group")
		}

		epochSeed, err := crypto.DeriveEpochKey(masterSeed, metadata.MaxEpochs, group.Epoch)
		if err != nil {
			return err
		}
		keys, err := crypto.DeriveGroupKeys(epochSeed)
		if err != nil {
			return err
		}

		// Store old sign key in history
		if group.HistoricalSignKeys == nil {
			group.HistoricalSignKeys = make(map[uint32][]byte)
		}
		group.HistoricalSignKeys[group.Epoch-1] = group.SignKey

		group.EncKey = keys.EncKey.EncapsulationKey().Bytes()
		group.SignKey = keys.SignKey.Public()

		// 3. Rebuild Named Lockbox
		newLockbox := crypto.NewLockbox()
		for uid := range retainUsers {
			// Phase 71: Use provisionRecipient with group context for HMAC privacy.
			if err := c.provisionRecipient(ctx, newLockbox, uid, epochSeed, group); err != nil {
				continue
			}
		}
		group.Lockbox = newLockbox

		// 4. Rebuild Anonymous Lockbox
		var remainingAnon [][]byte
		if len(group.AnonymousRegistry) > 0 {
			plainAnon, err := crypto.DecryptDEM(rk, group.AnonymousRegistry)
			if err == nil {
				var anonPubKeys [][]byte
				json.Unmarshal(plainAnon, &anonPubKeys)
				var newAnonPubKeys [][]byte
				for _, pk := range anonPubKeys {
					if !bytes.Equal(pk, targetAnonPubKey) {
						newAnonPubKeys = append(newAnonPubKeys, pk)
						remainingAnon = append(remainingAnon, pk)
					}
				}
				newPlainReg, _ := json.Marshal(newAnonPubKeys)
				encReg, _ := crypto.EncryptDEM(rk, newPlainReg)
				group.AnonymousRegistry = encReg
			}
		}

		group.AnonymousLockbox = nil
		for _, pkBytes := range remainingAnon {
			apk, err := crypto.UnmarshalEncapsulationKey(pkBytes)
			if err != nil {
				continue
			}
			tempLB := crypto.NewLockbox()
			tempLB.AddRecipient("seed", apk, epochSeed, group.Epoch)
			anonBlob, _ := json.Marshal(tempLB)
			group.AnonymousLockbox = append(group.AnonymousLockbox, anonBlob)
		}

		// Cache new keys
		cacheKey := groupKeyCacheID{id: group.ID, epoch: group.Epoch}
		c.keyMu.Lock()
		c.groupKeys[cacheKey] = keys.EncKey
		c.groupSignKeys[cacheKey] = keys.SignKey
		c.keyMu.Unlock()

		return nil
	})

	if err == nil && groupName != "" {
		if anchorErr := c.AnchorGroupInRegistry(ctx, groupName, updatedGroup.ID); anchorErr != nil {
			return fmt.Errorf("revocation succeeded but registry anchoring failed: %w", anchorErr)
		}
	}

	return err
}

func (c *Client) getGroupMasterSeed(ctx context.Context, group *metadata.Group) ([]byte, error) {
	// The master seed is always encrypted with the Registry Key in EncryptedEpochSeed
	rk, err := c.getGroupRegistryKey(ctx, group)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptDEM(rk, group.EncryptedEpochSeed)
}

// RemoveUserFromGroup delegates to RevokeGroupMember.
func (c *Client) RemoveUserFromGroup(ctx context.Context, groupID, userID string) error {
	return c.RevokeGroupMember(ctx, groupID, userID, nil)
}

// SetAttr updates the attributes of an inode at the given stdpath.
func (c *Client) setAttr(ctx context.Context, fullPath string, attr metadata.SetAttrRequest) error {
	inode, key, err := c.resolvePath(ctx, fullPath)
	if err != nil {
		return err
	}
	_, err = c.setAttrByID(ctx, inode, key, attr)
	return err
}

// SetAttrByID updates the attributes of an inode by ID. Returns the updated inode.
func (c *Client) setAttrByID(ctx context.Context, inode *metadata.Inode, key []byte, attr metadata.SetAttrRequest) (*metadata.Inode, error) {
	// 1. Pre-fetch required metadata before entering the atomic update
	if attr.OwnerID != nil {
		if _, err := c.getUser(ctx, *attr.OwnerID); err != nil {
			return nil, fmt.Errorf("failed to fetch new owner: %w", err)
		}
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
		if _, err := c.getWorldPublicKey(ctx); err != nil {
			logger.Debugf("setAttrByID: failed to pre-fetch world key: %v", err)
		}
	}

	if targetGroupID != "" && groupRW && !worldRead {
		if _, err := c.getGroup(ctx, targetGroupID); err != nil {
			logger.Debugf("setAttrByID: failed to pre-fetch group %s: %v", targetGroupID, err)
		}
		if _, err := c.getGroupEpochSeed(ctx, targetGroupID); err != nil {
			logger.Debugf("setAttrByID: failed to pre-fetch seed for group %s: %v", targetGroupID, err)
		}
	}

	// 1.5 Pre-fetch ACL recipients
	if attr.AccessACL != nil {
		for uid, bits := range attr.AccessACL.Users {
			if (bits & 4) != 0 {
				c.getUserUnverified(ctx, uid)
			}
		}
		for gid, bits := range attr.AccessACL.Groups {
			if (bits&4) != 0 && !worldRead {
				c.getGroupUnverifiedCached(ctx, gid)
				c.getGroupEpochSeedUnverified(ctx, gid)
			}
		}
	}

	// 2. Perform Atomic Update
	updated, err := c.updateInode(ctx, inode.ID, func(i *metadata.Inode) error {
		i.SetFileKey(key) // Ensure key is available for signing

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
		if attr.AccessACL != nil {
			i.AccessACL = attr.AccessACL
		}
		if attr.DefaultACL != nil {
			i.DefaultACL = attr.DefaultACL
		}

		// Update Lockbox using provisionRecipient (all info is pre-cached above)
		if attr.OwnerID != nil {
			if err := c.provisionRecipient(ctx, i.Lockbox, *attr.OwnerID, key, nil); err != nil {
				return err
			}
		}

		worldRead := (i.Mode & 0004) != 0
		groupRW := (i.Mode & 0060) != 0

		// 2.1 World Access
		_, worldInLockbox := i.Lockbox[metadata.WorldID]
		if worldRead {
			if err := c.provisionRecipient(ctx, i.Lockbox, metadata.WorldID, key, nil); err != nil {
				return err
			}
		} else if worldInLockbox {
			delete(i.Lockbox, metadata.WorldID)
		}

		// 2.2 Group Access
		if i.GroupID != "" {
			_, groupInLockbox := i.Lockbox[i.GroupID]
			if groupRW && !worldRead {
				if err := c.provisionRecipient(ctx, i.Lockbox, i.GroupID, key, nil); err != nil {
					// Log but continue; owner still has access
					logger.Debugf("setAttrByID: failed to provision group %s: %v", i.GroupID, err)
				}
			} else if (!groupRW || worldRead) && groupInLockbox {
				delete(i.Lockbox, i.GroupID)
			}
		}

		// 2.3 ACL Access Expansion
		if i.AccessACL != nil {
			for uid, bits := range i.AccessACL.Users {
				if (bits & 4) != 0 {
					if err := c.provisionRecipient(ctx, i.Lockbox, uid, key, nil); err != nil {
						return err
					}
				}
			}
			for gid, bits := range i.AccessACL.Groups {
				if (bits&4) != 0 && !worldRead {
					if err := c.provisionRecipient(ctx, i.Lockbox, gid, key, nil); err != nil {
						logger.Debugf("setAttrByID: failed to provision ACL group %s: %v", gid, err)
					}
				}
			}
		}

		return nil
	})

	return updated, err
}

// Remove deletes an inode at the given stdpath.
// Remove deletes the file or empty directory at the given stdpath.
func (c *Client) Remove(ctx context.Context, fullPath string) error {
	return c.RemoveEntry(ctx, fullPath)
}

// PushKeySync uploads an encrypted configuration blob to the server.
// Requires a valid session and mandatory Layer 7 E2EE (Sealing).
func (c *Client) pushKeySync(ctx context.Context, blob *metadata.KeySyncBlob) error {
	data, _ := json.Marshal(blob)
	bodyRC, _, err := c.doRequest(ctx, "POST", "/v1/user/keysync", data, requestOptions{sealed: true, retry: true}, nil)
	if err != nil {
		return err
	}
	bodyRC.Close()
	return nil
}

// PullKeySync retrieves the encrypted configuration blob from the server.
// Authenticates using an OIDC JWT.
func (c *Client) pullKeySync(ctx context.Context, jwt string) (*metadata.KeySyncBlob, error) {
	var blob metadata.KeySyncBlob
	_, _, err := c.doRequest(ctx, "GET", "/v1/user/keysync", nil, requestOptions{jwt: jwt, skipAuth: true, retry: true}, &blob)
	if err != nil {
		return nil, err
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

type requestOptions struct {
	action      string // Target action for /v1/invoke
	sealed      bool   // Seal request body
	unseal      bool   // Unseal response body
	retry       bool   // Use standard retry
	conflict    bool   // Use conflict-aware retry
	skipAuth    bool   // Skip standard session authentication
	skipControl bool   // Skip concurrency control semaphore
	jwt         string // Custom JWT for Authorization header
}

// doRequest encapsulates the standard metadata request lifecycle:
// acquireControl -> withRetry -> Auth -> [Seal] -> Execute -> [Unseal] -> releaseControl.
func (c *Client) doRequest(ctx context.Context, method, urlPath string, body []byte, opts requestOptions, out interface{}) (io.ReadCloser, *http.Response, error) {
	var resp *http.Response
	var bodyRC io.ReadCloser

	if opts.action != "" {
		opts.sealed = true
		if len(body) == 0 {
			body = []byte("{}")
		}
		env := metadata.SealedEnvelope{
			Action:  opts.action,
			Payload: body,
		}
		var err error
		body, err = json.Marshal(env)
		if err != nil {
			return nil, nil, err
		}
		urlPath = "/v1/invoke"
		method = http.MethodPost
	}

	op := func() error {
		if !opts.skipControl {
			if err := c.acquireControl(ctx); err != nil {
				return err
			}
			defer c.releaseControl()
		}

		req, err := http.NewRequestWithContext(ctx, method, c.serverAddr+urlPath, nil)
		if err != nil {
			return err
		}

		if opts.jwt != "" {
			req.Header.Set("Authorization", "Bearer "+opts.jwt)
		}

		if !opts.skipAuth {
			if err := c.authenticateRequest(ctx, req); err != nil {
				return err
			}
		}

		if opts.sealed {
			if len(body) == 0 {
				body = []byte("{}")
			}
			if err := c.sealBody(ctx, req, body); err != nil {
				return err
			}
		} else if len(body) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))
			req.Header.Set("Content-Type", "application/json")
		}

		r, err := c.httpCli.Do(req)
		if err != nil {
			return err
		}

		// Read and unseal exactly once
		var unsealed io.ReadCloser
		if opts.unseal {
			unsealed, err = c.unsealResponse(ctx, r)
		} else {
			unsealed = r.Body
		}

		if err != nil {
			r.Body.Close()
			return err
		}

		if r.StatusCode >= 400 {
			err = c.newAPIError(r, unsealed)
			unsealed.Close()
			return err
		}

		resp = r
		bodyRC = unsealed

		if out != nil {
			err := json.NewDecoder(unsealed).Decode(out)
			unsealed.Close()
			return err
		}

		return nil
	}

	var err error
	if opts.conflict {
		err = c.withConflictRetry(ctx, op)
	} else if opts.retry {
		err = c.withRetry(ctx, op)
	} else {
		err = op()
	}

	return bodyRC, resp, err
}

type withRetryOptions struct {
	maxIter    int
	maxBackoff time.Duration
	isConflict bool
}

func (c *Client) withRetryInternal(ctx context.Context, opts withRetryOptions, op func() error) error {
	var lastErr error
	backoff := 50 * time.Millisecond

	for i := 0; ; i++ {
		if opts.maxIter > 0 && i >= opts.maxIter {
			if lastErr != nil {
				return lastErr
			}
			return metadata.ErrConflict
		}

		err := op()
		if err == nil {
			return nil
		}
		lastErr = err

		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
				return err
			}
		}

		isConflict := opts.isConflict && isConflict(err)

		if isConflict || c.isRetryable(err) {
			select {
			case <-ctx.Done():
				if lastErr != nil {
					return fmt.Errorf("%w: %v", ctx.Err(), lastErr)
				}
				return ctx.Err()
			default:
			}

			jitter := time.Duration(mrand.Int63n(int64(backoff/2) + 1))
			select {
			case <-ctx.Done():
				if lastErr != nil {
					return fmt.Errorf("%w: %v", ctx.Err(), lastErr)
				}
				return ctx.Err()
			case <-time.After(backoff + jitter):
			}
			backoff *= 2
			if backoff > opts.maxBackoff {
				backoff = opts.maxBackoff
			}
			continue
		}
		return err
	}
}

func (c *Client) withRetry(ctx context.Context, op func() error) error {
	return c.withRetryInternal(ctx, withRetryOptions{
		maxIter:    0,
		maxBackoff: 500 * time.Millisecond,
		isConflict: false,
	}, op)
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

	// 2. Check for specific network errors
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection aborted") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "busy") ||
		strings.Contains(msg, "retry") ||
		strings.Contains(msg, "resource temporarily unavailable") ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// 3. API errors
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusForbidden {
			return false
		}
		if apiErr.StatusCode == http.StatusServiceUnavailable ||
			apiErr.StatusCode == http.StatusTooManyRequests ||
			apiErr.Code == metadata.ErrCodeNotLeader {
			return true
		}
	}

	return false
}

func (c *Client) withConflictRetry(ctx context.Context, op func() error) error {
	return c.withRetryInternal(ctx, withRetryOptions{
		maxIter:    100,
		maxBackoff: 5 * time.Second,
		isConflict: true,
	}, op)
}

func (c *Client) getClusterStats(ctx context.Context) (*metadata.ClusterStats, error) {
	var stats metadata.ClusterStats
	_, _, err := c.doRequest(ctx, "GET", "/v1/cluster/stats", nil, requestOptions{sealed: true, unseal: true, retry: true}, &stats)
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
func (c *Client) acquireLeases(ctx context.Context, ids []string, duration time.Duration, opts LeaseOptions) error {
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

	_, _, err := c.doRequest(ctx, "POST", "/v1/meta/lease/acquire", data, requestOptions{action: metadata.ActionAcquireLeases, sealed: true, unseal: true, retry: true, conflict: false}, nil)
	return err
}

// ReleaseLeases releases previously acquired distributed leases.
func (c *Client) releaseLeases(ctx context.Context, ids []string, nonce string) error {
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

	_, _, err := c.doRequest(ctx, "POST", "/v1/meta/lease/release", data, requestOptions{action: metadata.ActionReleaseLeases, sealed: true, unseal: true, retry: true, conflict: false}, nil)
	return err
}

// AdminListUsers returns an iterator over all users in the cluster.
func (c *Client) AdminListUsers(ctx context.Context) iter.Seq2[*metadata.User, error] {
	return func(yield func(*metadata.User, error) bool) {
		var users []metadata.User
		_, _, err := c.doRequest(ctx, "GET", "/v1/admin/users", nil, requestOptions{action: metadata.ActionAdminUsers, unseal: true, retry: true}, &users)
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
			req := metadata.AdminGroupsRequest{Cursor: cursor, Limit: 1000}
			data, _ := json.Marshal(req)
			_, resp, err := c.doRequest(ctx, "GET", "/v1/admin/groups", data, requestOptions{action: metadata.ActionAdminGroups, unseal: true, retry: true}, &groups)
			if err != nil {
				yield(nil, err)
				return
			}

			for i := range groups {
				if !yield(&groups[i], nil) {
					return
				}
			}

			nextCursor := resp.Header.Get("X-DistFS-Next-Cursor")
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
		_, _, err := c.doRequest(ctx, "GET", "/v1/admin/leases", nil, requestOptions{action: metadata.ActionAdminLeases, unseal: true, retry: true}, &leases)
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
		_, _, _ = c.doRequest(ctx, "GET", "/v1/admin/nodes", nil, requestOptions{action: metadata.ActionAdminNodes, unseal: true, retry: true}, &nodes)

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
	_, _, err := c.doRequest(ctx, "GET", "/v1/admin/status", nil, requestOptions{action: metadata.ActionAdminStatus, unseal: true, retry: true}, &status)
	return status, err
}

// ResolveUsername attempts to resolve a user identifier to a DistFS UserID.
// It prioritizes the local registry, then falls back to verifying raw 64-character IDs.
// ResolveUsername resolves a human-readable username to its 64-character hex User ID.
func (c *Client) ResolveUsername(ctx context.Context, username string) (string, *DirectoryEntry, error) {
	if metadata.IsInodeID(username) {
		return username, nil, nil // Already a 32-char hex ID (e.g., group ID or root ID)
	}

	if len(username) == 64 {
		if _, err := hex.DecodeString(username); err == nil {
			return username, nil, nil // Already a 64-char hex User ID
		}
	}

	if strings.Contains(username, "@") {
		return "", nil, fmt.Errorf("email resolution is no longer supported (use registry username instead)")
	}

	// Try the registry
	regPath := c.registryDir
	if regPath == "" {
		return "", nil, fmt.Errorf("registry not configured")
	}
	if !strings.HasSuffix(regPath, "/") {
		regPath += "/"
	}
	filePath := regPath + username + ".user"

	var entry DirectoryEntry
	err := c.readDataFile(ctx, filePath, &entry)
	if err != nil {
		if isNotFound(err) {
			return "", nil, fmt.Errorf("user '%s' not found in registry %s", username, regPath)
		}
		return "", nil, fmt.Errorf("failed to read registry entry for %s: %w", username, err)
	}

	// Verify the entry signature using the VerifierID's public key.
	verifier, err := c.getUser(ctx, entry.VerifierID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch verifier %s for registry entry: %w", entry.VerifierID, err)
	}
	if !verifier.IsAdmin {
		return "", nil, fmt.Errorf("verifier %s is not an administrator", entry.VerifierID)
	}
	if !entry.VerifySignature(verifier.SignKey) {
		return "", nil, fmt.Errorf("invalid registry signature for %s by %s", username, entry.VerifierID)
	}

	return entry.UserID, &entry, nil
}

// ResolveGroupName resolves a human-readable group name to its 32-character hex ID.
func (c *Client) ResolveGroupName(ctx context.Context, name string) (string, *GroupDirectoryEntry, error) {
	// Try the registry
	regPath := c.registryDir
	if regPath == "" {
		return "", nil, fmt.Errorf("registry not configured")
	}
	if !strings.HasSuffix(regPath, "/") {
		regPath += "/"
	}
	filePath := regPath + name + ".group"

	var entry GroupDirectoryEntry
	err := c.readDataFile(ctx, filePath, &entry)
	if err != nil {
		if isNotFound(err) {
			return "", nil, fmt.Errorf("group '%s' not found in registry %s", name, regPath)
		}
		return "", nil, fmt.Errorf("failed to read registry entry for %s: %w", name, err)
	}

	// Verify the entry signature using the VerifierID's public key.
	verifier, err := c.getUser(ctx, entry.VerifierID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch verifier %s for registry entry: %w", entry.VerifierID, err)
	}
	if !verifier.IsAdmin {
		return "", nil, fmt.Errorf("verifier %s is not an administrator", entry.VerifierID)
	}
	if !entry.VerifyAttestation(verifier.SignKey) {
		return "", nil, fmt.Errorf("invalid registry signature for group %s by %s", name, entry.VerifierID)
	}

	return entry.GroupID, &entry, nil
}

// AdminAudit streams redacted audit records from the server.
func (c *Client) AdminAudit(ctx context.Context, handler func(metadata.AuditRecord) error) error {
	bodyRC, resp, err := c.doRequest(ctx, "GET", "/v1/admin/audit", nil, requestOptions{action: metadata.ActionAdminAudit, unseal: true, retry: true}, nil)
	if err != nil {
		return err
	}
	defer bodyRC.Close()

	decoder := json.NewDecoder(bodyRC)
	for decoder.More() {
		var record metadata.AuditRecord
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("audit stream decode error: %w", err)
		}
		if err := handler(record); err != nil {
			return err
		}
	}
	_ = resp
	return nil
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

			for _, entry := range inode.Children {
				childID := entry.ID
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
	_, _, err := c.doRequest(ctx, "POST", "/v1/admin/promote", payload, requestOptions{action: metadata.ActionAdminPromote, unseal: true, retry: true}, nil)
	if err == nil {
		c.invalidateUserCache(userID)
	}
	return err
}

// AdminJoinNode adds a new storage node to the cluster.
func (c *Client) AdminJoinNode(ctx context.Context, address string) error {
	payload, _ := json.Marshal(map[string]string{"address": address})
	_, _, err := c.doRequest(ctx, "POST", "/v1/admin/join", payload, requestOptions{action: metadata.ActionAdminClusterJoin, unseal: true, retry: true}, nil)
	return err
}

// AdminRemoveNode removes a storage node from the cluster by ID.
func (c *Client) AdminRemoveNode(ctx context.Context, id string) error {
	payload, _ := json.Marshal(map[string]string{"id": id})
	_, _, err := c.doRequest(ctx, "POST", "/v1/admin/remove", payload, requestOptions{action: metadata.ActionAdminClusterRem, unseal: true, retry: true}, nil)
	return err
}

// AdminSetUserLock locks or unlocks a user account.
func (c *Client) AdminSetUserLock(ctx context.Context, userID string, locked bool) error {
	req := metadata.AdminSetUserLockRequest{
		UserID: userID,
		Locked: locked,
	}
	data, _ := json.Marshal(req)
	_, _, err := c.doRequest(ctx, "POST", "/v1/admin/lock", data, requestOptions{action: metadata.ActionAdminUserLock, unseal: true, retry: true}, nil)
	if err == nil {
		c.invalidateUserCache(userID)
	}
	return err
}

// AdminSetUserQuota updates the resource limits for a user.
func (c *Client) AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error {
	data, _ := json.Marshal(req)
	_, _, err := c.doRequest(ctx, "POST", "/v1/admin/quota/user", data, requestOptions{action: metadata.ActionAdminUserQuota, unseal: true, retry: true}, nil)
	if err == nil {
		c.invalidateUserCache(req.UserID)
	}
	return err
}

// AdminSetGroupQuota updates the resource limits for a group.
func (c *Client) AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error {
	data, _ := json.Marshal(req)
	_, _, err := c.doRequest(ctx, "POST", "/v1/admin/quota/group", data, requestOptions{action: metadata.ActionAdminGroupQuota, unseal: true, retry: true}, nil)
	if err == nil {
		c.invalidateGroupCache(req.GroupID)
	}
	return err
}

// IsResultError checks if a Raft command result is an error and returns it.
func (c *Client) isResultError(data json.RawMessage) *APIError {
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
		cacheKey := groupKeyCacheID{id: group.ID, epoch: group.Epoch}
		c.keyMu.RLock()
		gdk, ok := c.groupKeys[cacheKey]
		c.keyMu.RUnlock()

		if !ok {
			var err error
			gdk, err = c.getGroupPrivateKey(ctx, group.ID, group.Epoch)
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

	if isUpdate {
	}

	group.SignerID = c.userID
	hash := group.Hash()
	group.Signature = c.signKey.Sign(hash)
	return nil
}

// UpdateGroup performs an atomic read-modify-write operation on a group.
func (c *Client) prepareCreateGroup(ctx context.Context, group *metadata.Group) (metadata.LogCommand, error) {
	group.Version = 1
	if err := c.signGroup(ctx, group, false); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(group)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdCreateGroup, Data: data, UserID: c.userID}, nil
}

func (c *Client) prepareUpdateGroup(ctx context.Context, group *metadata.Group) (metadata.LogCommand, error) {
	group.Version++
	if err := c.signGroup(ctx, group, true); err != nil {
		return metadata.LogCommand{}, err
	}
	data, err := json.Marshal(group)
	if err != nil {
		return metadata.LogCommand{}, err
	}
	return metadata.LogCommand{Type: metadata.CmdUpdateGroup, Data: data, UserID: c.userID}, nil
}

func (c *Client) updateGroup(ctx context.Context, id string, fn GroupUpdateFunc) (*metadata.Group, error) {
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

		cmd, err := c.prepareUpdateGroup(ctx, group)
		if err != nil {
			return nil, err
		}

		results, err := c.applyBatch(ctx, []metadata.LogCommand{cmd})
		if err == nil {
			if len(results) == 0 {
				return nil, fmt.Errorf("empty results from updateGroup batch")
			}
			if err := c.isResultError(results[0]); err != nil {
				return nil, err
			}
			var updated metadata.Group
			if err := json.Unmarshal(results[0], &updated); err != nil {
				return nil, fmt.Errorf("failed to decode updated group: %w", err)
			}

			// Update Cache
			c.cacheMu.Lock()
			c.verifiedGroupCache[id] = &updated
			c.cacheMu.Unlock()

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

// getGroupMembers retrieves the list of members for a group.
// If the requester is an authorized manager, it returns emails. Otherwise, only UserIDs.
func (c *Client) getGroupMembers(ctx context.Context, groupID string) iter.Seq2[metadata.MemberEntry, error] {
	return func(yield func(metadata.MemberEntry, error) bool) {
		group, err := c.getGroup(ctx, groupID)
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
			// Not a manager, return public member list (UserIDs only, derived from Lockbox keys)
			for k := range group.Lockbox {
				if !strings.Contains(k, ":") {
					members = append(members, metadata.MemberEntry{UserID: k, Info: "[HIDDEN]"})
				}
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
	_, err := c.updateGroup(ctx, groupID, func(group *metadata.Group) error {
		// 1. Update RegistryLockbox (if we are a manager)
		rk, err := c.getGroupRegistryKey(ctx, group)
		if err == nil {
			// Re-key Registry for new owner
			if group.RegistryLockbox == nil {
				group.RegistryLockbox = crypto.NewLockbox()
			}
			// RegistryLockbox uses raw UserIDs (not anonymous)
			if err := c.provisionRecipient(ctx, group.RegistryLockbox, newOwnerID, rk, nil); err != nil {
				return err
			}
		}

		// 2. Update Primary Lockbox (Epoch Seed)
		// Phase 71: Use provisionRecipient with group context for HMAC privacy.
		seed, err := c.getGroupEpochSeed(ctx, groupID)
		if err == nil {
			if err := c.provisionRecipient(ctx, group.Lockbox, newOwnerID, seed, group); err != nil {
				return err
			}
		}

		// 3. Remove old owner access if they are not a member
		isMember := false
		if rk != nil {
			members, err := c.decryptRegistry(rk, group.EncryptedRegistry)
			if err == nil {
				for _, m := range members {
					if m.UserID == c.userID {
						isMember = true
						break
					}
				}
			}
		}
		if !isMember {
			target := c.computeMemberHMAC(group.ID, c.userID)
			delete(group.Lockbox, target)
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
	if err := json.Unmarshal(plain, v); err != nil {
		return err
	}
	return nil
}

func (c *Client) encryptInodeClientBlob(v interface{}, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("encryptInodeClientBlob: key is empty")
	}
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

// EncryptEntryName encrypts a filename using the parent directory's key.
func (c *Client) encryptEntryName(parentKey []byte, name string) (ciphertext, nonce []byte, err error) {
	if len(parentKey) == 0 {
		return nil, nil, fmt.Errorf("EncryptEntryName: parentKey is empty for %s", name)
	}
	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	// EncryptDEMWithNonce returns nonce + ciphertext
	res, err := crypto.EncryptDEMWithNonce(parentKey, nonce, []byte(name))
	if err != nil {
		return nil, nil, err
	}
	return res, nonce, nil
}

// DecryptEntryName decrypts a filename using the parent directory's key.
func (c *Client) decryptEntryName(ctx context.Context, parentKey []byte, ciphertext, nonce []byte) (string, error) {
	if len(parentKey) == 0 {
		return "", errors.New("parent key missing")
	}
	plain, err := crypto.DecryptDEMWithNonce(parentKey, nonce, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
