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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"sort"
	"strconv"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

// KeyData is a wrapper for serializing keys to disk.
type KeyData struct {
	Bytes []byte `json:"bytes"`
}

// BootstrapPayload contains the cryptographic material pushed to a joining node.
type BootstrapPayload struct {
	ClusterSecret []byte `json:"cluster_secret"`
	FSMKeyRing    []byte `json:"fsm_keyring"`
}

// APIErrorResponse is the standard structured error response.
type APIErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

const (
	// ErrCodeNotFound indicates the requested resource does not exist.
	ErrCodeNotFound = "DISTFS_NOT_FOUND"
	// ErrCodeExists indicates an attempt to create a resource that already exists.
	ErrCodeExists = "DISTFS_EXISTS"
	// ErrCodeVersionConflict indicates an optimistic concurrency failure.
	ErrCodeVersionConflict = "DISTFS_VERSION_CONFLICT"
	// ErrCodeLeaseRequired indicates a mutation attempt without holding an exclusive lease.
	ErrCodeLeaseRequired = "DISTFS_LEASE_REQUIRED"
	// ErrCodeQuotaExceeded indicates the user or group has exceeded their storage limit.
	ErrCodeQuotaExceeded = "DISTFS_QUOTA_EXCEEDED"
	// ErrCodeUnauthorized indicates invalid or missing authentication credentials.
	ErrCodeUnauthorized = "DISTFS_UNAUTHORIZED"
	// ErrCodeForbidden indicates the user lacks permission for the requested action.
	ErrCodeForbidden = "DISTFS_FORBIDDEN"
	// ErrCodeNotLeader indicates the request was sent to a follower node.
	ErrCodeNotLeader = "DISTFS_NOT_LEADER"
	// ErrCodeInternal indicates an unexpected server-side error or panic.
	ErrCodeInternal = "DISTFS_INTERNAL_ERROR"
	// ErrCodeAtomicRollback indicates a sub-command in a batch failed, causing a full rollback.
	ErrCodeAtomicRollback = "DISTFS_ATOMIC_ROLLBACK"
	// ErrCodeStructuralInconsistency indicates a mutation that violates filesystem topology.
	ErrCodeStructuralInconsistency = "DISTFS_STRUCTURAL_INCONSISTENCY"
	// ErrCodeQuotaDisabled indicates an attempt to set quota on a group where it is disabled.
	ErrCodeQuotaDisabled = "DISTFS_QUOTA_DISABLED"
)

// OIDCConfig represents the OpenID Connect configuration needed by clients for authentication.
type OIDCConfig struct {
	Issuer                      string `json:"issuer"`
	JWKSURI                     string `json:"jwks_uri"`
	AuthorizationEndpoint       string `json:"authorization_endpoint,omitempty"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`
	TokenEndpoint               string `json:"token_endpoint"`
}

// InodeType represents the file type (File, Directory, Symlink).
type InodeType uint8

const (
	FileType    InodeType = 0
	DirType     InodeType = 1
	SymlinkType InodeType = 2
)

// LeaseType represents the type of lease (Shared for readers, Exclusive for writers/placeholders).
type LeaseType uint8

const (
	LeaseShared    LeaseType = 0
	LeaseExclusive LeaseType = 1
)

const (
	// RootID is the fixed ID of the root directory.
	RootID = "root-directory-inode-id-0000000000"
	// WorldID is the reserved ID for the 'world' recipient in lockboxes.
	WorldID = "world"
	// InlineLimit is the maximum size of a file that can be inlined in metadata.
	InlineLimit = 4096
	// InodeIDLength is the expected length of a hex-encoded Inode ID (16 random bytes).
	InodeIDLength = 32
)

// IsInodeID returns true if the string is a valid Inode ID (32-char hex or special root ID).
func IsInodeID(id string) bool {
	if id == RootID {
		return true
	}
	if len(id) != InodeIDLength {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// ChunkEntry represents a single chunk of a file and its location.
// ChunkEntry represents a single data chunk and its storage locations.
type ChunkEntry struct {
	ID    string   `json:"id"`
	Nodes []string `json:"nodes"`          // Storage Node IDs
	URLs  []string `json:"urls,omitempty"` // Public URLs (Resolved by Metadata Server)
}

// ChunkPage is a pagination structure for storing large file manifests.
// ChunkPage represents a paginated collection of chunk entries for large files.
type ChunkPage struct {
	ID     string       `json:"id"`
	Chunks []ChunkEntry `json:"chunks"`
}

// UserUsage tracks the resource usage of a user.
type UserUsage struct {
	InodeCount int64 `json:"inodes"`
	TotalBytes int64 `json:"bytes"`
}

// UserQuota defines the resource limits for a user.
type UserQuota struct {
	MaxInodes int64 `json:"max_inodes"`
	MaxBytes  int64 `json:"max_bytes"`
}

// User represents a registered user in the system.
// IDs are HMAC(email) to preserve privacy.
type User struct {
	ID      string    `json:"id"` // HMAC(email)
	UID     uint32    `json:"uid"`
	SignKey []byte    `json:"sign_key"`
	EncKey  []byte    `json:"enc_key"`
	Usage   UserUsage `json:"usage"`
	Quota   UserQuota `json:"quota"`
	IsAdmin bool      `json:"is_admin"`
	Locked  bool      `json:"locked"`
}

// RegisterUserRequest is the payload for user registration.
type RegisterUserRequest struct {
	JWT     string `json:"jwt"`
	SignKey []byte `json:"sign_key"`
	EncKey  []byte `json:"enc_key"`
}

// MemberEntry represents a record in the encrypted member registry.
type MemberEntry struct {
	UserID string `json:"uid"`
	Info   string `json:"info"`
}

// GroupClientBlob contains non-enforcement metadata for a group.
type GroupClientBlob struct {
	Name string `json:"name"`
}

// Group represents a user group for sharing access.
// Group represents a security group in DistFS, including membership and keys.
type Group struct {
	ID                string          `json:"id"`
	GID               uint32          `json:"gid"`
	OwnerID           string          `json:"owner_id"` // User ID or Group ID
	Members           map[string]bool `json:"members"`
	EncKey            []byte          `json:"enc_key"`                // ML-KEM Public Key
	SignKey           []byte          `json:"sign_key"`               // ML-DSA Public Key
	EncryptedSignKey  []byte          `json:"enc_sign_key,omitempty"` // Wrapped Group Private Sign Key
	Lockbox           crypto.Lockbox  `json:"lockbox"`
	RegistryLockbox   crypto.Lockbox  `json:"registry_lockbox"` // Only for authorized managers
	EncryptedRegistry []byte          `json:"enc_registry"`     // Member list encrypted with Registry Key
	ClientBlob        []byte          `json:"client_blob,omitempty"`
	Usage             UserUsage       `json:"usage"` // Resource usage
	Quota             UserQuota       `json:"quota"` // Resource limits
	Version           uint64          `json:"version"`
	IsSystem          bool            `json:"is_system"` // Only settable by Admin
	SignerID          string          `json:"signer_id,omitempty"`
	Signature         []byte          `json:"signature,omitempty"`
	QuotaEnabled      bool            `json:"quota_enabled"` // Immutable, decided at creation

	// Client-side transient state
	name string
}

func (g *Group) GetName() string  { return g.name }
func (g *Group) SetName(s string) { g.name = s }

type GroupRole string

const (
	RoleOwner   GroupRole = "owner"
	RoleManager GroupRole = "manager"
	RoleMember  GroupRole = "member"
)

type GroupListEntry struct {
	ID           string         `json:"id"`
	OwnerID      string         `json:"owner_id"`
	Role         GroupRole      `json:"role"`
	EncKey       []byte         `json:"enc_key"` // Group Public Key
	Lockbox      crypto.Lockbox `json:"lockbox"` // For name decryption
	IsSystem     bool           `json:"is_system"`
	ClientBlob   []byte         `json:"client_blob,omitempty"`
	Usage        UserUsage      `json:"usage"`
	Quota        UserQuota      `json:"quota"`
	QuotaEnabled bool           `json:"quota_enabled"`
}

type GroupListResponse struct {
	Groups []GroupListEntry `json:"groups"`
}

// CreateGroupRequest is the payload for group creation.
type CreateGroupRequest struct {
	ID           string `json:"id"`
	QuotaEnabled bool   `json:"quota_enabled"`
}

// Hash calculates a cryptographic hash of the group metadata for signing.
func (g *Group) Hash() []byte {
	h := crypto.NewHash()
	h.Write([]byte("DistFS-Group-v1|"))
	h.Write([]byte("group-id:" + g.ID + "|"))

	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, g.Version)
	h.Write([]byte("v:"))
	h.Write(v)
	h.Write([]byte("|"))

	if g.IsSystem {
		h.Write([]byte("sys:1|"))
	} else {
		h.Write([]byte("sys:0|"))
	}

	h.Write([]byte("client_blob:"))
	h.Write(g.ClientBlob)
	h.Write([]byte("|"))

	h.Write([]byte("owner:" + g.OwnerID + "|"))
	h.Write([]byte("signer:" + g.SignerID + "|"))

	// Write Members (sorted for canonicality)
	h.Write([]byte("members:"))
	keys := make([]string, 0, len(g.Members))
	for k := range g.Members {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte(":"))
		if g.Members[k] {
			h.Write([]byte("1,"))
		} else {
			h.Write([]byte("0,"))
		}
	}
	h.Write([]byte("|"))

	h.Write([]byte("enc_key:"))
	h.Write(g.EncKey)
	h.Write([]byte("|"))

	h.Write([]byte("sign_key:"))
	h.Write(g.SignKey)
	h.Write([]byte("|"))

	h.Write([]byte("enc_sign_key:"))
	h.Write(g.EncryptedSignKey)
	h.Write([]byte("|"))

	// Write Lockbox (sorted for canonicality)
	if len(g.Lockbox) > 0 {
		h.Write([]byte("lockbox:"))
		recipients := make([]string, 0, len(g.Lockbox))
		for k := range g.Lockbox {
			recipients = append(recipients, k)
		}
		sort.Strings(recipients)
		for _, k := range recipients {
			entry := g.Lockbox[k]
			h.Write([]byte(k + ":"))
			h.Write(entry.KEMCiphertext)
			h.Write(entry.DEMCiphertext)
			h.Write([]byte(","))
		}
		h.Write([]byte("|"))
	}

	// Write RegistryLockbox (sorted for canonicality)
	if len(g.RegistryLockbox) > 0 {
		h.Write([]byte("registry_lockbox:"))
		recipients := make([]string, 0, len(g.RegistryLockbox))
		for k := range g.RegistryLockbox {
			recipients = append(recipients, k)
		}
		sort.Strings(recipients)
		for _, k := range recipients {
			entry := g.RegistryLockbox[k]
			h.Write([]byte(k + ":"))
			h.Write(entry.KEMCiphertext)
			h.Write(entry.DEMCiphertext)
			h.Write([]byte(","))
		}
		h.Write([]byte("|"))
	}

	h.Write([]byte("enc_registry:"))
	h.Write(g.EncryptedRegistry)
	h.Write([]byte("|"))

	// Include QuotaEnabled in hash (Phase 43)
	h.Write([]byte("quota_enabled:"))
	if g.QuotaEnabled {
		h.Write([]byte("1|"))
	} else {
		h.Write([]byte("0|"))
	}

	return h.Sum(nil)
}

func iif(cond bool, t, f string) string {
	if cond {
		return t
	}
	return f
}

// SignGroupForTest signs a group using a provided identity key.
func (g *Group) SignGroupForTest(signerID string, key *crypto.IdentityKey) {
	g.SignerID = signerID
	hash := g.Hash()
	g.Signature = key.Sign(hash)
}

// NodeStatus indicates the health/lifecycle state of a storage node.
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusDead     NodeStatus = "dead"
	NodeStatusDraining NodeStatus = "draining"
)

// Node represents a storage node in the cluster.
type Node struct {
	ID             string     `json:"id"`
	Address        string     `json:"address"`         // Public API Address
	ClusterAddress string     `json:"cluster_address"` // Internal Cluster API Address
	RaftAddress    string     `json:"raft_address"`
	Status         NodeStatus `json:"status"`
	PublicKey      []byte     `json:"public_key"` // TLS Public Key (Ed25519)
	SignKey        []byte     `json:"sign_key"`   // Metadata Sign Key (PQC)
	LastHeartbeat  int64      `json:"last_heartbeat"`
	Capacity       int64      `json:"capacity"`
	Used           int64      `json:"used"`
}

// ClusterStats aggregates storage information across the cluster.
type ClusterStats struct {
	TotalCapacity int64 `json:"total_capacity"`
	TotalUsed     int64 `json:"total_used"`
	NodeCount     int   `json:"node_count"`
}

// InodeClientBlob contains non-enforcement metadata for an inode.
type InodeClientBlob struct {
	Name          string `json:"name"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
	InlineData    []byte `json:"inline_data,omitempty"`
	MTime         int64  `json:"mtime"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
}

// POSIXAccess defines POSIX.1e draft standard Access Control Lists.
// Keys are DistFS User or Group string IDs. Values are the 3-bit mode (0-7).
type POSIXAccess struct {
	Users  map[string]uint32 `json:"users,omitempty"`
	Groups map[string]uint32 `json:"groups,omitempty"`
	Mask   *uint32           `json:"mask,omitempty"`
}

func (p *POSIXAccess) writeHash(h hash.Hash) {
	if p == nil {
		return
	}
	if len(p.Users) > 0 {
		h.Write([]byte("u:"))
		keys := make([]string, 0, len(p.Users))
		for k := range p.Users {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k + ":" + strconv.Itoa(int(p.Users[k])) + ","))
		}
		h.Write([]byte("|"))
	}
	if len(p.Groups) > 0 {
		h.Write([]byte("g:"))
		keys := make([]string, 0, len(p.Groups))
		for k := range p.Groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k + ":" + strconv.Itoa(int(p.Groups[k])) + ","))
		}
		h.Write([]byte("|"))
	}
	if p.Mask != nil {
		h.Write([]byte("m:" + strconv.Itoa(int(*p.Mask)) + "|"))
	}
}

// Inode represents a file or directory in the metadata layer.
type Inode struct {
	ID            string               `json:"id"`
	Links         map[string]bool      `json:"links"` // Set of "ParentID:NameHMAC"
	Type          InodeType            `json:"type"`
	OwnerID       string               `json:"owner_id"` // DistFS User ID
	GroupID       string               `json:"group_id"` // DistFS Group ID
	Mode          uint32               `json:"mode"`
	Size          uint64               `json:"size"`
	CTime         int64                `json:"ctime"`
	NLink         uint32               `json:"nlink"`
	ClientBlob    []byte               `json:"client_blob,omitempty"`
	Children      map[string]string    `json:"children"`
	ChunkManifest []ChunkEntry         `json:"manifest"`
	ChunkPages    []string             `json:"chunk_pages,omitempty"`
	Lockbox       crypto.Lockbox       `json:"lockbox"`
	Version       uint64               `json:"version"`
	IsSystem      bool                 `json:"is_system"`
	Leases        map[string]LeaseInfo `json:"leases,omitempty"` // Nonce -> LeaseInfo
	Unlinked      bool                 `json:"unlinked,omitempty"`

	AccessACL  *POSIXAccess `json:"access_acl,omitempty"`
	DefaultACL *POSIXAccess `json:"default_acl,omitempty"`

	// Manifest Integrity (Phase 31 & 47 & 50)
	Nonce              []byte `json:"nonce,omitempty"` // Cryptographic commitment to OwnerID
	SignerID           string `json:"signer_id,omitempty"`
	UserSig            []byte `json:"user_sig,omitempty"` // Signature by user's ML-DSA identity key
	GroupSig           []byte `json:"group_sig,omitempty"`
	OwnerDelegationSig []byte `json:"owner_delegation_sig,omitempty"` // Phase 50: Owner's signature over (ID + GroupID)

	// Client-side transient state (unexported, not in JSON)
	name          string
	symlinkTarget string
	inlineData    []byte
	mtime         int64
	uid           uint32
	gid           uint32
	fileKey       []byte
}

func (i *Inode) GetName() string           { return i.name }
func (i *Inode) SetName(s string)          { i.name = s }
func (i *Inode) GetSymlinkTarget() string  { return i.symlinkTarget }
func (i *Inode) SetSymlinkTarget(s string) { i.symlinkTarget = s }
func (i *Inode) GetInlineData() []byte     { return i.inlineData }
func (i *Inode) SetInlineData(d []byte)    { i.inlineData = d }
func (i *Inode) GetMTime() int64           { return i.mtime }
func (i *Inode) SetMTime(t int64)          { i.mtime = t }
func (i *Inode) GetUID() uint32            { return i.uid }
func (i *Inode) SetUID(u uint32)           { i.uid = u }
func (i *Inode) GetGID() uint32            { return i.gid }
func (i *Inode) SetGID(g uint32)           { i.gid = g }
func (i *Inode) GetSignerID() string       { return i.SignerID }
func (i *Inode) SetSignerID(s string)      { i.SignerID = s }
func (i *Inode) GetFileKey() []byte        { return i.fileKey }
func (i *Inode) SetFileKey(k []byte)       { i.fileKey = k }

// GenerateInodeID computes a cryptographically verifiable Inode ID bound to the creator's OwnerID.
// ID = hex(SHA256(OwnerID || "|" || Nonce))[:32]
func GenerateInodeID(ownerID string, nonce []byte) string {
	h := sha256.New()
	h.Write([]byte(ownerID))
	h.Write([]byte("|"))
	h.Write(nonce)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (i *Inode) DelegationHash() []byte {
	h := crypto.NewHash()
	h.Write([]byte("delegation_v1|"))
	h.Write([]byte("id:" + i.ID + "|"))
	h.Write([]byte("group:" + i.GroupID + "|"))

	if i.AccessACL != nil {
		h.Write([]byte("aacl:"))
		i.AccessACL.writeHash(h)
	}
	if i.DefaultACL != nil {
		h.Write([]byte("dacl:"))
		i.DefaultACL.writeHash(h)
	}

	return h.Sum(nil)
}

// ManifestHash calculates a cryptographic hash of the inode's manifest and critical metadata.
func (i *Inode) ManifestHash() []byte {
	h := crypto.NewHash()
	h.Write([]byte("id:" + i.ID + "|"))

	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, i.Version)
	h.Write([]byte("v:"))
	h.Write(v)
	h.Write([]byte("|"))

	m := make([]byte, 4)
	binary.BigEndian.PutUint32(m, i.Mode)
	h.Write([]byte("mode:"))
	h.Write(m)
	h.Write([]byte("|"))

	h.Write([]byte("gid_str:" + i.GroupID + "|"))

	if i.IsSystem {
		h.Write([]byte("sys:1|"))
	} else {
		h.Write([]byte("sys:0|"))
	}

	if i.AccessACL != nil {
		h.Write([]byte("aacl:"))
		i.AccessACL.writeHash(h)
	}
	if i.DefaultACL != nil {
		h.Write([]byte("dacl:"))
		i.DefaultACL.writeHash(h)
	}

	h.Write([]byte("client_blob:"))
	h.Write(i.ClientBlob)
	h.Write([]byte("|"))

	h.Write([]byte("owner:" + i.OwnerID + "|"))
	h.Write([]byte("signer:" + i.SignerID + "|"))

	t := make([]byte, 4)
	binary.BigEndian.PutUint32(t, uint32(i.Type))
	h.Write([]byte("type:"))
	h.Write(t)
	h.Write([]byte("|"))

	// Write Links (sorted for canonicality)
	if len(i.Links) > 0 {
		h.Write([]byte("links:"))
		linkTags := make([]string, 0, len(i.Links))
		for tag := range i.Links {
			linkTags = append(linkTags, tag)
		}
		sort.Strings(linkTags)
		for _, tag := range linkTags {
			h.Write([]byte(tag + ","))
		}
		h.Write([]byte("|"))
	}

	// Write Children (sorted keys for canonicality)
	h.Write([]byte("children:"))
	keys := make([]string, 0, len(i.Children))
	for k := range i.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k + ":" + i.Children[k] + ","))
	}
	h.Write([]byte("|"))

	// Write ChunkManifest
	h.Write([]byte("manifest:"))
	for _, entry := range i.ChunkManifest {
		h.Write([]byte(entry.ID + ","))
	}
	h.Write([]byte("|"))

	// Write ChunkPages
	h.Write([]byte("pages:"))
	for _, page := range i.ChunkPages {
		h.Write([]byte(page + ","))
	}
	h.Write([]byte("|"))

	// Write Lockbox (sorted for canonicality)
	if len(i.Lockbox) > 0 {
		h.Write([]byte("lockbox:"))
		recipients := make([]string, 0, len(i.Lockbox))
		for k := range i.Lockbox {
			recipients = append(recipients, k)
		}
		sort.Strings(recipients)
		for _, k := range recipients {
			entry := i.Lockbox[k]
			h.Write([]byte(k + ":"))
			h.Write(entry.KEMCiphertext)
			h.Write(entry.DEMCiphertext)
			h.Write([]byte(","))
		}
		h.Write([]byte("|"))
	}

	if len(i.OwnerDelegationSig) > 0 {
		h.Write([]byte("owner_delegation_sig:"))
		h.Write(i.OwnerDelegationSig)
		h.Write([]byte("|"))
	}

	return h.Sum(nil)
}

// SignInodeForTest signs an inode using a provided identity key.
// Only used for low-level metadata tests that bypass the client.
func (i *Inode) SignInodeForTest(userID string, key *crypto.IdentityKey) {
	i.SignerID = userID

	if len(i.ClientBlob) == 0 {
		// For tests, we simulate the ClientBlob so ManifestHash is consistent
		blob := InodeClientBlob{
			Name:          i.name,
			SymlinkTarget: i.symlinkTarget,
			InlineData:    i.inlineData,
			MTime:         i.mtime,
			UID:           i.uid,
			GID:           i.gid,
		}
		i.ClientBlob, _ = json.Marshal(blob)
	}

	hash := i.ManifestHash()
	i.UserSig = key.Sign(hash)
}

// AuthChallengeRequest initiates the login flow.
type AuthChallengeRequest struct {
	UserID string `json:"uid"`
}

// AuthChallengeResponse contains the challenge from the server.
type AuthChallengeResponse struct {
	Challenge []byte `json:"challenge"` // Random bytes
	Signature []byte `json:"sig"`       // Server signature over Challenge
}

// AuthChallengeSolve is the user's response to the challenge.
type AuthChallengeSolve struct {
	UserID    string `json:"uid"`
	Challenge []byte `json:"challenge"`
	Signature []byte `json:"sig"`               // User signature over Challenge
	EncKey    []byte `json:"enc_key,omitempty"` // Ephemeral ML-KEM-768 PK for session key establishment
}

// SessionToken is the internal structure of a session token.
type SessionToken struct {
	UserID string `json:"uid"`
	Expiry int64  `json:"exp"`
	Nonce  string `json:"nonce"`
}

// SignedSessionToken wraps the session token with a server signature.
type SignedSessionToken struct {
	Token     SessionToken `json:"token"`
	Signature []byte       `json:"sig"`
}

// SessionResponse returns the encoded session token.
type SessionResponse struct {
	Token string `json:"token"`            // Base64(SignedSessionToken)
	KEMCT []byte `json:"kem_ct,omitempty"` // Ephemeral ML-KEM-768 CT for session key establishment
}

type LeaseInfo struct {
	InodeID   string    `json:"inode_id"`
	SessionID string    `json:"session_id"`
	Nonce     string    `json:"nonce,omitempty"`
	Expiry    int64     `json:"expiry"`
	Type      LeaseType `json:"type"`
}

// CapabilityToken grants access to specific chunks for a limited time.
type CapabilityToken struct {
	Chunks         []string `json:"chunks"`
	Mode           string   `json:"mode"` // "R" or "W"
	Exp            int64    `json:"exp"`
	SessionBinding []byte   `json:"session_binding,omitempty"` // SHA256(SessionID)
}

// ClusterSignKey stores the cluster-wide token signing key information.
type ClusterSignKey struct {
	Public           []byte `json:"public"`
	EncryptedPrivate []byte `json:"enc_private"`
}

// SignedAuthToken is a CapabilityToken signed by the Metadata Server.
type SignedAuthToken struct {
	SignerID  string `json:"signer_id,omitempty"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"sig"`
}

func (s *SignedAuthToken) Marshal() []byte {
	b, _ := json.Marshal(s)
	return b
}

func (s *SignedAuthToken) Unmarshal(b []byte) error {
	return json.Unmarshal(b, s)
}

// WorldIdentity represents the public/private key pair for the 'world' user.
type WorldIdentity struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

// SealedRequest wraps an encrypted request payload.
type SealedRequest struct {
	UserID string `json:"uid"`
	Sealed []byte `json:"sealed"`
}

// SealedResponse wraps an encrypted response payload.
type SealedResponse struct {
	Sealed []byte `json:"sealed"`
}

// KeySyncBlob stores a passphrase-encrypted client configuration for synchronization.
type KeySyncBlob struct {
	KDF        string `json:"kdf"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}

// KeySyncRequest is the Raft command payload for storing a sync blob.
type KeySyncRequest struct {
	UserID string      `json:"uid"`
	Blob   KeySyncBlob `json:"blob"`
}

// SanitizeMode applies system-wide permission constraints (Phase 31).
func SanitizeMode(mode uint32, itype InodeType) uint32 {
	if itype == SymlinkType {
		return mode // Symlinks are traditionally 0777
	}
	return mode &^ 0002 // Prohibition of World-Writable
}

type SetAttrRequest struct {
	InodeID string  `json:"inode_id"`
	Mode    *uint32 `json:"mode,omitempty"`
	OwnerID *string `json:"owner_id,omitempty"`
	GroupID *string `json:"group_id,omitempty"`
	Size    *uint64 `json:"size,omitempty"`
	MTime   *int64  `json:"mtime,omitempty"`
}

type SetUserQuotaRequest struct {
	UserID    string  `json:"user_id"`
	MaxBytes  *uint64 `json:"max_bytes,omitempty"`
	MaxInodes *uint64 `json:"max_inodes,omitempty"`
}

type SetGroupQuotaRequest struct {
	GroupID   string  `json:"group_id"`
	MaxBytes  *uint64 `json:"max_bytes,omitempty"`
	MaxInodes *uint64 `json:"max_inodes,omitempty"`
}

// AdminSetUserLockRequest is the payload for locking/unlocking a user.
type AdminSetUserLockRequest struct {
	UserID string `json:"user_id"`
	Locked bool   `json:"locked"`
}

// Phase 48: Audit Types

// RedactedInode represents a version of an Inode safe for cluster-wide audit.
// It contains no cryptographic keys or private plaintext blobs.
type RedactedInode struct {
	ID                 string               `json:"id"`
	Links              map[string]bool      `json:"links"`
	Type               InodeType            `json:"type"`
	OwnerID            string               `json:"owner_id"`
	GroupID            string               `json:"group_id"`
	Mode               uint32               `json:"mode"`
	Size               uint64               `json:"size"`
	CTime              int64                `json:"ctime"`
	NLink              uint32               `json:"nlink"`
	Children           map[string]string    `json:"children,omitempty"`
	Version            uint64               `json:"version"`
	IsSystem           bool                 `json:"is_system"`
	Leases             map[string]LeaseInfo `json:"leases,omitempty"`
	Unlinked           bool                 `json:"unlinked,omitempty"`
	SignerID           string               `json:"signer_id"`
	BlobSize           int                  `json:"blob_size"`
	ChunkPageCount     int                  `json:"chunk_page_count"`
	RecipientIDs       []string             `json:"recipient_ids"` // List of User/Group IDs in lockbox
	RegistryRecipients []string             `json:"registry_recipients,omitempty"`
}

// RedactedUser represents a user record safe for cluster-wide audit.
type RedactedUser struct {
	ID      string    `json:"id"`
	UID     uint32    `json:"uid"`
	Usage   UserUsage `json:"usage"`
	Quota   UserQuota `json:"quota"`
	IsAdmin bool      `json:"is_admin"`
	Locked  bool      `json:"locked"`
}

// RedactedGroup represents a group record safe for cluster-wide audit.
type RedactedGroup struct {
	ID           string    `json:"id"`
	GID          uint32    `json:"gid"`
	OwnerID      string    `json:"owner_id"`
	Usage        UserUsage `json:"usage"`
	Quota        UserQuota `json:"quota"`
	QuotaEnabled bool      `json:"quota_enabled"`
	MemberCount  int       `json:"member_count"`
	IsSystem     bool      `json:"is_system"`
}

// InconsistencyReport flags a structural or logical corruption found during audit.
type InconsistencyReport struct {
	Type     string `json:"type"` // e.g. "LINK_ASYMMETRY", "QUOTA_MISMATCH"
	TargetID string `json:"target_id"`
	Message  string `json:"message"`
}

// AuditRecordType defines the type of record in the streaming audit log.
type AuditRecordType string

const (
	AuditInode         AuditRecordType = "inode"
	AuditUser          AuditRecordType = "user"
	AuditGroup         AuditRecordType = "group"
	AuditNode          AuditRecordType = "node"
	AuditLease         AuditRecordType = "lease"
	AuditGC            AuditRecordType = "gc"
	AuditInconsistency AuditRecordType = "inconsistency"
)

// AuditRecord is a single entry in the NDJSON audit stream.
type AuditRecord struct {
	Type    AuditRecordType      `json:"type"`
	Inode   *RedactedInode       `json:"inode,omitempty"`
	User    *RedactedUser        `json:"user,omitempty"`
	Group   *RedactedGroup       `json:"group,omitempty"`
	Node    *Node                `json:"node,omitempty"`
	Report  *InconsistencyReport `json:"report,omitempty"`
	GCChunk string               `json:"gc_chunk,omitempty"`
}

var (
	ErrExists                  = errors.New("already exists")
	ErrNotFound                = errors.New("not found")
	ErrConflict                = errors.New("version conflict")
	ErrStopIteration           = errors.New("iteration stopped")
	ErrAtomicRollback          = errors.New("atomic transaction failure")
	ErrLeaseRequired           = errors.New("lease required")
	ErrStructuralInconsistency = errors.New("structural inconsistency detected")
	ErrQuotaExceeded           = errors.New("quota exceeded")
	ErrQuotaDisabled           = errors.New("group quota is disabled")
)

type CommandType uint8

const (
	CmdCreateInode        CommandType = 1
	CmdUpdateInode        CommandType = 2
	CmdDeleteInode        CommandType = 3
	CmdRegisterNode       CommandType = 4
	CmdCreateUser         CommandType = 5
	CmdCreateGroup        CommandType = 6
	CmdUpdateGroup        CommandType = 7
	CmdAddChunkReplica    CommandType = 8
	CmdGCRemove           CommandType = 9
	CmdSetUserQuota       CommandType = 10
	CmdRotateKey          CommandType = 11
	CmdInitWorld          CommandType = 12
	CmdStoreKeySync       CommandType = 13
	CmdBatch              CommandType = 14
	CmdAcquireLeases      CommandType = 15
	CmdReleaseLeases      CommandType = 16
	CmdPromoteAdmin       CommandType = 17
	CmdStoreMetrics       CommandType = 18
	CmdSetGroupQuota      CommandType = 19
	CmdSetClusterSignKey  CommandType = 20
	CmdRemoveNode         CommandType = 21
	CmdRotateFSMKey       CommandType = 22
	CmdReencryptValue     CommandType = 23
	CmdAdminSetUserLock   CommandType = 24
	CmdRemoveChunkReplica CommandType = 25
)

type LogCommand struct {
	Type          CommandType       `json:"type"`
	Data          json.RawMessage   `json:"data"`
	UserID        string            `json:"uid,omitempty"`
	SessionNonce  string            `json:"sid,omitempty"`
	LeaseBindings map[string]string `json:"lease_bindings,omitempty"` // nameHMAC -> pathID
	Atomic        bool              `json:"atomic,omitempty"`         // Roll back entire transaction on any sub-command error
}

func (c LogCommand) Marshal() []byte {
	b, _ := json.Marshal(c)
	return b
}

type ReencryptRequest struct {
	Bucket []byte `json:"bucket"`
	Key    []byte `json:"key"`
}

type LeaseRequest struct {
	InodeIDs     []string  `json:"inode_ids"`
	SessionID    string    `json:"session_id"`
	Nonce        string    `json:"nonce,omitempty"`
	Duration     int64     `json:"duration"`
	UserID       string    `json:"user_id,omitempty"`
	Type         LeaseType `json:"type,omitempty"`
	Placeholders []Inode   `json:"placeholders,omitempty"`
}

type RotateKeyRequest struct {
	Gen uint32 `json:"gen"`
	Key []byte `json:"key"`
}

type RotateFSMKeyRequest struct {
	Gen    uint32 `json:"gen"`
	NewKey []byte `json:"new_key"`
}

type ClusterKey struct {
	ID        string `json:"id"`
	CreatedAt int64  `json:"created_at"`
	Key       []byte `json:"key"`
	EncKey    []byte `json:"enc_key,omitempty"`
	DecKey    []byte `json:"dec_key,omitempty"`
}

type AddReplicaRequest struct {
	InodeID string   `json:"inode_id"`
	ChunkID string   `json:"chunk_id"`
	NodeIDs []string `json:"node_ids"`
}
