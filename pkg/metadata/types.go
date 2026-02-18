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
	"encoding/binary"
	"sort"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

// OIDCConfig represents the subset of OpenID Connect configuration needed by clients.
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

const (
	// RootID is the fixed ID of the root directory.
	RootID = "root-directory-inode-id-0000000000"
	// WorldID is the reserved ID for the 'world' recipient in lockboxes.
	WorldID = "world"
	// InlineLimit is the maximum size of a file that can be inlined in metadata.
	InlineLimit = 4096
)

// ChunkEntry represents a single chunk of a file and its location.
type ChunkEntry struct {
	ID    string   `json:"id"`
	Nodes []string `json:"nodes"`          // Storage Node IDs
	URLs  []string `json:"urls,omitempty"` // Public URLs (Resolved by Metadata Server)
}

// ChunkPage is a pagination structure for storing large file manifests.
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
}

// RegisterUserRequest is the payload for user registration.
type RegisterUserRequest struct {
	JWT     string `json:"jwt"`
	SignKey []byte `json:"sign_key"`
	EncKey  []byte `json:"enc_key"`
}

// Group represents a user group for sharing access.
type Group struct {
	ID               string          `json:"id"`
	EncryptedName    []byte          `json:"enc_name"`
	GID              uint32          `json:"gid"`
	OwnerID          string          `json:"owner_id"` // User ID (string)
	Members          map[string]bool `json:"members"`
	EncKey           []byte          `json:"enc_key"`                // ML-KEM Public Key
	SignKey          []byte          `json:"sign_key"`               // ML-DSA Public Key
	EncryptedSignKey []byte          `json:"enc_sign_key,omitempty"` // Wrapped Group Private Sign Key
	Lockbox          crypto.Lockbox  `json:"lockbox"`
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

type AdminChownRequest struct {
	InodeID string  `json:"inode_id"`
	OwnerID *string `json:"owner_id,omitempty"` // New DistFS User ID
	GroupID *string `json:"group_id,omitempty"` // New DistFS Group ID
	UID     *uint32 `json:"uid,omitempty"`      // New POSIX UID
	GID     *uint32 `json:"gid,omitempty"`      // New POSIX GID
}

type AdminChmodRequest struct {
	InodeID string `json:"inode_id"`
	Mode    uint32 `json:"mode"`
}

// Inode represents a file or directory in the metadata layer.
type Inode struct {
	ID            string            `json:"id"`
	Links         map[string]bool   `json:"links,omitempty"` // Set of "ParentID:NameHMAC"
	Type          InodeType         `json:"type"`
	OwnerID       string            `json:"owner_id"` // DistFS User ID
	GroupID       string            `json:"group_id"` // DistFS Group ID
	UID           uint32            `json:"uid"`      // POSIX UID
	GID           uint32            `json:"gid"`      // POSIX GID
	Mode          uint32            `json:"mode"`
	Size          uint64            `json:"size"`
	MTime         int64             `json:"mtime"` // Nanoseconds
	CTime         int64             `json:"ctime"` // Nanoseconds
	NLink         uint32            `json:"nlink"`
	SymlinkTarget string            `json:"symlink_target,omitempty"`
	EncryptedName []byte            `json:"enc_name"`
	InlineData    []byte            `json:"inline_data,omitempty"`
	Children      map[string]string `json:"children,omitempty"`
	ChunkManifest []ChunkEntry      `json:"manifest,omitempty"`
	ChunkPages    []string          `json:"chunk_pages,omitempty"`
	Lockbox       crypto.Lockbox    `json:"lockbox"`
	Version       uint64            `json:"version"`
	LeaseOwner    string            `json:"lease_owner,omitempty"`
	LeaseExpiry   int64             `json:"lease_expiry,omitempty"`

	// Manifest Integrity (Phase 31)
	SignerID          string   `json:"signer_id,omitempty"` // User ID of the last writer
	UserSig           []byte   `json:"user_sig,omitempty"`  // Signature by user's ML-DSA identity key
	GroupSig          []byte   `json:"group_sig,omitempty"` // Signature by group's ML-DSA key
	AuthorizedSigners []string `json:"auth_signers,omitempty"`
}

// ManifestHash calculates a cryptographic hash of the inode's manifest and critical metadata.
func (i *Inode) ManifestHash() []byte {
	h := crypto.NewHash()
	h.Write([]byte("id:" + i.ID + "|"))

	v := make([]byte, 8)
	binary.LittleEndian.PutUint64(v, i.Version)
	h.Write([]byte("v:"))
	h.Write(v)
	h.Write([]byte("|"))

	m := make([]byte, 4)
	binary.LittleEndian.PutUint32(m, i.Mode)
	h.Write([]byte("mode:"))
	h.Write(m)
	h.Write([]byte("|"))

	uid := make([]byte, 4)
	binary.LittleEndian.PutUint32(uid, i.UID)
	h.Write([]byte("uid:"))
	h.Write(uid)
	h.Write([]byte("|"))

	gid := make([]byte, 4)
	binary.LittleEndian.PutUint32(gid, i.GID)
	h.Write([]byte("gid:"))
	h.Write(gid)
	h.Write([]byte("|"))

	h.Write([]byte("gid_str:" + i.GroupID + "|"))

	if i.SymlinkTarget != "" {
		h.Write([]byte("symlink:" + i.SymlinkTarget + "|"))
	}

	mt := make([]byte, 8)
	binary.LittleEndian.PutUint64(mt, uint64(i.MTime))
	h.Write([]byte("mtime:"))
	h.Write(mt)
	h.Write([]byte("|"))

	nl := make([]byte, 4)
	binary.LittleEndian.PutUint32(nl, i.NLink)
	h.Write([]byte("nlink:"))
	h.Write(nl)
	h.Write([]byte("|"))

	s := make([]byte, 8)
	binary.LittleEndian.PutUint64(s, i.Size)
	h.Write([]byte("s:"))
	h.Write(s)
	h.Write([]byte("|"))

	h.Write([]byte("owner:" + i.OwnerID + "|"))
	h.Write([]byte("signer:" + i.SignerID + "|"))

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

	// Write InlineData
	h.Write([]byte("inline:"))
	h.Write(i.InlineData)
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

	// Write EncryptedName
	if len(i.EncryptedName) > 0 {
		h.Write([]byte("encname:"))
		h.Write(i.EncryptedName)
		h.Write([]byte("|"))
	}

	// Write AuthorizedSigners (sorted for canonicality)
	if len(i.AuthorizedSigners) > 0 {
		signers := make([]string, len(i.AuthorizedSigners))
		copy(signers, i.AuthorizedSigners)
		sort.Strings(signers)
		h.Write([]byte("auth:"))
		for _, signer := range signers {
			h.Write([]byte(signer + ","))
		}
		h.Write([]byte("|"))
	}

	return h.Sum(nil)
}

// SignInodeForTest signs an inode using a provided identity key.
// Only used for low-level metadata tests that bypass the client.
func (i *Inode) SignInodeForTest(userID string, key *crypto.IdentityKey) {
	i.SignerID = userID
	if len(i.AuthorizedSigners) == 0 && i.OwnerID != "" {
		i.AuthorizedSigners = []string{i.OwnerID}
	}
	// Note: We use Version+1 because FSM increments version during apply
	orig := i.Version
	i.Version++
	hash := i.ManifestHash()
	i.UserSig = key.Sign(hash)
	i.Version = orig
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
	Signature []byte `json:"sig"` // User signature over Challenge
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
	Token string `json:"token"` // Base64(SignedSessionToken)
}

// CapabilityToken grants access to specific chunks on Data Nodes.
type CapabilityToken struct {
	Chunks []string `json:"chunks"`
	Mode   string   `json:"mode"` // "R" or "W"
	Exp    int64    `json:"exp"`
}

// SignedAuthToken is a CapabilityToken signed by the Metadata Server.
type SignedAuthToken struct {
	SignerID  string `json:"signer_id,omitempty"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"sig"`
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
