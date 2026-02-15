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
	ID            string          `json:"id"`
	EncryptedName []byte          `json:"enc_name"`
	GID           uint32          `json:"gid"`
	OwnerID       string          `json:"owner_id"` // User ID (string)
	Members       map[string]bool `json:"members"`
	EncKey        []byte          `json:"enc_key"`
	Lockbox       crypto.Lockbox  `json:"lockbox"`
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
	PublicKey      []byte     `json:"public_key"`
	LastHeartbeat  int64      `json:"last_heartbeat"`
	Capacity       int64      `json:"capacity"`
	Used           int64      `json:"used"`
}

// Inode represents a file or directory in the metadata layer.
type Inode struct {
	ID            string            `json:"id"`
	ParentID      string            `json:"parent_id"`
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
	NameHMAC      string            `json:"name_hmac,omitempty"` // HMAC(parentKey, name)
	InlineData    []byte            `json:"inline_data,omitempty"`
	Children      map[string]string `json:"children,omitempty"`
	ChunkManifest []ChunkEntry      `json:"manifest,omitempty"`
	ChunkPages    []string          `json:"chunk_pages,omitempty"`
	Lockbox       crypto.Lockbox    `json:"lockbox"`
	Version       uint64            `json:"version"`
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
