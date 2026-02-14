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

type InodeType uint8

const (
	FileType    InodeType = 0
	DirType     InodeType = 1
	SymlinkType InodeType = 2
)

const RootID = "root-directory-inode-id-0000000000"
const WorldID = "world"

type ChunkEntry struct {
	ID    string   `json:"id"`
	Nodes []string `json:"nodes"`
}

type ChunkPage struct {
	ID     string       `json:"id"`
	Chunks []ChunkEntry `json:"chunks"`
}

type UserUsage struct {
	InodeCount int64 `json:"inodes"`
	TotalBytes int64 `json:"bytes"`
}

type UserQuota struct {
	MaxInodes int64 `json:"max_inodes"`
	MaxBytes  int64 `json:"max_bytes"`
}

type User struct {
	ID      string    `json:"id"` // HMAC(email)
	UID     uint32    `json:"uid"`
	SignKey []byte    `json:"sign_key"`
	EncKey  []byte    `json:"enc_key"`
	Usage   UserUsage `json:"usage"`
	Quota   UserQuota `json:"quota"`
}

type RegisterUserRequest struct {
	JWT     string `json:"jwt"`
	SignKey []byte `json:"sign_key"`
	EncKey  []byte `json:"enc_key"`
}

type Group struct {
	ID            string          `json:"id"`
	EncryptedName []byte          `json:"enc_name"`
	GID           uint32          `json:"gid"`
	OwnerID       string          `json:"owner_id"` // User ID (string)
	Members       map[string]bool `json:"members"`
	EncKey        []byte          `json:"enc_key"`
	Lockbox       crypto.Lockbox  `json:"lockbox"`
}

type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusDead     NodeStatus = "dead"
	NodeStatusDraining NodeStatus = "draining"
)

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
	Children      map[string]string `json:"children,omitempty"`
	ChunkManifest []ChunkEntry      `json:"manifest,omitempty"`
	ChunkPages    []string          `json:"chunk_pages,omitempty"`
	Lockbox       crypto.Lockbox    `json:"lockbox"`
	Version       uint64            `json:"version"`
}

type AuthChallengeRequest struct {
	UserID string `json:"uid"`
}

type AuthChallengeResponse struct {
	Challenge []byte `json:"challenge"` // Random bytes
	Signature []byte `json:"sig"`       // Server signature over Challenge
}

type AuthChallengeSolve struct {
	UserID    string `json:"uid"`
	Challenge []byte `json:"challenge"`
	Signature []byte `json:"sig"` // User signature over Challenge
}

type SessionToken struct {
	UserID string `json:"uid"`
	Expiry int64  `json:"exp"`
	Nonce  string `json:"nonce"`
}

type SignedSessionToken struct {
	Token     SessionToken `json:"token"`
	Signature []byte       `json:"sig"`
}

type SessionResponse struct {
	Token string `json:"token"` // Base64(SignedSessionToken)
}

type CapabilityToken struct {
	Chunks []string `json:"chunks"`
	Mode   string   `json:"mode"` // "R" or "W"
	Exp    int64    `json:"exp"`
}

type SignedAuthToken struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"sig"`
}

type WorldIdentity struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

type SealedRequest struct {
	UserID string `json:"uid"`
	Sealed []byte `json:"sealed"`
}

type SealedResponse struct {
	Sealed []byte `json:"sealed"`
}
