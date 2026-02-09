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

type ChunkEntry struct {
	ID    string   `json:"id"`
	Nodes []string `json:"nodes"`
}

type User struct {
	ID      string `json:"id"` // Still useful for lookup by email/username
	UID     uint32 `json:"uid"`
	SignKey []byte `json:"sign_key"`
	EncKey  []byte `json:"enc_key"`
	Name    string `json:"name"`
}

type Group struct {
	ID      string          `json:"id"`
	GID     uint32          `json:"gid"`
	OwnerID string          `json:"owner_id"` // User ID (string)
	Members map[string]bool `json:"members"`
	EncKey  []byte          `json:"enc_key"`
	Lockbox crypto.Lockbox  `json:"lockbox"`
}

type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusDead     NodeStatus = "dead"
	NodeStatusDraining NodeStatus = "draining"
)

type Node struct {
	ID            string     `json:"id"`
	Address       string     `json:"address"` // API Address
	RaftAddress   string     `json:"raft_address"`
	Status        NodeStatus `json:"status"`
	PublicKey     []byte     `json:"public_key"`
	LastHeartbeat int64      `json:"last_heartbeat"`
	Capacity      int64      `json:"capacity"`
	Used          int64      `json:"used"`
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
	ChunkManifest []ChunkEntry      `json:"manifest"`
	Lockbox       crypto.Lockbox    `json:"lockbox"`
	Version       uint64            `json:"version"`
}

type AuthToken struct {
	UserID string `json:"uid"`
	Time   int64  `json:"ts"`
	Nonce  string `json:"nonce"`
}

type SignedAuthToken struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"sig"`
}

type CapabilityToken struct {
	Chunks []string `json:"chunks"`
	Mode   string   `json:"mode"` // "R" or "W"
	Exp    int64    `json:"exp"`
}
