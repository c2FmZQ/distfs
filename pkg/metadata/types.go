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
	FileType InodeType = 0
	DirType  InodeType = 1
)

type ChunkEntry struct {
	ID    string   `json:"id"`
	Nodes []string `json:"nodes"`
}

type User struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"public_key"`
	Name      string `json:"name"`
}

type Group struct {
	ID        string         `json:"id"`
	OwnerID   string         `json:"owner_id"`
	Members   map[string]bool `json:"members"` // UserID -> bool
	PublicKey []byte         `json:"public_key"`
	Lockbox   crypto.Lockbox `json:"lockbox"`
}

type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusDead     NodeStatus = "dead"
	NodeStatusDraining NodeStatus = "draining"
)

type Node struct {
	ID            string     `json:"id"`
	Address       string     `json:"address"` // Data API Address
	Status        NodeStatus `json:"status"`
	LastHeartbeat int64      `json:"last_heartbeat"`
	Capacity      int64      `json:"capacity"`
	Used          int64      `json:"used"`
}

type Inode struct {
	ID            string         `json:"id"`
	ParentID      string         `json:"parent_id"`
	Type          InodeType      `json:"type"`
	OwnerID       string         `json:"owner_id"`
	GroupID       string         `json:"group_id"`
	Mode          uint32         `json:"mode"`
	Size          uint64         `json:"size"`
	EncryptedName []byte         `json:"enc_name"`
	ChunkManifest []ChunkEntry   `json:"manifest"`
	Lockbox       crypto.Lockbox `json:"lockbox"`
	Version       uint64         `json:"version"`
}