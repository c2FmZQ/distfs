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

type Inode struct {
	ID            string         `json:"id"`
	ParentID      string         `json:"parent_id"`
	Type          InodeType      `json:"type"`
	OwnerID       string         `json:"owner_id"`
	GroupID       string         `json:"group_id"`
	Mode          uint32         `json:"mode"`
	Size          uint64         `json:"size"`
	EncryptedName []byte         `json:"enc_name"`
	ChunkManifest []string       `json:"manifest"`
	Lockbox       crypto.Lockbox `json:"lockbox"`
	Version       uint64         `json:"version"`
}
