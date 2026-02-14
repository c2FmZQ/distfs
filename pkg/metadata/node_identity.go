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
	"encoding/hex"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
)

// KeyData is a wrapper for serializing keys to disk.
type KeyData struct {
	Bytes []byte `json:"bytes"`
}

// LoadOrGenerateNodeKey loads the Ed25519 node key from storage,
// or generates a new one if it doesn't exist.
func LoadOrGenerateNodeKey(st *storage.Storage, name string) (*crypto.IdentityKey, error) {
	var kd KeyData
	if err := st.ReadDataFile(name, &kd); err == nil {
		return crypto.UnmarshalIdentityKey(kd.Bytes), nil
	}

	key, err := crypto.GenerateIdentityKey()
	if err != nil {
		return nil, err
	}

	kd.Bytes = key.MarshalPrivate()
	if err := st.SaveDataFile(name, kd); err != nil {
		return nil, err
	}

	return key, nil
}

// NodeIDFromKey derives the Raft Node ID from the public key.
func NodeIDFromKey(key *crypto.IdentityKey) string {
	return NodeIDFromPublicKey(key.Public())
}

// NodeIDFromPublicKey derives the Raft Node ID from the raw public key bytes.
func NodeIDFromPublicKey(pub []byte) string {
	if len(pub) < 8 {
		return hex.EncodeToString(pub)
	}
	return hex.EncodeToString(pub[:8])
}
