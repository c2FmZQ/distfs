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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"

	"github.com/c2FmZQ/storage"
)

// KeyData is a wrapper for serializing keys to disk.
type KeyData struct {
	Bytes []byte `json:"bytes"`
}

// NodeKey represents an Ed25519 key pair used for mTLS and Raft identity.
type NodeKey struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

func (k *NodeKey) Public() []byte  { return k.Pub }
func (k *NodeKey) Private() []byte { return k.Priv }

// LoadOrGenerateNodeKey loads the Ed25519 node key from storage,
// or generates a new one if it doesn't exist.
func LoadOrGenerateNodeKey(st *storage.Storage, name string) (*NodeKey, error) {
	var kd KeyData
	if err := st.ReadDataFile(name, &kd); err == nil {
		priv := ed25519.PrivateKey(kd.Bytes)
		pub := priv.Public().(ed25519.PublicKey)
		return &NodeKey{Priv: priv, Pub: pub}, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	kd.Bytes = priv
	if err := st.SaveDataFile(name, kd); err != nil {
		return nil, err
	}

	return &NodeKey{Priv: priv, Pub: pub}, nil
}

// NodeIDFromKey derives the Raft Node ID from the public key.
func NodeIDFromKey(key *NodeKey) string {
	return NodeIDFromPublicKey(key.Pub)
}

// NodeIDFromPublicKey derives the Raft Node ID from the raw public key bytes.
func NodeIDFromPublicKey(pub []byte) string {
	if len(pub) < 8 {
		return hex.EncodeToString(pub)
	}
	return hex.EncodeToString(pub[:8])
}
