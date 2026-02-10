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
	"os"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

// LoadOrGenerateNodeKey loads the Ed25519 node key from the given path,
// or generates a new one if it doesn't exist.
func LoadOrGenerateNodeKey(path string) (*crypto.IdentityKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		return crypto.UnmarshalIdentityKey(b), nil
	}

	key, err := crypto.GenerateIdentityKey()
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, key.MarshalPrivate(), 0600); err != nil {
		return nil, err
	}

	return key, nil
}

// NodeIDFromKey derives the Raft Node ID from the public key.
// The ID is the first 16 characters (8 bytes) of the hex-encoded SHA-256 hash of the public key.
// Wait, plan says: "derived from the first 8 bytes of the corresponding Ed25519 public key (hex-encoded)."
// "first 8 bytes of the public key" -> hex encoded -> 16 chars.
func NodeIDFromKey(key *crypto.IdentityKey) string {
	pub := key.Public()
	// Plan: "first 8 bytes of the corresponding Ed25519 public key (hex-encoded)"
	// So take first 8 bytes of pub key, then hex encode.
	if len(pub) < 8 {
		// Should not happen for Ed25519 (32 bytes)
		return hex.EncodeToString(pub)
	}
	return hex.EncodeToString(pub[:8])
}
