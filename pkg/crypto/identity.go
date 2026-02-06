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

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// IdentityKey represents a user's asymmetric key pair for signing/identity.
// Currently backed by Ed25519.
type IdentityKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// GenerateIdentityKey creates a new random identity key.
func GenerateIdentityKey() (*IdentityKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %w", err)
	}
	return &IdentityKey{priv: priv, pub: pub}, nil
}

// Sign signs the message.
func (k *IdentityKey) Sign(msg []byte) []byte {
	return ed25519.Sign(k.priv, msg)
}

// Public returns the public key bytes.
func (k *IdentityKey) Public() []byte {
	// Make a copy to prevent modification
	p := make([]byte, len(k.pub))
	copy(p, k.pub)
	return p
}

// VerifySignature checks the signature against the public key.
func VerifySignature(pubKey []byte, msg, sig []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pubKey, msg, sig)
}
