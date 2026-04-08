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
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TODO: Switch to crypto/mldsa (standard library) when it becomes available in Go (planned for Go 1.27).

// IdentityKey represents a user's asymmetric key pair for signing/identity.
// Currently backed by ML-DSA-65 (FIPS 204).
type IdentityKey struct {
	priv *mldsa65.PrivateKey
	pub  *mldsa65.PublicKey
}

// IdentityPublicKey represents a user's public signing key.
type IdentityPublicKey struct {
	pub *mldsa65.PublicKey
}

func (k *IdentityPublicKey) Verify(msg, sig []byte) bool {
	return mldsa65.Verify(k.pub, msg, nil, sig)
}

func UnmarshalIdentityPublicKey(b []byte) (*IdentityPublicKey, error) {
	if len(b) != mldsa65.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return &IdentityPublicKey{pub: &pub}, nil
}

func UnmarshalIdentityPrivateKey(b []byte) (*IdentityKey, error) {
	if len(b) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	// ML-DSA private key usually contains the public key bytes
	return &IdentityKey{priv: &priv, pub: priv.Public().(*mldsa65.PublicKey)}, nil
}

// GenerateIdentityKey creates a new random identity key.
func GenerateIdentityKey() (*IdentityKey, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %w", err)
	}
	return &IdentityKey{priv: priv, pub: pub}, nil
}

// GenerateIdentityKeyFromSeed generates a key pair from a 32-byte seed.
func GenerateIdentityKeyFromSeed(seed []byte) (*IdentityKey, error) {
	// ML-DSA-65 requires a 32-byte seed.
	// We use bytes.NewReader(seed) as the entropy source for deterministic generation.
	pub, priv, err := mldsa65.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key from seed: %w", err)
	}
	return &IdentityKey{priv: priv, pub: pub}, nil
}

// Sign signs the message.
func (k *IdentityKey) Sign(msg []byte) []byte {
	sig, _ := k.priv.Sign(rand.Reader, msg, nil)
	return sig
}

// Public returns the public key bytes.
func (k *IdentityKey) Public() []byte {
	return k.pub.Bytes()
}

// MarshalPrivate serializes the private key.
func (k *IdentityKey) MarshalPrivate() []byte {
	return k.priv.Bytes()
}

// UnmarshalIdentityKey deserializes the private key.
func UnmarshalIdentityKey(b []byte) *IdentityKey {
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(b); err != nil {
		return nil
	}
	pub := priv.Public().(*mldsa65.PublicKey)
	return &IdentityKey{priv: &priv, pub: pub}
}

// VerifySignature checks the signature against the public key.
func VerifySignature(pubKey []byte, msg, sig []byte) bool {
	if len(pubKey) != mldsa65.PublicKeySize {
		return false
	}
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(pubKey); err != nil {
		return false
	}
	// ctx is optional, we use nil
	return mldsa65.Verify(&pub, msg, nil, sig)
}

// SignatureSize returns the size of an ML-DSA-65 signature.
func SignatureSize() int {
	return mldsa65.SignatureSize
}

// PublicKeySize returns the size of an ML-DSA-65 public key.
func PublicKeySize() int {
	return mldsa65.PublicKeySize
}
