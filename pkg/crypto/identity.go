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
	"crypto/mldsa"
	"fmt"
)

// IdentityKey represents a user's asymmetric key pair for signing/identity.
// Currently backed by ML-DSA-65 (FIPS 204).
type IdentityKey struct {
	priv *mldsa.PrivateKey
	pub  *mldsa.PublicKey
}

// IdentityPublicKey represents a user's public signing key.
type IdentityPublicKey struct {
	pub *mldsa.PublicKey
}

func (k *IdentityPublicKey) Verify(msg, sig []byte) bool {
	return mldsa.Verify(k.pub, msg, sig, nil) == nil
}

func UnmarshalIdentityPublicKey(b []byte) (*IdentityPublicKey, error) {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), b)
	if err != nil {
		return nil, err
	}
	return &IdentityPublicKey{pub: pub}, nil
}

// GenerateIdentityKey creates a new ML-DSA (Dilithium) key pair.
func GenerateIdentityKey() (*IdentityKey, error) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %w", err)
	}
	return &IdentityKey{priv: priv, pub: priv.PublicKey()}, nil
}

// GenerateIdentityKeyFromSeed generates a key pair from a 32-byte seed.
func GenerateIdentityKeyFromSeed(seed []byte) (*IdentityKey, error) {
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key from seed: %w", err)
	}
	return &IdentityKey{priv: priv, pub: priv.PublicKey()}, nil
}

// Sign signs the message.
func (k *IdentityKey) Sign(msg []byte) []byte {
	sig, _ := k.priv.Sign(nil, msg, nil)
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
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), b)
	if err != nil {
		return nil
	}
	return &IdentityKey{priv: priv, pub: priv.PublicKey()}
}

// VerifySignature checks the signature against the public key.
func VerifySignature(pubKey []byte, msg, sig []byte) bool {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pubKey)
	if err != nil {
		return false
	}
	return mldsa.Verify(pub, msg, sig, nil) == nil
}

// SignatureSize returns the size of an ML-DSA-65 signature.
func SignatureSize() int {
	return mldsa.MLDSA65SignatureSize
}

// PublicKeySize returns the size of an ML-DSA-65 public key.
func PublicKeySize() int {
	return mldsa.MLDSA65PublicKeySize
}
