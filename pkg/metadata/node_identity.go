//go:build !wasm

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
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/tpm"
)

// NodeKey represents an mTLS and Raft identity key. It wraps a crypto.Signer.
type NodeKey struct {
	Signer crypto.Signer
	Pub    []byte
}

func (k *NodeKey) Public() []byte { return k.Pub }

// LoadOrGenerateNodeKey loads the node key from storage, or generates a new one.
// If tpmDev is non-nil, it creates a hardware-bound ECC key in the TPM.
// Otherwise, it creates a software Ed25519 key.
func LoadOrGenerateNodeKey(st *storage.Storage, name string, tpmDev *tpm.TPM) (*NodeKey, error) {
	var kd KeyData
	if err := st.ReadDataFile(name, &kd); err == nil {
		if tpmDev != nil {
			// Try to load as TPM key
			key, err := tpmDev.UnmarshalKey(kd.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal TPM key (existing node.key is not a TPM key): %w", err)
			}
			pubBytes, _ := x509.MarshalPKIXPublicKey(key.Public())
			return &NodeKey{Signer: key, Pub: pubBytes}, nil
		}

		// Fallback/Default: Ed25519
		if len(kd.Bytes) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(kd.Bytes)
			pub := priv.Public().(ed25519.PublicKey)
			return &NodeKey{Signer: priv, Pub: pub}, nil
		}
	}

	// Generate New Key
	if tpmDev != nil {
		key, err := tpmDev.CreateKey(tpm.WithECC(elliptic.P256()))
		if err != nil {
			return nil, fmt.Errorf("failed to create TPM key: %w", err)
		}
		marshaled, err := key.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TPM key handle: %w", err)
		}
		kd.Bytes = marshaled
		if err := st.SaveDataFile(name, kd); err != nil {
			return nil, err
		}
		pubBytes, _ := x509.MarshalPKIXPublicKey(key.Public())
		return &NodeKey{Signer: key, Pub: pubBytes}, nil
	}

	// Default Software Key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	kd.Bytes = priv
	if err := st.SaveDataFile(name, kd); err != nil {
		return nil, err
	}

	return &NodeKey{Signer: priv, Pub: pub}, nil
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
