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
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// NewHash returns a new SHA256 hash.
func NewHash() hash.Hash {
	return sha256.New()
}

// GroupKeys represents the set of keys derived from an epoch seed.
type GroupKeys struct {
	SymmetricKey []byte
	EncKey       *mlkem.DecapsulationKey768
	SignKey      *IdentityKey
}

// DeriveGroupKeys derives the complete suite of epoch keys from a 64-byte seed using HKDF-SHA512.
func DeriveGroupKeys(epochSeed []byte) (*GroupKeys, error) {
	// HKDF-Extract and Expand to derive the required seeds.
	// We need: 32 bytes (Symmetric), 64 bytes (KEM), 32 bytes (DSA) = 128 bytes total.
	r := hkdf.New(sha512.New, epochSeed, nil, []byte("DistFS-Group-Keys-v1"))

	symKey := make([]byte, 32)
	kemSeed := make([]byte, 64)
	dsaSeed := make([]byte, 32)

	if _, err := io.ReadFull(r, symKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, kemSeed); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, dsaSeed); err != nil {
		return nil, err
	}

	// Derive Asymmetric Keys directly from high-entropy seeds
	encKey, err := mlkem.NewDecapsulationKey768(kemSeed)
	if err != nil {
		return nil, err
	}

	signKey, err := GenerateIdentityKeyFromSeed(dsaSeed)
	if err != nil {
		return nil, err
	}

	return &GroupKeys{
		SymmetricKey: symKey,
		EncKey:       encKey,
		SignKey:      signKey,
	}, nil
}

// DerivePreviousEpochKey implements the Hash Chain for forward secrecy.
// K_{N-1} = Hash(K_N)
// We use SHA-512 to maintain 64 bytes of entropy throughout the chain.
func DerivePreviousEpochKey(currentKey []byte) []byte {
	h := sha512.Sum512(currentKey)
	return h[:]
}

// DeriveEpochKey derives a specific epoch key from the seed.
// EpochKey = Hash^(MaxEpochs - Epoch)(EpochSeed)
func DeriveEpochKey(seed []byte, maxEpochs, currentEpoch uint32) ([]byte, error) {
	if currentEpoch > maxEpochs {
		return nil, fmt.Errorf("currentEpoch (%d) cannot exceed maxEpochs (%d)", currentEpoch, maxEpochs)
	}
	iterations := maxEpochs - currentEpoch

	key := make([]byte, len(seed))
	copy(key, seed)

	for i := uint32(0); i < iterations; i++ {
		h := sha512.Sum512(key)
		key = h[:]
	}
	return key, nil
}
