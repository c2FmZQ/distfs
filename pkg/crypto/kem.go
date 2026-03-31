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
	"crypto/rand"
	"fmt"
)

// GenerateEncryptionKey generates a post-quantum key pair for encryption (ML-KEM-768).
func GenerateEncryptionKey() (*mlkem.DecapsulationKey768, error) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey768(seed)
}

// Encapsulate generates a shared secret and its ciphertext for the given public key.
func Encapsulate(pubKey *mlkem.EncapsulationKey768) ([]byte, []byte) {
	return pubKey.Encapsulate()
}

// Decapsulate recovers the shared secret from the ciphertext using the private key.
func Decapsulate(privKey *mlkem.DecapsulationKey768, ciphertext []byte) ([]byte, error) {
	return privKey.Decapsulate(ciphertext)
}

// MarshalDecapsulationKey serializes the private key (returns the 64-byte seed).
func MarshalDecapsulationKey(dk *mlkem.DecapsulationKey768) []byte {
	return dk.Bytes()
}

// UnmarshalDecapsulationKey deserializes the private key (expects the 64-byte seed).
func UnmarshalDecapsulationKey(b []byte) (*mlkem.DecapsulationKey768, error) {
	if len(b) != 64 {
		// If we have the full marshaled key (1184 bytes), we can't use it with NewDecapsulationKey768.
		// This suggests we should have stored the seed.
		// For now, let's log the error.
		return nil, fmt.Errorf("mlkem: invalid seed length %d (expected 64)", len(b))
	}
	return mlkem.NewDecapsulationKey768(b)
}

// MarshalEncapsulationKey serializes the public key.
func MarshalEncapsulationKey(ek *mlkem.EncapsulationKey768) []byte {
	return ek.Bytes()
}

// UnmarshalEncapsulationKey deserializes the public key.
func UnmarshalEncapsulationKey(b []byte) (*mlkem.EncapsulationKey768, error) {
	return mlkem.NewEncapsulationKey768(b)
}
