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
)

// GenerateEncryptionKey generates a post-quantum key pair for encryption (ML-KEM-768).
func GenerateEncryptionKey() (*mlkem.DecapsulationKey768, error) {
	return mlkem.GenerateKey768()
}

// Encapsulate generates a shared secret and its ciphertext for the given public key.
func Encapsulate(pubKey *mlkem.EncapsulationKey768) ([]byte, []byte) {
	return pubKey.Encapsulate()
}

// Decapsulate recovers the shared secret from the ciphertext using the private key.
func Decapsulate(privKey *mlkem.DecapsulationKey768, ciphertext []byte) ([]byte, error) {
	return privKey.Decapsulate(ciphertext)
}
