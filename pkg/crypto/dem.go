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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptDEM encrypts plaintext using the given symmetric key (AES-256-GCM).
// It generates a random nonce.
// Returns nonce + ciphertext.
func EncryptDEM(key, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, 12) // Standard GCM nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return EncryptDEMWithNonce(key, nonce, plaintext)
}

// EncryptDEMWithNonce encrypts with a specific nonce.
// Returns nonce + ciphertext.
func EncryptDEMWithNonce(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptDEM decrypts the ciphertext (nonce + data) using the key.
func DecryptDEM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
