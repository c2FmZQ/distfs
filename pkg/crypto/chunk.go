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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const ChunkSize = 1024 * 1024 // 1 MB

// EncryptChunk pads plaintext to 1MB, encrypts it using chunkIndex for uniqueness, and returns the ChunkID (Hash) and Ciphertext.
func EncryptChunk(fileKey []byte, plaintext []byte, chunkIndex uint64) (chunkID string, ciphertext []byte, err error) {
	if len(plaintext) > ChunkSize {
		return "", nil, fmt.Errorf("plaintext larger than chunk size")
	}

	// Pad with zeros to ChunkSize for size hiding
	padded := make([]byte, ChunkSize)
	copy(padded, plaintext)

	// Deterministic Nonce based on Chunk Index (BigEndian, 12 bytes)
	// This ensures uniqueness per chunk within a file (assuming unique fileKey).
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], chunkIndex)

	// Encrypt
	ct, err := EncryptDEMWithNonce(fileKey, nonce, padded)
	if err != nil {
		return "", nil, err
	}

	// Hash
	hash := sha256.Sum256(ct)
	id := hex.EncodeToString(hash[:])

	return id, ct, nil
}

// DecryptChunk decrypts the ciphertext. It returns the full 1MB padded block.
// The caller is responsible for truncating to the actual useful data size (tracked in metadata).
func DecryptChunk(fileKey []byte, ciphertext []byte) ([]byte, error) {
	return DecryptDEM(fileKey, ciphertext)
}
