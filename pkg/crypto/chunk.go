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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const ChunkSize = 1024 * 1024 // 1 MB

// DeriveChunkNonce generates a synthetic nonce from the file key and chunk index.
func DeriveChunkNonce(fileKey []byte, chunkIndex uint64) []byte {
	mac := hmac.New(sha256.New, fileKey)
	idx := make([]byte, 8)
	binary.BigEndian.PutUint64(idx, chunkIndex)
	mac.Write([]byte("CHUNK_NONCE_V1"))
	mac.Write(idx)
	return mac.Sum(nil)[:12]
}

// EncryptChunk pads plaintext to 1MB, encrypts it using chunkIndex for uniqueness, and returns the ChunkID (Hash) and Ciphertext.
func EncryptChunk(fileKey []byte, plaintext []byte, chunkIndex uint64) (chunkID string, ciphertext []byte, err error) {
	if len(plaintext) > ChunkSize {
		return "", nil, fmt.Errorf("plaintext larger than chunk size")
	}

	// Pad with zeros to ChunkSize for size hiding
	padded := make([]byte, ChunkSize)
	copy(padded, plaintext)

	// Synthetic HMAC Nonce
	nonce := DeriveChunkNonce(fileKey, chunkIndex)

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
func DecryptChunk(fileKey []byte, chunkIndex uint64, ciphertext []byte) ([]byte, error) {
	nonce := DeriveChunkNonce(fileKey, chunkIndex)
	return DecryptDEMWithNonce(fileKey, nonce, ciphertext)
}
