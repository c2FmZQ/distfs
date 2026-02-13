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
	"fmt"
)

// LockboxEntry contains the cryptographic material for a single recipient to retrieve the file key.
type LockboxEntry struct {
	KEMCiphertext []byte `json:"kem"` // Output of mlkem.Encapsulate
	DEMCiphertext []byte `json:"dem"` // Encrypted File Key (using shared secret)
}

// Lockbox stores access keys for users. Map UserID -> Entry.
type Lockbox map[string]LockboxEntry

func NewLockbox() Lockbox {
	return make(Lockbox)
}

// AddRecipient adds a user to the lockbox.
func (l Lockbox) AddRecipient(userID string, pubKey *mlkem.EncapsulationKey768, fileKey []byte) error {
	secret, kemCT := Encapsulate(pubKey)

	demCT, err := EncryptDEM(secret, fileKey)
	if err != nil {
		return err
	}

	l[userID] = LockboxEntry{
		KEMCiphertext: kemCT,
		DEMCiphertext: demCT,
	}
	return nil
}

var ErrRecipientNotFound = fmt.Errorf("recipient not in lockbox")

// GetFileKey retrieves the file key for a user.
func (l Lockbox) GetFileKey(userID string, privKey *mlkem.DecapsulationKey768) ([]byte, error) {
	entry, ok := l[userID]
	if !ok {
		return nil, ErrRecipientNotFound
	}

	secret, err := Decapsulate(privKey, entry.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("kem decapsulate failed: %w", err)
	}

	return DecryptDEM(secret, entry.DEMCiphertext)
}
