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
	KEMCiphertext []byte `json:"kem,omitempty"` // Output of mlkem.Encapsulate
	DEMCiphertext []byte `json:"dem"`           // Encrypted File Key (using shared secret)
	Epoch         uint32 `json:"epoch"`         // Ratchet epoch used for this entry (0 for asymmetric)
}

// Lockbox stores access keys for users. Map UserID -> Entry.
type Lockbox map[string]LockboxEntry

// NewLockbox creates a new empty lockbox.
func NewLockbox() Lockbox {
	return make(Lockbox)
}

// AddRecipient adds a user to the lockbox using ML-KEM.
func (l Lockbox) AddRecipient(userID string, pubKey *mlkem.EncapsulationKey768, fileKey []byte, epoch uint32) error {
	secret, kemCT := Encapsulate(pubKey)

	demCT, err := EncryptDEM(secret, fileKey)
	if err != nil {
		return err
	}

	l[userID] = LockboxEntry{
		KEMCiphertext: kemCT,
		DEMCiphertext: demCT,
		Epoch:         epoch,
	}
	return nil
}

var ErrRecipientNotFound = fmt.Errorf("recipient not in lockbox")

// GetFileKey retrieves the file key for a user using their ML-KEM Decapsulation Key.
func (l Lockbox) GetFileKey(userID string, privKey *mlkem.DecapsulationKey768) ([]byte, error) {
	entry, ok := l[userID]
	if !ok {
		return nil, ErrRecipientNotFound
	}

	if len(entry.KEMCiphertext) == 0 {
		return nil, fmt.Errorf("recipient %s has no KEM ciphertext (entry is possibly corrupted or legacy symmetric)", userID)
	}

	secret, err := Decapsulate(privKey, entry.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("kem decapsulate failed for recipient %s: %w", userID, err)
	}

	return DecryptDEM(secret, entry.DEMCiphertext)
}
