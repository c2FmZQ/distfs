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
	"crypto/ed25519"
	"testing"
)

func TestIdentityKey(t *testing.T) {
	k, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey failed: %v", err)
	}

	if len(k.Public()) != ed25519.PublicKeySize {
		t.Errorf("Unexpected public key size: %d", len(k.Public()))
	}

	msg := []byte("hello world")
	sig := k.Sign(msg)

	if !VerifySignature(k.Public(), msg, sig) {
		t.Error("Signature verification failed")
	}

	if VerifySignature(k.Public(), []byte("wrong"), sig) {
		t.Error("Verification passed for wrong message")
	}
}

func TestKEM(t *testing.T) {
	dk, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey failed: %v", err)
	}
	ek := dk.EncapsulationKey()

	secret, ct := Encapsulate(ek)

	recovered, err := Decapsulate(dk, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if string(secret) != string(recovered) {
		t.Error("Recovered secret mismatch")
	}
}

func TestLockbox(t *testing.T) {
	// Alice
	dkA, _ := GenerateEncryptionKey()
	ekA := dkA.EncapsulationKey()

	// Bob
	dkB, _ := GenerateEncryptionKey()
	ekB := dkB.EncapsulationKey()

	// File Key
	fileKey := []byte("01234567890123456789012345678901") // 32 bytes

	lb := NewLockbox()

	// Add Alice
	if err := lb.AddRecipient("alice", ekA, fileKey); err != nil {
		t.Fatalf("AddRecipient Alice failed: %v", err)
	}

	// Add Bob
	if err := lb.AddRecipient("bob", ekB, fileKey); err != nil {
		t.Fatalf("AddRecipient Bob failed: %v", err)
	}

	// Alice retrieve
	recKeyA, err := lb.GetFileKey("alice", dkA)
	if err != nil {
		t.Fatalf("Alice GetFileKey failed: %v", err)
	}
	if string(recKeyA) != string(fileKey) {
		t.Error("Alice recovered wrong key")
	}

	// Bob retrieve
	recKeyB, err := lb.GetFileKey("bob", dkB)
	if err != nil {
		t.Fatalf("Bob GetFileKey failed: %v", err)
	}
	if string(recKeyB) != string(fileKey) {
		t.Error("Bob recovered wrong key")
	}

	// Alice tries to read Bob's
	_, err = lb.GetFileKey("bob", dkA)
	if err == nil {
		t.Error("Alice should not be able to decrypt Bob's entry")
	}
}

func TestChunkEncryption(t *testing.T) {
	key := make([]byte, 32)
	data := []byte("hello distributed world")

	id, ct, err := EncryptChunk(key, data)
	if err != nil {
		t.Fatalf("EncryptChunk failed: %v", err)
	}

	if len(ct) <= ChunkSize {
		t.Error("Ciphertext should be larger than ChunkSize (overhead)")
	}

	// Verify CAS (Deterministic)
	id2, ct2, _ := EncryptChunk(key, data)
	if id != id2 {
		t.Error("EncryptChunk is not deterministic")
	}
	// Check bytes
	for i := range ct {
		if ct[i] != ct2[i] {
			t.Error("Ciphertext mismatch")
			break
		}
	}

	// Decrypt
	plain, err := DecryptChunk(key, ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	// Verify data
	if string(plain[:len(data)]) != string(data) {
		t.Error("Decrypted data mismatch")
	}
}
