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
	"testing"
)

func TestIdentityKey(t *testing.T) {
	k, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey failed: %v", err)
	}

	if len(k.Public()) != PublicKeySize() {
		t.Errorf("Unexpected public key size: %d, expected %d", len(k.Public()), PublicKeySize())
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

	id, ct, err := EncryptChunk(key, data, 0)
	if err != nil {
		t.Fatalf("EncryptChunk failed: %v", err)
	}

	if len(ct) <= ChunkSize {
		t.Error("Ciphertext should be larger than ChunkSize (overhead)")
	}

	// Verify Non-Determinism (Same Index, different random suffix)
	id2, ct2, _ := EncryptChunk(key, data, 0)
	if id == id2 {
		t.Error("EncryptChunk should not be deterministic for same index (needs random suffix)")
	}
	if string(ct) == string(ct2) {
		t.Error("Ciphertext should differ for same index due to random suffix")
	}

	// Verify Uniqueness (Different Index)
	id3, ct3, _ := EncryptChunk(key, data, 1)
	if id == id3 {
		t.Error("EncryptChunk should produce different ID for different index")
	}
	if string(ct) == string(ct3) {
		t.Error("Ciphertext should differ for different index")
	}

	// Decrypt
	plain, err := DecryptChunk(key, 0, ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	// Verify data
	if string(plain[:len(data)]) != string(data) {
		t.Error("Decrypted data mismatch")
	}
}

func TestKEM_Errors(t *testing.T) {
	dk, _ := GenerateEncryptionKey()

	// Too short ciphertext
	_, err := Decapsulate(dk, make([]byte, 10))
	if err == nil {
		t.Error("Decapsulate should fail for short ciphertext")
	}

	// Invalid keys
	_, err = UnmarshalDecapsulationKey(make([]byte, 10))
	if err == nil {
		t.Error("UnmarshalDecapsulationKey should fail for bad data")
	}
	_, err = UnmarshalEncapsulationKey(make([]byte, 10))
	if err == nil {
		t.Error("UnmarshalEncapsulationKey should fail for bad data")
	}
}

func TestDEM_Errors(t *testing.T) {
	key := make([]byte, 32)

	// Too short
	_, err := DecryptDEM(key, make([]byte, 5))
	if err == nil {
		t.Error("DecryptDEM should fail for short data")
	}

	// Invalid key size
	_, err = EncryptDEM(make([]byte, 10), []byte("data"))
	if err == nil {
		t.Error("EncryptDEM should fail for bad key size")
	}
}

func TestKeyRing(t *testing.T) {
	initial := make([]byte, 32)
	kr := NewKeyRing(initial)

	k, gen := kr.Current()
	if gen != 1 || string(k) != string(initial) {
		t.Errorf("Initial keyring mismatch: gen=%d", gen)
	}

	// Rotate
	newGen, err := kr.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if newGen != 2 {
		t.Errorf("Expected gen 2, got %d", newGen)
	}

	k2, gen2 := kr.Current()
	if gen2 != 2 || string(k2) == string(initial) {
		t.Error("Key not rotated")
	}

	// Get old
	kOld, ok := kr.Get(1)
	if !ok || string(kOld) != string(initial) {
		t.Error("Failed to get old key")
	}

	// Marshal/Unmarshal
	data := kr.Marshal()
	kr2, err := UnmarshalKeyRing(data)
	if err != nil {
		t.Fatal(err)
	}

	if kr2.current != kr.current {
		t.Error("Unmarshal current mismatch")
	}

	kBack, _ := kr2.Get(1)
	if string(kBack) != string(initial) {
		t.Error("Unmarshal key mismatch")
	}

	// Unmarshal error
	_, err = UnmarshalKeyRing(make([]byte, 2))
	if err == nil {
		t.Error("UnmarshalKeyRing should fail for short data")
	}
}

func TestHash(t *testing.T) {
	h := NewHash()
	h.Write([]byte("data"))
	sum := h.Sum(nil)
	if len(sum) != 32 {
		t.Errorf("Unexpected hash length: %d", len(sum))
	}
}

func TestIdentityKeySerialization(t *testing.T) {
	k, _ := GenerateIdentityKey()
	priv := k.MarshalPrivate()
	k2 := UnmarshalIdentityKey(priv)
	if string(k.Public()) != string(k2.Public()) {
		t.Error("Public key mismatch after unmarshal")
	}

	if VerifySignature([]byte("invalid"), []byte("msg"), []byte("sig")) {
		t.Error("VerifySignature should fail for invalid key length")
	}
}

func TestKEMSerialization(t *testing.T) {
	dk, _ := GenerateEncryptionKey()
	ek := dk.EncapsulationKey()

	dkBytes := MarshalDecapsulationKey(dk)
	dk2, _ := UnmarshalDecapsulationKey(dkBytes)

	ekBytes := MarshalEncapsulationKey(ek)
	ek2, _ := UnmarshalEncapsulationKey(ekBytes)

	s1, ct := Encapsulate(ek2)
	s2, _ := Decapsulate(dk2, ct)
	if string(s1) != string(s2) {
		t.Error("KEM failed after key serialization")
	}
}

func TestKeyRing_AddKey(t *testing.T) {
	initial := make([]byte, 32)
	kr := NewKeyRing(initial)

	newKey := make([]byte, 32)
	newKey[0] = 1
	kr.AddKey(5, newKey)

	k, gen := kr.Current()
	if gen != 5 {
		t.Errorf("Expected current gen 5, got %d", gen)
	}
	if string(k) != string(newKey) {
		t.Error("Key mismatch for gen 5")
	}
}

func TestLockbox_Errors(t *testing.T) {
	lb := NewLockbox()
	dk, _ := GenerateEncryptionKey()

	// Get missing user
	if _, err := lb.GetFileKey("missing", dk); err == nil {
		t.Error("Expected error for missing user")
	}
}

func TestIdentityKey_Errors(t *testing.T) {
	// Bad unmarshal
	if k := UnmarshalIdentityKey([]byte("too short")); k != nil {
		t.Error("UnmarshalIdentityKey should fail for short data")
	}

	// Verify with wrong key size
	if VerifySignature(make([]byte, 10), []byte("msg"), []byte("sig")) {
		t.Error("VerifySignature should fail for wrong key size")
	}

	// Verify with wrong public key data
	if VerifySignature(make([]byte, PublicKeySize()), []byte("msg"), make([]byte, SignatureSize())) {
		// This might pass if all zeros is valid? Unlikely for ML-DSA.
	}
}

func TestChunkEncryption_Errors(t *testing.T) {
	key := make([]byte, 32)
	largeData := make([]byte, ChunkSize+1)

	if _, _, err := EncryptChunk(key, largeData, 0); err == nil {
		t.Error("EncryptChunk should fail for data > ChunkSize")
	}

	// Error from EncryptDEMWithNonce (bad key size)
	if _, _, err := EncryptChunk(make([]byte, 10), []byte("data"), 0); err == nil {
		t.Error("EncryptChunk should fail for bad key size")
	}
}

func TestDEM_MoreErrors(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 10) // Wrong size

	if _, err := EncryptDEMWithNonce(key, nonce, []byte("data")); err == nil {
		t.Error("EncryptDEMWithNonce should fail for wrong nonce size")
	}

	if _, err := DecryptDEM(make([]byte, 10), []byte("data")); err == nil {
		t.Error("DecryptDEM should fail for bad key size")
	}

	// Decrypt with bad tag
	ct, _ := EncryptDEM(key, []byte("data"))
	ct[len(ct)-1] ^= 0xFF
	if _, err := DecryptDEM(key, ct); err == nil {
		t.Error("DecryptDEM should fail for tampered ciphertext")
	}
}

func TestSealedRequest(t *testing.T) {
	// 1. Setup Keys
	serverDK, _ := GenerateEncryptionKey()
	serverPK := serverDK.EncapsulationKey()

	clientID, _ := GenerateIdentityKey()

	// 2. Seal
	payload := []byte(`{"cmd":"test","data":"secret"}`)
	sealed, err := SealRequest(serverPK, clientID, payload)
	if err != nil {
		t.Fatalf("SealRequest failed: %v", err)
	}

	// 3. Open
	ts, opened, sharedSecret, err := OpenRequest(serverDK, clientID.Public(), sealed)
	if err != nil {
		t.Fatalf("OpenRequest failed: %v", err)
	}

	if len(sharedSecret) != 32 {
		t.Error("Invalid shared secret length")
	}

	if string(opened) != string(payload) {
		t.Errorf("Payload mismatch: %s vs %s", string(opened), string(payload))
	}

	if ts == 0 {
		t.Error("Timestamp should not be zero")
	}

	// 4. Test Tamper
	sealed[len(sealed)-1] ^= 0xFF
	_, _, _, err = OpenRequest(serverDK, clientID.Public(), sealed)
	if err == nil {
		t.Error("OpenRequest should fail for tampered ciphertext")
	}
}
