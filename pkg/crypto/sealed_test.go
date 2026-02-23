// Copyright 2026 TTBT Enterprises LLC
package crypto

import (
	"bytes"
	"testing"
)

func TestOpenRequestSymmetric(t *testing.T) {
	serverDK, _ := GenerateEncryptionKey()
	serverPK := serverDK.EncapsulationKey()
	clientID, _ := GenerateIdentityKey()
	payload := []byte("test symmetric payload")

	sealed, err := SealRequest(serverPK, clientID, payload)
	if err != nil {
		t.Fatal(err)
	}

	// First open normally to get shared secret
	_, _, sharedSecret, err := OpenRequest(serverDK, clientID.Public(), sealed)
	if err != nil {
		t.Fatal(err)
	}

	// Now open symmetrically
	ts, opened, err := OpenRequestSymmetric(sharedSecret, clientID.Public(), sealed)
	if err != nil {
		t.Fatalf("OpenRequestSymmetric failed: %v", err)
	}

	if !bytes.Equal(opened, payload) {
		t.Errorf("Payload mismatch: %s vs %s", opened, payload)
	}
	if ts == 0 {
		t.Error("Timestamp is zero")
	}

	// Error cases
	if _, _, err := OpenRequestSymmetric(sharedSecret, clientID.Public(), sealed[:10]); err == nil {
		t.Error("Expected error for short data")
	}

	badSecret := make([]byte, 32)
	if _, _, err := OpenRequestSymmetric(badSecret, clientID.Public(), sealed); err == nil {
		t.Error("Expected error for bad shared secret")
	}

	badSig := append([]byte{}, sealed...)
	badSig[len(badSig)-1] ^= 0xFF
	if _, _, err := OpenRequestSymmetric(sharedSecret, clientID.Public(), badSig); err == nil {
		t.Error("Expected error for bad signature")
	}
}

func TestSealedResponse(t *testing.T) {
	clientDK, _ := GenerateEncryptionKey()
	clientPK := clientDK.EncapsulationKey()
	serverID, _ := GenerateIdentityKey()
	payload := []byte("test response payload")

	sealed, err := SealResponse(clientPK, serverID, payload)
	if err != nil {
		t.Fatal(err)
	}

	ts, opened, err := OpenResponse(clientDK, serverID.Public(), sealed)
	if err != nil {
		t.Fatalf("OpenResponse failed: %v", err)
	}

	if !bytes.Equal(opened, payload) {
		t.Errorf("Payload mismatch: %s vs %s", opened, payload)
	}
	if ts == 0 {
		t.Error("Timestamp is zero")
	}

	// Error cases
	if _, _, err := OpenResponse(clientDK, serverID.Public(), sealed[:10]); err == nil {
		t.Error("Expected error for short data")
	}

	wrongDK, _ := GenerateEncryptionKey()
	if _, _, err := OpenResponse(wrongDK, serverID.Public(), sealed); err == nil {
		t.Error("Expected error for wrong decapsulation key")
	}

	badSig := append([]byte{}, sealed...)
	badSig[len(badSig)-1] ^= 0xFF
	if _, _, err := OpenResponse(clientDK, serverID.Public(), badSig); err == nil {
		t.Error("Expected error for bad signature")
	}
}

func TestSealUnseal(t *testing.T) {
	recipientDK, _ := GenerateEncryptionKey()
	recipientPK := recipientDK.EncapsulationKey()
	payload := []byte("secret metadata")
	nonce := int64(12345)

	sealed, err := Seal(payload, recipientPK, nonce)
	if err != nil {
		t.Fatal(err)
	}

	unsealed, err := Unseal(sealed, recipientDK)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(unsealed, payload) {
		t.Errorf("Payload mismatch: %s vs %s", unsealed, payload)
	}

	// Error cases
	if _, err := Unseal(sealed[:10], recipientDK); err == nil {
		t.Error("Expected error for short data")
	}

	wrongDK, _ := GenerateEncryptionKey()
	if _, err := Unseal(sealed, wrongDK); err == nil {
		t.Error("Expected error for wrong decapsulation key")
	}

	badCT := append([]byte{}, sealed...)
	badCT[len(badCT)-1] ^= 0xFF
	if _, err := Unseal(badCT, recipientDK); err == nil {
		t.Error("Expected error for bad ciphertext")
	}

	// 4. Bad DEM (short inner)
	sharedSecret, kemCT := Encapsulate(recipientPK)
	badInner, _ := EncryptDEM(sharedSecret, []byte("short"))
	sealedBad := append(kemCT, badInner...)
	if _, err := Unseal(sealedBad, recipientDK); err == nil {
		t.Error("Expected error for short inner")
	}
}

func TestOpenRequest_MoreErrors(t *testing.T) {
	serverDK, _ := GenerateEncryptionKey()
	clientID, _ := GenerateIdentityKey()

	// 1. Too short
	if _, _, _, err := OpenRequest(serverDK, clientID.Public(), make([]byte, 10)); err == nil {
		t.Error("Expected error for short data")
	}

	// 2. Bad KEM
	if _, _, _, err := OpenRequest(serverDK, clientID.Public(), make([]byte, 1000)); err == nil {
		t.Error("Expected error for bad KEM")
	}

	// 3. Bad DEM (short inner)
	serverPK := serverDK.EncapsulationKey()
	sharedSecret, kemCT := Encapsulate(serverPK)
	badInner, _ := EncryptDEM(sharedSecret, []byte("short"))
	sealed := append(kemCT, badInner...)
	if _, _, _, err := OpenRequest(serverDK, clientID.Public(), sealed); err == nil {
		t.Error("Expected error for short inner")
	}
}

func TestOpenResponse_MoreErrors(t *testing.T) {
	clientDK, _ := GenerateEncryptionKey()
	serverID, _ := GenerateIdentityKey()

	// 1. Bad KEM
	if _, _, err := OpenResponse(clientDK, serverID.Public(), make([]byte, 1000)); err == nil {
		t.Error("Expected error for bad KEM")
	}

	// 2. Bad DEM (short inner)
	clientPK := clientDK.EncapsulationKey()
	sharedSecret, kemCT := Encapsulate(clientPK)
	badInner, _ := EncryptDEM(sharedSecret, []byte("short"))
	sealed := append(kemCT, badInner...)
	if _, _, err := OpenResponse(clientDK, serverID.Public(), sealed); err == nil {
		t.Error("Expected error for short inner")
	}
}
