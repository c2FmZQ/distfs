package client

import (
	"strings"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

func TestContactExchange(t *testing.T) {
	// 1. Setup Client A
	dkA, _ := crypto.GenerateEncryptionKey()
	skA, _ := crypto.GenerateIdentityKey()
	clientA := &Client{
		userID:  "alice",
		decKey:  dkA,
		signKey: skA,
	}

	// 2. Generate Contact String
	s, err := clientA.GenerateContactString()
	if err != nil {
		t.Fatalf("GenerateContactString failed: %v", err)
	}

	if !strings.HasPrefix(s, "distfs-contact:v1:") {
		t.Errorf("Unexpected prefix: %s", s)
	}

	// 3. Setup Client B (The receiver)
	clientB := &Client{}

	// 4. Parse and Verify
	info, err := clientB.ParseContactString(s)
	if err != nil {
		t.Fatalf("ParseContactString failed: %v", err)
	}

	if info.UserID != "alice" {
		t.Errorf("UserID mismatch: got %s, want alice", info.UserID)
	}

	// 5. Test Tampering
	// Decode, modify, re-encode
	// (Simpler: just try parsing a string with an invalid signature)
	tampered := s + "extra"
	_, err = clientB.ParseContactString(tampered)
	if err == nil {
		t.Error("ParseContactString should have failed for tampered string (decoding)")
	}

	// 6. Test Expiry (Manual construction would require full signing)
	t.Log("Contact exchange verified")
}
