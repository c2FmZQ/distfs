// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"testing"
)

func TestTypes_Misc(t *testing.T) {
	// 1. iif (although unused, it's there)
	if iif(true, "a", "b") != "a" {
		t.Error("iif true failed")
	}
	if iif(false, "a", "b") != "b" {
		t.Error("iif false failed")
	}

	// 2. SignedAuthToken Marshal/Unmarshal
	sat := &SignedAuthToken{
		SignerID: "n1",
		Payload:  []byte("payload"),
		Signature: []byte("sig"),
	}
	b := sat.Marshal()
	var sat2 SignedAuthToken
	if err := sat2.Unmarshal(b); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if sat2.SignerID != "n1" {
		t.Error("SignerID mismatch")
	}

	// 3. SanitizeMode
	m := SanitizeMode(0777, FileType)
	if (m & 0002) != 0 {
		t.Error("SanitizeMode failed to remove world-write bit")
	}
	m2 := SanitizeMode(0777, SymlinkType)
	if (m2 & 0002) == 0 {
		t.Error("SanitizeMode should preserve world-write bit for symlinks")
	}
}
