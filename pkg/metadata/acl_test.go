package metadata

import (
	"testing"
)

func TestEvaluatePOSIXAccess(t *testing.T) {
	// Simple test to ensure evaluatePOSIXAccess is correctly wired
	inode := &Inode{
		OwnerID: "u1",
		GroupID: "g1",
		Mode:    0640,
	}

	// Owner Write (Mode 0600 -> 0002)
	if !evaluatePOSIXAccess(inode, "u1", false, nil, 0002) {
		t.Error("owner should have write access")
	}

	// Owner Read (Mode 0600 -> 0004)
	if !evaluatePOSIXAccess(inode, "u1", false, nil, 0004) {
		t.Error("owner should have read access")
	}

	// Group Read (Mode 0040 -> 0004)
	if !evaluatePOSIXAccess(inode, "u2", true, nil, 0004) {
		t.Error("group should have read access")
	}

	// Group Write (Mode 0040 -> no write)
	if evaluatePOSIXAccess(inode, "u2", true, nil, 0002) {
		t.Error("group should NOT have write access")
	}

	// Other Read (Mode 0000)
	if evaluatePOSIXAccess(inode, "u3", false, nil, 0004) {
		t.Error("other should NOT have read access")
	}
}
