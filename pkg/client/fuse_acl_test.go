//go:build !wasm

package client

import (
	"os"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestFUSE_ACLTranslation(t *testing.T) {
	// Simple unit test for Encode/Decode
	// Provide base permissions (e.g. 0644 -> User: 6, Group: 4, Other: 4)
	inode := &metadata.Inode{Mode: 0644}

	// Synthesize a basic ACL
	encoded, err := EncodeACL(inode, false)
	if err != nil {
		t.Fatalf("EncodeACL failed: %v", err)
	}

	decoded, err := DecodeACL(encoded)
	if err != nil {
		t.Fatalf("DecodeACL failed: %v", err)
	}

	// Should be nil because we only had base permissions (no users/groups)
	if decoded != nil {
		t.Fatalf("Expected nil decoded ACL for base permissions, got %v", decoded)
	}

	// Now try an advanced one
	inode.AccessACL = &metadata.POSIXAccess{
		Users:  map[string]uint32{"user-1001": 4},
		Groups: map[string]uint32{"group-1001": 5},
	}

	// We set the mock map so EncodeACL uses 'user-1001' instead of local UID
	os.Setenv("DISTFS_MOCK_FUSE_UID_MAP", `{"1001":"user-1001", "1002":"group-1001"}`)
	defer os.Unsetenv("DISTFS_MOCK_FUSE_UID_MAP")

	// Decode should yield the same struct
	// Note: EncodeACL stub in acl.go currently maps user-ID -> e.ID.
	// Our mock map expects an OS uid mapping, but we don't need it if we are just testing
	// the Decode mapping since FUSE sends the e.ID (e.g., 1001).

	// Let's manually craft a FUSE payload for setfacl -m u:1001:r--
	// Version 2 (4 bytes)
	// Entry 1: UserObj (Tag 1, Perm 6, ID -1)
	// Entry 2: User    (Tag 2, Perm 4, ID 1001)
	// Entry 3: GroupObj(Tag 4, Perm 4, ID -1)
	// Entry 4: Mask    (Tag 16, Perm 4, ID -1)
	// Entry 5: Other   (Tag 32, Perm 4, ID -1)

	entries := []AclEntry{
		{Tag: aclUserObj, Perm: 6, ID: 0xFFFFFFFF},
		{Tag: aclUser, Perm: 4, ID: 1001},
		{Tag: aclGroupObj, Perm: 4, ID: 0xFFFFFFFF},
		{Tag: aclMask, Perm: 4, ID: 0xFFFFFFFF},
		{Tag: aclOther, Perm: 4, ID: 0xFFFFFFFF},
	}
	payload, _ := buildAclPayload(entries)

	parsedAcl, err := DecodeACL(payload)
	if err != nil {
		t.Fatalf("DecodeACL failed: %v", err)
	}

	if parsedAcl == nil {
		t.Fatalf("parsedAcl is nil")
	}

	if perm, ok := parsedAcl.Users["user-1001"]; !ok || perm != 4 {
		t.Errorf("Expected user-1001 to have perm 4, got %v (ok=%v)", perm, ok)
	}

	if parsedAcl.Mask == nil || *parsedAcl.Mask != 4 {
		t.Errorf("Expected mask to be 4, got %v", parsedAcl.Mask)
	}
}
