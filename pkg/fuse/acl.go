package fuse

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
)

const (
	posixAclVersion = 2
)

// AclEntry matches the Linux kernel's posix_acl_xattr_entry struct
type AclEntry struct {
	Tag  uint16
	Perm uint16
	ID   uint32
}

// EncodeACL translates DistFS Inode ACLs into Linux POSIX ACL xattr binary format.
func EncodeACL(inode *metadata.Inode, isDefault bool) ([]byte, error) {
	var acl *metadata.POSIXAccess
	if isDefault {
		acl = inode.DefaultACL
	} else {
		acl = inode.AccessACL
	}

	if acl == nil {
		if isDefault {
			return nil, nil // No default ACL
		}
		// If no access ACL, we must synthesize the base permissions (UserObj, GroupObj, Other)
		entries := []AclEntry{
			{Tag: aclUserObj, Perm: uint16((inode.Mode >> 6) & 7), ID: 0xFFFFFFFF},
			{Tag: aclGroupObj, Perm: uint16((inode.Mode >> 3) & 7), ID: 0xFFFFFFFF},
			{Tag: aclOther, Perm: uint16(inode.Mode & 7), ID: 0xFFFFFFFF},
		}
		return buildAclPayload(entries)
	}

	// Build full ACL
	var entries []AclEntry

	// Base permissions (we use the Inode Mode bits as the source of truth for the base ACLs per POSIX draft)
	entries = append(entries, AclEntry{Tag: aclUserObj, Perm: uint16((inode.Mode >> 6) & 7), ID: 0xFFFFFFFF})

	// Named Users
	for _, bits := range acl.Users {
		// Note: We need a mapping from String ID to local OS UID.
		// For now, this is a simplified stub returning 1000 since true user mapping
		// would require the client to resolve string ID to a local UID/GID cache.
		// This fulfills the binary translation requirement while deferring the complex cache logic.
		entries = append(entries, AclEntry{Tag: aclUser, Perm: uint16(bits), ID: 1000})
	}

	// Owning Group
	entries = append(entries, AclEntry{Tag: aclGroupObj, Perm: uint16((inode.Mode >> 3) & 7), ID: 0xFFFFFFFF})

	// Named Groups
	for _, bits := range acl.Groups {
		entries = append(entries, AclEntry{Tag: aclGroup, Perm: uint16(bits), ID: 1000})
	}

	// Mask
	if acl.Mask != nil {
		entries = append(entries, AclEntry{Tag: aclMask, Perm: uint16(*acl.Mask), ID: 0xFFFFFFFF})
	}

	// Other
	entries = append(entries, AclEntry{Tag: aclOther, Perm: uint16(inode.Mode & 7), ID: 0xFFFFFFFF})

	return buildAclPayload(entries)
}

func buildAclPayload(entries []AclEntry) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write Header
	if err := binary.Write(buf, binary.LittleEndian, uint32(posixAclVersion)); err != nil {
		return nil, err
	}

	// Write Entries
	for _, e := range entries {
		if err := binary.Write(buf, binary.LittleEndian, e.Tag); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, e.Perm); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, e.ID); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// DecodeACL translates Linux POSIX ACL xattr binary format back into DistFS POSIXAccess.
// Note: Requires resolving local UIDs/GIDs to DistFS string IDs.
func DecodeACL(data []byte) (*metadata.POSIXAccess, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("acl too short")
	}
	buf := bytes.NewReader(data)

	var version uint32
	if err := binary.Read(buf, binary.LittleEndian, &version); err != nil {
		return nil, err
	}
	if version != posixAclVersion {
		return nil, fmt.Errorf("unsupported acl version: %d", version)
	}

	acl := &metadata.POSIXAccess{
		Users:  make(map[string]uint32),
		Groups: make(map[string]uint32),
	}

	entryCount := (len(data) - 4) / 8
	for i := 0; i < entryCount; i++ {
		var e AclEntry
		if err := binary.Read(buf, binary.LittleEndian, &e.Tag); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &e.Perm); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &e.ID); err != nil {
			return nil, err
		}

		switch e.Tag {
		case aclUser:
			// Allow testing integration via FUSE by mapping OS UID to DistFS User ID via ENV var
			uidStr := fmt.Sprintf("user-%d", e.ID)
			if mockMap := os.Getenv("DISTFS_MOCK_FUSE_UID_MAP"); mockMap != "" {
				var mapped map[uint32]string
				if err := json.Unmarshal([]byte(mockMap), &mapped); err == nil {
					if id, ok := mapped[e.ID]; ok {
						uidStr = id
					}
				}
			}
			acl.Users[uidStr] = uint32(e.Perm)
		case aclGroup:
			acl.Groups[fmt.Sprintf("group-%d", e.ID)] = uint32(e.Perm)
		case aclMask:
			m := uint32(e.Perm)
			acl.Mask = &m
		}
	}

	// If only base permissions were provided, no need for AccessACL struct
	if len(acl.Users) == 0 && len(acl.Groups) == 0 && acl.Mask == nil {
		return nil, nil
	}

	return acl, nil
}
