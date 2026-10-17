// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

func TestInodeClone(t *testing.T) {
	mask := uint32(0777)
	original := &Inode{
		ID:    "test-inode-123",
		Links: map[string]bool{"parent:name": true},
		Type:  DirType,
		Children: map[string]ChildEntry{
			"child1": {
				ID:            "child-inode-id",
				EncryptedName: []byte("encrypted-name-bytes"),
				Nonce:         []byte("nonce-bytes"),
			},
		},
		ClientBlob: []byte("client-blob-data"),
		ChunkManifest: []ChunkEntry{
			{
				ID:    "chunk-1",
				Nodes: []string{"node-a", "node-b"},
				URLs:  []string{"url-1", "url-2"},
			},
		},
		Lockbox: crypto.Lockbox{
			"user1": crypto.LockboxEntry{
				KEMCiphertext: []byte("kem-ct-bytes"),
				DEMCiphertext: []byte("dem-ct-bytes"),
				Epoch:         2,
			},
		},
		AccessACL: &POSIXAccess{
			Users:  map[string]uint32{"user1": 7},
			Groups: map[string]uint32{"group1": 5},
			Mask:   &mask,
		},
		symlinkTarget: "symlink-target-path",
		inlineData:    []byte("inlined-data-bytes"),
		mtime:         999999,
		uid:           1000,
		gid:           1001,
		fileKey:       []byte("file-key-bytes"),
	}

	cloned := original.Clone()

	// Verify deep copy of basic values
	if cloned.ID != original.ID || cloned.Type != original.Type || cloned.mtime != original.mtime {
		t.Errorf("Basic fields do not match")
	}

	// Verify maps are copied, not shared
	cloned.Links["parent:name"] = false
	if original.Links["parent:name"] != true {
		t.Errorf("Links map was shared!")
	}

	cloned.Children["child1"].EncryptedName[0] = 0xAA
	if original.Children["child1"].EncryptedName[0] == 0xAA {
		t.Errorf("Children EncryptedName slice was shared!")
	}

	delete(cloned.Children, "child1")
	if _, ok := original.Children["child1"]; !ok {
		t.Errorf("Children map was shared!")
	}

	// Verify slices are copied
	cloned.ClientBlob[0] = 0xBB
	if original.ClientBlob[0] == 0xBB {
		t.Errorf("ClientBlob slice was shared!")
	}

	// Verify ChunkManifest deep copy
	cloned.ChunkManifest[0].Nodes[0] = "mutated-node"
	if original.ChunkManifest[0].Nodes[0] == "mutated-node" {
		t.Errorf("ChunkManifest Nodes slice was shared!")
	}

	cloned.ChunkManifest[0].URLs[0] = "mutated-url"
	if original.ChunkManifest[0].URLs[0] == "mutated-url" {
		t.Errorf("ChunkManifest URLs slice was shared!")
	}

	cloned.ChunkManifest[0].ID = "mutated-chunk"
	if original.ChunkManifest[0].ID == "mutated-chunk" {
		t.Errorf("ChunkManifest entry was shared!")
	}

	// Verify Lockbox deep copy
	cloned.Lockbox["user1"].KEMCiphertext[0] = 0xCC
	if original.Lockbox["user1"].KEMCiphertext[0] == 0xCC {
		t.Errorf("Lockbox KEMCiphertext was shared!")
	}

	delete(cloned.Lockbox, "user1")
	if _, ok := original.Lockbox["user1"]; !ok {
		t.Errorf("Lockbox map was shared!")
	}

	// Verify ACL deep copy
	cloned.AccessACL.Users["user1"] = 0
	if original.AccessACL.Users["user1"] != 7 {
		t.Errorf("AccessACL Users map was shared!")
	}

	*cloned.AccessACL.Mask = 0
	if *original.AccessACL.Mask != 0777 {
		t.Errorf("AccessACL Mask pointer was shared!")
	}

	// Verify transient fields
	if cloned.GetSymlinkTarget() != original.GetSymlinkTarget() {
		t.Errorf("symlinkTarget was not copied")
	}

	cloned.inlineData[0] = 0xDD
	if original.inlineData[0] == 0xDD {
		t.Errorf("inlineData was shared")
	}

	cloned.fileKey[0] = 0xEE
	if original.fileKey[0] == 0xEE {
		t.Errorf("fileKey was shared")
	}
}

func TestNilInodeClone(t *testing.T) {
	var i *Inode
	if i.Clone() != nil {
		t.Errorf("Cloning nil Inode should return nil")
	}
}
