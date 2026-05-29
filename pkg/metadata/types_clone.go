// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"github.com/c2FmZQ/distfs/pkg/crypto"
)

// Clone returns a deep copy of the Inode.
func (i *Inode) Clone() *Inode {
	if i == nil {
		return nil
	}
	clone := *i // Shallow copy most scalar/non-slice/non-map values

	// Deep copy maps
	if i.Links != nil {
		clone.Links = make(map[string]bool, len(i.Links))
		for k, v := range i.Links {
			clone.Links[k] = v
		}
	}
	if i.Children != nil {
		clone.Children = make(map[string]ChildEntry, len(i.Children))
		for k, v := range i.Children {
			entryCopy := ChildEntry{
				ID: v.ID,
			}
			if v.EncryptedName != nil {
				entryCopy.EncryptedName = make([]byte, len(v.EncryptedName))
				copy(entryCopy.EncryptedName, v.EncryptedName)
			}
			if v.Nonce != nil {
				entryCopy.Nonce = make([]byte, len(v.Nonce))
				copy(entryCopy.Nonce, v.Nonce)
			}
			clone.Children[k] = entryCopy
		}
	}
	if i.Leases != nil {
		clone.Leases = make(map[string]LeaseInfo, len(i.Leases))
		for k, v := range i.Leases {
			clone.Leases[k] = v
		}
	}
	if i.Lockbox != nil {
		clone.Lockbox = make(crypto.Lockbox, len(i.Lockbox))
		for k, v := range i.Lockbox {
			entryCopy := crypto.LockboxEntry{
				Epoch: v.Epoch,
			}
			if v.KEMCiphertext != nil {
				entryCopy.KEMCiphertext = make([]byte, len(v.KEMCiphertext))
				copy(entryCopy.KEMCiphertext, v.KEMCiphertext)
			}
			if v.DEMCiphertext != nil {
				entryCopy.DEMCiphertext = make([]byte, len(v.DEMCiphertext))
				copy(entryCopy.DEMCiphertext, v.DEMCiphertext)
			}
			clone.Lockbox[k] = entryCopy
		}
	}

	// Deep copy slices
	if i.ClientBlob != nil {
		clone.ClientBlob = make([]byte, len(i.ClientBlob))
		copy(clone.ClientBlob, i.ClientBlob)
	}
	if i.ChunkManifest != nil {
		clone.ChunkManifest = make([]ChunkEntry, len(i.ChunkManifest))
		for idx, entry := range i.ChunkManifest {
			entryCopy := ChunkEntry{
				ID: entry.ID,
			}
			if entry.Nodes != nil {
				entryCopy.Nodes = make([]string, len(entry.Nodes))
				copy(entryCopy.Nodes, entry.Nodes)
			}
			if entry.URLs != nil {
				entryCopy.URLs = make([]string, len(entry.URLs))
				copy(entryCopy.URLs, entry.URLs)
			}
			clone.ChunkManifest[idx] = entryCopy
		}
	}
	if i.ChunkPages != nil {
		clone.ChunkPages = make([]string, len(i.ChunkPages))
		copy(clone.ChunkPages, i.ChunkPages)
	}
	if i.Nonce != nil {
		clone.Nonce = make([]byte, len(i.Nonce))
		copy(clone.Nonce, i.Nonce)
	}
	if i.UserSig != nil {
		clone.UserSig = make([]byte, len(i.UserSig))
		copy(clone.UserSig, i.UserSig)
	}
	if i.GroupSig != nil {
		clone.GroupSig = make([]byte, len(i.GroupSig))
		copy(clone.GroupSig, i.GroupSig)
	}
	if i.OwnerDelegationSig != nil {
		clone.OwnerDelegationSig = make([]byte, len(i.OwnerDelegationSig))
		copy(clone.OwnerDelegationSig, i.OwnerDelegationSig)
	}
	if i.ClusterSig != nil {
		clone.ClusterSig = make([]byte, len(i.ClusterSig))
		copy(clone.ClusterSig, i.ClusterSig)
	}

	// ACLs
	if i.AccessACL != nil {
		aclCopy := POSIXAccess{}
		if i.AccessACL.Users != nil {
			aclCopy.Users = make(map[string]uint32, len(i.AccessACL.Users))
			for k, v := range i.AccessACL.Users {
				aclCopy.Users[k] = v
			}
		}
		if i.AccessACL.Groups != nil {
			aclCopy.Groups = make(map[string]uint32, len(i.AccessACL.Groups))
			for k, v := range i.AccessACL.Groups {
				aclCopy.Groups[k] = v
			}
		}
		if i.AccessACL.Mask != nil {
			maskCopy := *i.AccessACL.Mask
			aclCopy.Mask = &maskCopy
		}
		clone.AccessACL = &aclCopy
	}
	if i.DefaultACL != nil {
		aclCopy := POSIXAccess{}
		if i.DefaultACL.Users != nil {
			aclCopy.Users = make(map[string]uint32, len(i.DefaultACL.Users))
			for k, v := range i.DefaultACL.Users {
				aclCopy.Users[k] = v
			}
		}
		if i.DefaultACL.Groups != nil {
			aclCopy.Groups = make(map[string]uint32, len(i.DefaultACL.Groups))
			for k, v := range i.DefaultACL.Groups {
				aclCopy.Groups[k] = v
			}
		}
		if i.DefaultACL.Mask != nil {
			maskCopy := *i.DefaultACL.Mask
			aclCopy.Mask = &maskCopy
		}
		clone.DefaultACL = &aclCopy
	}

	// Transient state (slices/pointers)
	if i.inlineData != nil {
		clone.inlineData = make([]byte, len(i.inlineData))
		copy(clone.inlineData, i.inlineData)
	}
	if i.fileKey != nil {
		clone.fileKey = make([]byte, len(i.fileKey))
		copy(clone.fileKey, i.fileKey)
	}

	return &clone
}

// Clone returns a deep copy of the User.
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	clone := *u
	if u.SignKey != nil {
		clone.SignKey = make([]byte, len(u.SignKey))
		copy(clone.SignKey, u.SignKey)
	}
	if u.EncKey != nil {
		clone.EncKey = make([]byte, len(u.EncKey))
		copy(clone.EncKey, u.EncKey)
	}
	if u.Signature != nil {
		clone.Signature = make([]byte, len(u.Signature))
		copy(clone.Signature, u.Signature)
	}
	return &clone
}

// Clone returns a deep copy of the Group.
func (g *Group) Clone() *Group {
	if g == nil {
		return nil
	}
	clone := *g
	if g.Nonce != nil {
		clone.Nonce = make([]byte, len(g.Nonce))
		copy(clone.Nonce, g.Nonce)
	}
	if g.EncKey != nil {
		clone.EncKey = make([]byte, len(g.EncKey))
		copy(clone.EncKey, g.EncKey)
	}
	if g.SignKey != nil {
		clone.SignKey = make([]byte, len(g.SignKey))
		copy(clone.SignKey, g.SignKey)
	}
	if g.HistoricalSignKeys != nil {
		clone.HistoricalSignKeys = make(map[uint32][]byte, len(g.HistoricalSignKeys))
		for k, v := range g.HistoricalSignKeys {
			if v != nil {
				vc := make([]byte, len(v))
				copy(vc, v)
				clone.HistoricalSignKeys[k] = vc
			} else {
				clone.HistoricalSignKeys[k] = nil
			}
		}
	}
	if g.EncryptedSignKey != nil {
		clone.EncryptedSignKey = make([]byte, len(g.EncryptedSignKey))
		copy(clone.EncryptedSignKey, g.EncryptedSignKey)
	}
	if g.Lockbox != nil {
		clone.Lockbox = make(crypto.Lockbox, len(g.Lockbox))
		for k, v := range g.Lockbox {
			vc := crypto.LockboxEntry{Epoch: v.Epoch}
			if v.KEMCiphertext != nil {
				vc.KEMCiphertext = make([]byte, len(v.KEMCiphertext))
				copy(vc.KEMCiphertext, v.KEMCiphertext)
			}
			if v.DEMCiphertext != nil {
				vc.DEMCiphertext = make([]byte, len(v.DEMCiphertext))
				copy(vc.DEMCiphertext, v.DEMCiphertext)
			}
			clone.Lockbox[k] = vc
		}
	}
	if g.AnonymousLockbox != nil {
		clone.AnonymousLockbox = make([][]byte, len(g.AnonymousLockbox))
		for i, v := range g.AnonymousLockbox {
			if v != nil {
				vc := make([]byte, len(v))
				copy(vc, v)
				clone.AnonymousLockbox[i] = vc
			}
		}
	}
	if g.RegistryLockbox != nil {
		clone.RegistryLockbox = make(crypto.Lockbox, len(g.RegistryLockbox))
		for k, v := range g.RegistryLockbox {
			vc := crypto.LockboxEntry{Epoch: v.Epoch}
			if v.KEMCiphertext != nil {
				vc.KEMCiphertext = make([]byte, len(v.KEMCiphertext))
				copy(vc.KEMCiphertext, v.KEMCiphertext)
			}
			if v.DEMCiphertext != nil {
				vc.DEMCiphertext = make([]byte, len(v.DEMCiphertext))
				copy(vc.DEMCiphertext, v.DEMCiphertext)
			}
			clone.RegistryLockbox[k] = vc
		}
	}
	if g.EncryptedRegistry != nil {
		clone.EncryptedRegistry = make([]byte, len(g.EncryptedRegistry))
		copy(clone.EncryptedRegistry, g.EncryptedRegistry)
	}
	if g.AnonymousRegistry != nil {
		clone.AnonymousRegistry = make([]byte, len(g.AnonymousRegistry))
		copy(clone.AnonymousRegistry, g.AnonymousRegistry)
	}
	if g.EncryptedEpochSeed != nil {
		clone.EncryptedEpochSeed = make([]byte, len(g.EncryptedEpochSeed))
		copy(clone.EncryptedEpochSeed, g.EncryptedEpochSeed)
	}
	if g.ClientBlob != nil {
		clone.ClientBlob = make([]byte, len(g.ClientBlob))
		copy(clone.ClientBlob, g.ClientBlob)
	}
	return &clone
}
