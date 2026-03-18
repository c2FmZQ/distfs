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

package client

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// EnsureRoot initializes the root directory inode. It returns the ID of the initialized root (useful for secondary roots) and an error if it already exists.
func (c *Client) EnsureRoot(ctx context.Context) (string, error) {
	inode, err := c.getInode(ctx, c.rootID)
	if err == nil {
		c.rootOwner = inode.OwnerID
		c.rootVersion = inode.Version
		return c.rootID, metadata.ErrExists
	}

	if c.decKey == nil {
		return "", fmt.Errorf("cannot create secure root without identity")
	}

	rootKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rootKey); err != nil {
		return "", err
	}

	lb, err := c.createLockbox(ctx, rootKey, 0755, c.userID, "", nil)
	if err != nil {
		return "", err
	}
	var nonce []byte
	finalRootID := c.rootID
	if finalRootID != metadata.RootID {
		nonce = make([]byte, 16)
		rand.Read(nonce)
		finalRootID = metadata.GenerateInodeID(c.userID, nonce)
	}

	newInode := metadata.Inode{
		ID:       finalRootID,
		Nonce:    nonce,
		Type:     metadata.DirType,
		Mode:     0755,
		Children: make(map[string]metadata.ChildEntry),
		Lockbox:  lb,
		OwnerID:  c.userID,
		NLink:    1,
	}
	newInode.SetFileKey(rootKey)
	newInode.Version = 1
	_, err = c.createInode(ctx, newInode)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusConflict {
			// Already exists, but we MUST fetch it to capture the anchor (owner/version)
			_, err = c.getInode(ctx, finalRootID)
			return finalRootID, err
		}
		return "", err
	}
	return finalRootID, nil
}

// ResolvePath resolves a string path to an Inode and its FileKey.
// GetPathID computes the opaque identifier used for filename leases (ParentID:nameHMAC).
func (c *Client) GetPathID(ctx context.Context, path string) (string, error) {
	if path == "/" {
		return "path:root:" + c.rootID, nil
	}

	dir, name := filepath.Split(strings.TrimRight(path, "/"))
	if dir == "" {
		dir = "/"
	}

	parentInode, parentKey, err := c.ResolvePath(ctx, dir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve parent directory %s: %w", dir, err)
	}

	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	nameHMAC := hex.EncodeToString(mac.Sum(nil))

	return "path:" + parentInode.ID + ":" + nameHMAC, nil
}

// ResolvePath resolves a human-readable path to an Inode and its decrypted FileKey.
func (c *Client) ResolvePath(ctx context.Context, path string) (*metadata.Inode, []byte, error) {
	return c.ResolvePathExtended(ctx, path, true)
}

// ResolvePathExtended resolves a path with optional symlink following for the final component.
func (c *Client) ResolvePathExtended(ctx context.Context, path string, followFinal bool) (*metadata.Inode, []byte, error) {
	path = "/" + strings.Trim(path, "/")

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			c.clearPathCache()
		}

		inode, key, err := c.resolvePathInternal(ctx, path, followFinal)
		if err == nil {
			return inode, key, nil
		}

		if !isNotFound(err) {
			return nil, nil, err
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (c *Client) resolvePathInternal(ctx context.Context, path string, followFinal bool) (*metadata.Inode, []byte, error) {
	if path == "/" {
		// Fast path for root
		inode, err := c.getInode(ctx, c.rootID)
		if err != nil {
			if isNotFound(err) {
				return nil, nil, fmt.Errorf("root inode %s not found; has it been initialized with 'admin-create-root'?", c.rootID)
			}
			return nil, nil, fmt.Errorf("failed to get root inode %s: %w", c.rootID, err)
		}
		key, err := c.UnlockInode(ctx, inode)
		if err != nil {
			return nil, nil, fmt.Errorf("access denied to root: %w", err)
		}
		return inode, key, nil
	}

	// 1. Path Cache Lookup
	parts := strings.Split(path, "/")
	for i := len(parts); i > 0; i-- {
		prefix := "/" + strings.Join(parts[1:i], "/")
		if entry, ok := c.getPathCache(prefix); ok {
			inode := entry.inode
			if inode == nil {
				// Fallback to fetch if not cached
				var err error
				inode, err = c.getInode(ctx, entry.inodeID)
				if err != nil {
					if isNotFound(err) {
						c.invalidatePathCache(prefix)
					}
					continue
				}
			}

			// Validate hint integrity
			valid := false
			if prefix == "/" {
				valid = inode.ID == c.rootID
			} else if inode.Links != nil {
				valid = inode.Links[entry.linkTag]
			}

			if valid {
				remainingPath := strings.Join(parts[i:], "/")
				if remainingPath == "" {
					// We reached the final component. If it's a symlink and followFinal is true, follow it.
					if inode.Type == metadata.SymlinkType && followFinal {
						return c.resolveSymlink(ctx, inode, entry.key, prefix, 0, followFinal)
					}
					return inode, entry.key, nil
				}
				// If cached prefix is a symlink, we MUST follow it before proceeding.
				if inode.Type == metadata.SymlinkType {
					newInode, newKey, err := c.resolveSymlink(ctx, inode, entry.key, prefix, 0, true)
					if err != nil {
						return nil, nil, err
					}
					return c.resolveSequential(ctx, newInode, newKey, remainingPath, prefix, 0, followFinal)
				}
				return c.resolveSequential(ctx, inode, entry.key, remainingPath, prefix, 0, followFinal)
			}
			c.invalidatePathCache(prefix)
		}
	}

	// 2. Sequential Resolution from root
	rootInode, err := c.getInode(ctx, c.rootID)
	if err != nil {
		if isNotFound(err) {
			return nil, nil, fmt.Errorf("root inode %s not found; has it been initialized with 'admin-create-root'?", c.rootID)
		}
		return nil, nil, fmt.Errorf("failed to get root inode %s: %w", c.rootID, err)
	}

	rootKey, err := c.UnlockInode(ctx, rootInode)
	if err != nil {
		return nil, nil, fmt.Errorf("access denied to root: %w", err)
	}

	// Populate cache for root
	c.putPathCache("/", pathCacheEntry{inodeID: c.rootID, key: rootKey, inode: rootInode})

	return c.resolveSequential(ctx, rootInode, rootKey, strings.TrimPrefix(path, "/"), "", 0, followFinal)
}

func (c *Client) resolveSequential(ctx context.Context, currentInode *metadata.Inode, currentKey []byte, remainingPath string, prefix string, symlinkCount int, followFinal bool) (*metadata.Inode, []byte, error) {
	const maxSymlinks = 40
	parts := strings.Split(remainingPath, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		isFinal := i == len(parts)-1

		if currentInode.Type != metadata.DirType {
			return nil, nil, fmt.Errorf("path component %s is not a directory", prefix)
		}

		mac := hmac.New(sha256.New, currentKey)
		mac.Write([]byte(part))
		encName := hex.EncodeToString(mac.Sum(nil))

		entry, ok := currentInode.Children[encName]
		if !ok {
			return nil, nil, fmt.Errorf("path component %s not found in %s", part, prefix)
		}
		childID := entry.ID

		childInode, err := c.getInode(ctx, childID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch inode %s for path component %s: %w", childID, part, err)
		}

		childKey, err := c.UnlockInode(ctx, childInode)
		if err != nil {
			return nil, nil, fmt.Errorf("access denied to path component %s: %w", part, err)
		}

		// Update prefix and cache
		prefix = filepath.Join(prefix, part)
		cachePath := prefix
		if !strings.HasPrefix(cachePath, "/") {
			cachePath = "/" + cachePath
		}
		c.putPathCache(cachePath, pathCacheEntry{
			inodeID: childID,
			key:     childKey,
			linkTag: currentInode.ID + ":" + encName,
			inode:   childInode,
		})

		if childInode.Type == metadata.SymlinkType {
			if !isFinal || followFinal {
				if symlinkCount >= maxSymlinks {
					return nil, nil, fmt.Errorf("too many symbolic links")
				}
				currentInode, currentKey, err = c.resolveSymlink(ctx, childInode, childKey, prefix, symlinkCount+1, followFinal)
				if err != nil {
					return nil, nil, err
				}
				continue
			}
		}

		currentInode = childInode
		currentKey = childKey
	}

	return currentInode, currentKey, nil
}

func (c *Client) resolveSymlink(ctx context.Context, inode *metadata.Inode, key []byte, prefix string, symlinkCount int, followFinal bool) (*metadata.Inode, []byte, error) {
	target := inode.GetSymlinkTarget()
	if target == "" {
		return nil, nil, fmt.Errorf("symlink %s has no target", prefix)
	}

	if !filepath.IsAbs(target) {
		dir := filepath.Dir(prefix)
		target = filepath.Join(dir, target)
	}

	// SEC: Sanitize target path to prevent escaping DistFS root
	target = "/" + strings.TrimLeft(filepath.Clean(target), "/")

	return c.resolvePathInternalRecursive(ctx, target, followFinal, symlinkCount)
}

func (c *Client) resolvePathInternalRecursive(ctx context.Context, path string, followFinal bool, symlinkCount int) (*metadata.Inode, []byte, error) {
	path = "/" + strings.Trim(path, "/")
	if path == "/" {
		// Root handled normally
		return c.resolvePathInternal(ctx, "/", followFinal)
	}

	// For simplicity, we restart resolution from root for symlinks
	// but we could optimize by resolving relative paths.
	rootInode, err := c.getInode(ctx, c.rootID)
	if err != nil {
		return nil, nil, err
	}
	rootKey, err := c.UnlockInode(ctx, rootInode)
	if err != nil {
		return nil, nil, err
	}

	return c.resolveSequential(ctx, rootInode, rootKey, strings.TrimPrefix(path, "/"), "", symlinkCount, followFinal)
}

// AddEntry creates a new directory entry.
func (c *Client) AddEntry(ctx context.Context, parentID string, parentKey []byte, name string, iType metadata.InodeType, r io.Reader, size int64, symlinkTarget string, mode uint32, groupID string, uid, gid uint32) (*metadata.Inode, []byte, error) {
	return c.addEntryInternal(ctx, parentID, parentKey, name, iType, r, size, symlinkTarget, mode, groupID, uid, gid, MkdirOptions{})
}

func (c *Client) addEntryInternal(ctx context.Context, parentID string, parentKey []byte, name string, iType metadata.InodeType, r io.Reader, size int64, symlinkTarget string, mode uint32, groupID string, uid, gid uint32, opts MkdirOptions) (*metadata.Inode, []byte, error) {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))
	pathID := "path:" + parentID + ":" + encName

	// 1. Acquire Exclusive Path Lease
	nonce := c.getSessionNonce()
	if nonce == "" {
		nonce = generateNonce()
	}
	if err := c.withConflictRetry(ctx, func() error {
		return c.AcquireLeases(ctx, []string{pathID}, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce})
	}); err != nil {
		return nil, nil, err
	}
	defer c.ReleaseLeases(ctx, []string{pathID}, nonce)

	// 2. Check if it already exists (Post-Lease check to avoid TOCTOU)
	parent, err := c.getInode(ctx, parentID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch parent: %w", err)
	}
	if entry, exists := parent.Children[encName]; exists {
		existing, err := c.getInode(ctx, entry.ID)
		if err == nil {
			return existing, nil, metadata.ErrExists
		}
		return nil, nil, metadata.ErrExists
	}

	ownerID := c.userID
	if opts.OwnerID != "" {
		ownerID = opts.OwnerID
	}

	inodeNonce := make([]byte, 16)
	rand.Read(inodeNonce)
	newID := metadata.GenerateInodeID(ownerID, inodeNonce)

	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, nil, err
	}

	// NEW: Upload data first if it's a file
	var inlineData []byte
	var chunkEntries []metadata.ChunkEntry
	if iType == metadata.FileType && r != nil {
		inlineData, chunkEntries, err = c.uploadDataInternal(ctx, newID, newKey, r, size)
		if err != nil {
			return nil, nil, err
		}
	}

	// 3. ATOMIC ADD (Child Create + Parent Update)
	err = c.withConflictRetry(ctx, func() error {
		// 1. Prepare Child Inode
		ownerID := c.userID
		if opts.OwnerID != "" {
			ownerID = opts.OwnerID
		}

		// 2. Fetch Latest Parent
		parent, err := c.getInode(ctx, parentID)
		if err != nil {
			return fmt.Errorf("failed to fetch parent: %w", err)
		}

		// Phase 51.5: Default ACL Inheritance
		var accessACL *metadata.POSIXAccess
		var defaultACL *metadata.POSIXAccess
		if parent.DefaultACL != nil {
			// Inherit DefaultACL as the AccessACL
			accessACL = &metadata.POSIXAccess{
				Users:  make(map[string]uint32),
				Groups: make(map[string]uint32),
			}
			for k, v := range parent.DefaultACL.Users {
				accessACL.Users[k] = v
			}
			for k, v := range parent.DefaultACL.Groups {
				accessACL.Groups[k] = v
			}
			if parent.DefaultACL.Mask != nil {
				m := *parent.DefaultACL.Mask
				accessACL.Mask = &m
			}

			// If it's a directory, it also inherits the DefaultACL
			if iType == metadata.DirType {
				defaultACL = &metadata.POSIXAccess{
					Users:  make(map[string]uint32),
					Groups: make(map[string]uint32),
				}
				for k, v := range parent.DefaultACL.Users {
					defaultACL.Users[k] = v
				}
				for k, v := range parent.DefaultACL.Groups {
					defaultACL.Groups[k] = v
				}
				if parent.DefaultACL.Mask != nil {
					m := *parent.DefaultACL.Mask
					defaultACL.Mask = &m
				}
			}
		}

		// Explicit options override inherited defaults (if provided)
		if opts.AccessACL != nil {
			accessACL = opts.AccessACL
		}
		if opts.DefaultACL != nil {
			defaultACL = opts.DefaultACL
		}

		lb, err := c.createLockbox(ctx, newKey, mode, ownerID, groupID, accessACL)
		if err != nil {
			return err
		}

		newInode := metadata.Inode{
			ID:    newID,
			Nonce: inodeNonce,
			Links: map[string]bool{
				parentID + ":" + encName: true,
			},
			Type:          iType,
			Mode:          mode,
			Children:      make(map[string]metadata.ChildEntry),
			ChunkManifest: chunkEntries,
			Lockbox:       lb,
			AccessACL:     accessACL,
			DefaultACL:    defaultACL,

			OwnerID: ownerID,
			GroupID: groupID,
			CTime:   time.Now().UnixNano(),
			NLink:   1,
			Version: 1,
		}
		newInode.SetSymlinkTarget(symlinkTarget)
		newInode.SetFileKey(newKey)
		newInode.SetMTime(time.Now().UnixNano())
		newInode.SetInlineData(inlineData)
		newInode.SetUID(uid)
		newInode.SetGID(gid)
		newInode.Size = uint64(size)
		if size == 0 {
			newInode.Size = uint64(len(inlineData))
		}

		// Final existence check to prevent overwriting
		if existing, exists := parent.Children[encName]; exists && existing.ID != newID {
			return metadata.ErrExists
		}

		parentKey, err := c.UnlockInode(ctx, parent)
		if err != nil {
			return fmt.Errorf("failed to unlock parent for name encryption: %w", err)
		}

		encNameBlob, nameNonce, err := c.EncryptEntryName(parentKey, name)
		if err != nil {
			return err
		}

		parent.SetFileKey(parentKey)
		if parent.Children == nil {
			parent.Children = make(map[string]metadata.ChildEntry)
		}
		parent.Children[encName] = metadata.ChildEntry{
			ID:            newID,
			EncryptedName: encNameBlob,
			Nonce:         nameNonce,
		}

		// 3. Prepare Commands
		cmdChild, err := c.PrepareCreate(ctx, newInode)
		if err != nil {
			return err
		}

		cmdParent, err := c.PrepareUpdate(ctx, *parent)
		if err != nil {
			return err
		}
		cmdParent.LeaseBindings = map[string]string{encName: parentID + ":" + encName}

		// 4. Submit Atomic Batch
		_, err = c.ApplyBatch(ctx, []metadata.LogCommand{cmdChild, cmdParent})
		return err
	})

	if err != nil {
		// Phase 53.3: Cleanup orphans if metadata update failed
		if len(chunkEntries) > 0 {
			go c.cleanupChunks(ctx, newID, chunkEntries)
		}
		return nil, nil, err
	}

	// Cache the newly generated key immediately so VerifyInode can succeed
	// during the subsequent getInode call, even if we aren't in the lockbox
	// (e.g., when an Admin provisions a directory for another user).
	c.keyMu.Lock()
	c.keyCache[newID] = fileMetadata{
		key:     newKey,
		groupID: groupID,
		linkTag: parentID + ":" + encName,
		inlined: size == 0 && len(inlineData) > 0,
	}
	c.keyMu.Unlock()

	finalInode, err := c.getInode(ctx, newID)
	return finalInode, newKey, err
}

// Mkdir creates a directory.
// MkdirOptions provides optional parameters for directory creation.
type MkdirOptions struct {
	OwnerID    string
	AccessACL  *metadata.POSIXAccess
	DefaultACL *metadata.POSIXAccess
}

// Mkdir creates a new directory at the specified path.
func (c *Client) Mkdir(ctx context.Context, path string, perm fs.FileMode) error {
	return c.MkdirExtended(ctx, path, perm, MkdirOptions{})
}

// MkdirExtended creates a new directory with optional parameters.
func (c *Client) MkdirExtended(ctx context.Context, path string, perm fs.FileMode, opts MkdirOptions) error {
	return c.addEntry(ctx, path, metadata.DirType, nil, 0, "", uint32(perm), opts)
}

// MkdirAll creates a directory and all parent directories.
func (c *Client) MkdirAll(ctx context.Context, path string) error {
	path = "/" + strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	current := "/"
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		err := c.Mkdir(ctx, current, 0755)
		if err != nil && err != metadata.ErrExists {
			return err
		}
	}
	return nil
}

// CreateFile creates a file with the given content.
func (c *Client) CreateFile(ctx context.Context, path string, r io.Reader, size int64) error {
	return c.addEntry(ctx, path, metadata.FileType, r, size, "", 0600, MkdirOptions{})
}

// Chmod changes the mode of a file or directory.
// Chmod changes the permission bits of the file or directory at the given path.
func (c *Client) Chmod(ctx context.Context, path string, mode fs.FileMode) error {
	return c.SetAttr(ctx, path, metadata.SetAttrRequest{
		Mode: ptr(uint32(mode)),
	})
}

// Chown changes the owner and group of a file or directory.
// Chown changes the owner and group of the file or directory at the given path.
func (c *Client) Chown(ctx context.Context, path string, ownerID, groupID string) error {
	return c.SetAttr(ctx, path, metadata.SetAttrRequest{
		OwnerID: &ownerID,
		GroupID: &groupID,
	})
}

// Symlink creates a symbolic link.
// Symlink creates a symbolic link at linkPath pointing to target.
func (c *Client) Symlink(ctx context.Context, target, linkPath string) error {
	return c.addEntry(ctx, linkPath, metadata.SymlinkType, nil, 0, target, 0777, MkdirOptions{})
}

// Rename moves or renames a directory entry.
// Rename atomically moves or renames a file or directory.
func (c *Client) Rename(ctx context.Context, oldPath, newPath string) error {
	oldDir, oldName := filepath.Split(strings.TrimRight(oldPath, "/"))
	newDir, newName := filepath.Split(strings.TrimRight(newPath, "/"))

	oldParent, oldParentKey, err := c.ResolvePath(ctx, oldDir)
	if err != nil {
		return fmt.Errorf("resolve old parent: %w", err)
	}
	newParent, newParentKey, err := c.ResolvePath(ctx, newDir)
	if err != nil {
		return fmt.Errorf("resolve new parent: %w", err)
	}

	if err := c.RenameRaw(ctx, oldParent.ID, oldParentKey, oldName, newParent.ID, newParentKey, newName); err != nil {
		return err
	}
	c.invalidatePathCache(oldPath)
	c.invalidatePathCache(newPath)
	return nil
}

func (c *Client) RenameRaw(ctx context.Context, oldParentID string, oldParentKey []byte, oldName string, newParentID string, newParentKey []byte, newName string) error {
	macOld := hmac.New(sha256.New, oldParentKey)
	macOld.Write([]byte(oldName))
	encOldName := hex.EncodeToString(macOld.Sum(nil))

	macNew := hmac.New(sha256.New, newParentKey)
	macNew.Write([]byte(newName))
	encNewName := hex.EncodeToString(macNew.Sum(nil))

	pathOld := "path:" + oldParentID + ":" + encOldName
	pathNew := "path:" + newParentID + ":" + encNewName

	// 1. Acquire Exclusive Path Leases
	nonce := c.getSessionNonce()
	if nonce == "" {
		nonce = generateNonce()
	}
	if err := c.withConflictRetry(ctx, func() error {
		return c.AcquireLeases(ctx, []string{pathOld, pathNew}, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce})
	}); err != nil {
		return err
	}
	defer c.ReleaseLeases(ctx, []string{pathOld, pathNew}, nonce)

	return c.withConflictRetry(ctx, func() error {
		// 1. Get Inode to move
		oldParent, err := c.getInode(ctx, oldParentID)
		if err != nil {
			return fmt.Errorf("failed to get old parent: %w", err)
		}
		entry, ok := oldParent.Children[encOldName]
		if !ok {
			return fs.ErrNotExist
		}
		childID := entry.ID

		child, err := c.getInode(ctx, childID)
		if err != nil {
			return fmt.Errorf("failed to get child: %w", err)
		}

		childKey, err := c.UnlockInode(ctx, child)
		if err != nil {
			return fmt.Errorf("failed to unlock child: %w", err)
		}

		var newParent *metadata.Inode
		if oldParentID == newParentID {
			newParent = oldParent
		} else {
			newParent, err = c.getInode(ctx, newParentID)
			if err != nil {
				return fmt.Errorf("failed to get new parent: %w", err)
			}
		}

		// Unlock new parent first (needed for name encryption and integrity check)
		newParentKey, err := c.UnlockInode(ctx, newParent)
		if err != nil {
			return fmt.Errorf("failed to unlock new parent for name encryption: %w", err)
		}

		// 2. Prepare Updates
		var cmds []metadata.LogCommand

		// Update Child Links
		if child.Links == nil {
			child.Links = make(map[string]bool)
		}
		delete(child.Links, oldParentID+":"+encOldName)
		child.Links[newParentID+":"+encNewName] = true
		child.SetMTime(time.Now().UnixNano())
		child.SetFileKey(childKey)

		cmdChild, err := c.PrepareUpdate(ctx, *child)
		if err != nil {
			return err
		}
		cmds = append(cmds, cmdChild)

		// Update Old Parent (Remove)
		delete(oldParent.Children, encOldName)

		// Handle Overwrite: If target exists, unlink it
		if existing, exists := newParent.Children[encNewName]; exists {
			existingID := existing.ID
			existingInode, err := c.getInode(ctx, existingID)
			if err == nil {
				if existingInode.NLink > 0 {
					existingInode.NLink--
				}
				delete(existingInode.Links, newParentID+":"+encNewName)

				cmd, err := c.PrepareUpdate(ctx, *existingInode)
				if err != nil {
					return err
				}
				cmds = append(cmds, cmd)
			}
		}

		// Update New Parent (Add)
		if newParent.Children == nil {
			newParent.Children = make(map[string]metadata.ChildEntry)
		}

		encNameBlob, nameNonce, err := c.EncryptEntryName(newParentKey, newName)
		if err != nil {
			return err
		}
		newParent.Children[encNewName] = metadata.ChildEntry{
			ID:            childID,
			EncryptedName: encNameBlob,
			Nonce:         nameNonce,
		}

		// Build batch
		if oldParentID != newParentID {
			cmd1, err := c.PrepareUpdate(ctx, *oldParent)
			if err != nil {
				return err
			}
			cmd1.LeaseBindings = map[string]string{encOldName: oldParentID + ":" + encOldName}

			cmd2, err := c.PrepareUpdate(ctx, *newParent)
			if err != nil {
				return err
			}
			cmd2.LeaseBindings = map[string]string{encNewName: newParentID + ":" + encNewName}

			cmds = append(cmds, cmd1, cmd2)
		} else {
			cmd1, err := c.PrepareUpdate(ctx, *oldParent)
			if err != nil {
				return err
			}
			cmd1.LeaseBindings = map[string]string{
				encOldName: oldParentID + ":" + encOldName,
				encNewName: newParentID + ":" + encNewName,
			}
			cmds = append(cmds, cmd1)
		}

		// 3. Submit Atomic Batch
		_, err = c.ApplyBatch(ctx, cmds)
		return err
	})
}

// Copy recursively copies a file or directory from src to dst.
func (c *Client) Copy(ctx context.Context, src, dst string) error {
	src = "/" + strings.Trim(src, "/")
	dst = "/" + strings.Trim(dst, "/")

	inode, _, err := c.ResolvePath(ctx, src)
	if err != nil {
		return fmt.Errorf("resolve src: %w", err)
	}

	return c.copyInternal(ctx, inode, src, dst)
}

func (c *Client) copyInternal(ctx context.Context, inode *metadata.Inode, src, dst string) error {
	switch inode.Type {
	case metadata.FileType:
		// 1. Download
		rc, err := c.OpenBlobRead(ctx, src)
		if err != nil {
			return fmt.Errorf("open src: %w", err)
		}
		defer rc.Close()

		// 2. Upload (CreateFile handles new key generation and encryption)
		if err := c.CreateFile(ctx, dst, rc, int64(inode.Size)); err != nil {
			return fmt.Errorf("create dst: %w", err)
		}

	case metadata.DirType:
		// 1. Create target directory
		if err := c.Mkdir(ctx, dst, 0755); err != nil && !errors.Is(err, metadata.ErrExists) {
			return fmt.Errorf("mkdir dst: %w", err)
		}

		// 2. List children
		entries, err := c.ReadDirExtended(ctx, src, true)
		if err != nil {
			return fmt.Errorf("readdir src: %w", err)
		}

		// 3. Recurse
		for _, entry := range entries {
			childSrc := filepath.Join(src, entry.Name())
			childDst := filepath.Join(dst, entry.Name())
			if err := c.copyInternal(ctx, entry.Inode(), childSrc, childDst); err != nil {
				return err
			}
		}

	case metadata.SymlinkType:
		target := inode.GetSymlinkTarget()
		if err := c.Symlink(ctx, target, dst); err != nil {
			return fmt.Errorf("symlink dst: %w", err)
		}

	default:
		return fmt.Errorf("unsupported inode type: %v", inode.Type)
	}

	return nil
}

// RemoveEntry deletes a directory entry.
func (c *Client) RemoveEntry(ctx context.Context, path string) error {
	dir, name := filepath.Split(strings.TrimRight(path, "/"))
	parent, parentKey, err := c.ResolvePath(ctx, dir)
	if err != nil {
		return err
	}
	if err := c.RemoveEntryRaw(ctx, parent.ID, parentKey, name); err != nil {
		return err
	}
	c.invalidatePathCache("/" + strings.Trim(path, "/"))
	return nil
}

// RemoveAll recursively deletes a path.
func (c *Client) RemoveAll(ctx context.Context, path string) error {
	path = "/" + strings.Trim(path, "/")
	inode, _, err := c.ResolvePath(ctx, path)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}

	if inode.Type == metadata.DirType {
		// List children and remove them
		distFS := c.FS(ctx)
		relPath := strings.TrimPrefix(path, "/")
		if relPath == "" {
			relPath = "."
		}
		entries, err := fs.ReadDir(distFS, relPath)
		if err == nil {
			for _, entry := range entries {
				if err := c.RemoveAll(ctx, filepath.Join(path, entry.Name())); err != nil {
					return err
				}
			}
		}
	}

	return c.Remove(ctx, path)
}

// RemoveEntryRaw performs a removal operation using raw IDs and names.
func (c *Client) RemoveEntryRaw(ctx context.Context, parentID string, parentKey []byte, name string) error {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))
	pathID := "path:" + parentID + ":" + encName

	// 1. Acquire Exclusive Path Lease
	nonce := c.getSessionNonce()
	if nonce == "" {
		nonce = generateNonce()
	}
	if err := c.withConflictRetry(ctx, func() error {
		return c.AcquireLeases(ctx, []string{pathID}, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce})
	}); err != nil {
		return err
	}
	defer c.ReleaseLeases(ctx, []string{pathID}, nonce)

	return c.withConflictRetry(ctx, func() error {
		// 2. Get Inodes
		parent, err := c.getInode(ctx, parentID)
		if err != nil {
			return err
		}
		entry, ok := parent.Children[encName]
		if !ok {
			return nil // Already gone
		}
		childID := entry.ID

		// 2. Prepare Updates
		var cmds []metadata.LogCommand

		// Remove from Parent
		delete(parent.Children, encName)
		cmdParent, err := c.PrepareUpdate(ctx, *parent)
		if err != nil {
			return err
		}
		cmdParent.LeaseBindings = map[string]string{encName: parentID + ":" + encName}
		cmds = append(cmds, cmdParent)

		// Decrement NLink / Update Child Links
		child, err := c.getInode(ctx, childID)
		if err != nil {
			if isNotFound(err) {
				// Child inode already gone? Just finish removing from parent.
				_, err := c.ApplyBatch(ctx, []metadata.LogCommand{cmdParent})
				return err
			}
			return err
		}
		if child.Type == metadata.DirType && len(child.Children) > 0 {
			return fmt.Errorf("directory not empty")
		}

		child.NLink--
		if child.Links != nil {
			delete(child.Links, parentID+":"+encName)
		}
		child.SetMTime(time.Now().UnixNano())
		cmdChild, err := c.PrepareUpdate(ctx, *child)
		if err != nil {
			return err
		}
		cmds = append(cmds, cmdChild)

		// 3. Submit Atomic Batch
		_, err = c.ApplyBatch(ctx, cmds)
		return err
	})
}

// Stat returns file info for the given path.
// Stat returns metadata information for the file or directory at the given path.
func (c *Client) Stat(ctx context.Context, path string) (*DistFileInfo, error) {
	inode, _, err := c.ResolvePathExtended(ctx, path, true)
	if err != nil {
		return nil, err
	}
	_, fileName := filepath.Split(path)
	if fileName == "" && path == "/" {
		fileName = "/"
	}
	return &DistFileInfo{inode: inode, name: fileName}, nil
}

// Lstat returns file info for the given path, without following the final symlink.
// Lstat returns metadata information for the path, without following symbolic links.
func (c *Client) Lstat(ctx context.Context, path string) (*DistFileInfo, error) {
	inode, _, err := c.ResolvePathExtended(ctx, path, false)
	if err != nil {
		return nil, err
	}
	_, fileName := filepath.Split(path)
	if fileName == "" && path == "/" {
		fileName = "/"
	}
	return &DistFileInfo{inode: inode, name: fileName}, nil
}

// ReadDir returns a list of directory entries for the given path.
func (c *Client) ReadDir(ctx context.Context, path string) ([]*DistDirEntry, error) {
	return c.ReadDirExtended(ctx, path, false)
}

// Open opens a file or directory for reading.
func (c *Client) Open(ctx context.Context, path string, flag int, perm fs.FileMode) (*DistFile, error) {
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		return nil, err
	}

	if inode.Type == metadata.DirType {
		return nil, fmt.Errorf("is a directory") // CLIENT-API says *DistFile, but maybe we should support DistDir too
	}

	reader, err := c.NewReader(ctx, inode.ID, key)
	if err != nil {
		return nil, err
	}

	return &DistFile{reader: reader}, nil
}

// Link creates a hard link.
// Link creates a hard link at linkPath pointing to an existing file at targetPath.
func (c *Client) Link(ctx context.Context, targetPath, linkPath string) error {
	target, _, err := c.ResolvePath(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}

	if target.Type == metadata.DirType {
		return errors.New("is a directory")
	}

	dir, name := filepath.Split(strings.TrimRight(linkPath, "/"))
	parent, parentKey, err := c.ResolvePath(ctx, dir)
	if err != nil {
		return fmt.Errorf("resolve parent: %w", err)
	}

	if err := c.LinkRaw(ctx, parent.ID, parentKey, name, target.ID); err != nil {
		return err
	}

	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	targetKey, _ := c.UnlockInode(ctx, target)

	c.putPathCache("/"+strings.Trim(linkPath, "/"), pathCacheEntry{
		inodeID: target.ID,
		key:     targetKey,
		linkTag: parent.ID + ":" + encName,
	})
	return nil
}

// LinkRaw performs a linking operation using raw IDs and names.
func (c *Client) LinkRaw(ctx context.Context, parentID string, parentKey []byte, name string, targetID string) error {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))
	pathID := "path:" + parentID + ":" + encName

	// 1. Acquire Exclusive Path Lease
	nonce := c.getSessionNonce()
	if nonce == "" {
		nonce = generateNonce()
	}
	if err := c.withConflictRetry(ctx, func() error {
		return c.AcquireLeases(ctx, []string{pathID}, 2*time.Minute, LeaseOptions{Type: metadata.LeaseExclusive, Nonce: nonce})
	}); err != nil {
		return err
	}
	defer c.ReleaseLeases(ctx, []string{pathID}, nonce)

	return c.withConflictRetry(ctx, func() error {
		// 1. Get Inodes
		target, err := c.getInode(ctx, targetID)
		if err != nil {
			return err
		}
		parent, err := c.getInode(ctx, parentID)
		if err != nil {
			return err
		}

		// 2. Prepare Updates
		var cmds []metadata.LogCommand

		target.NLink++
		if target.Links == nil {
			target.Links = make(map[string]bool)
		}
		target.Links[parentID+":"+encName] = true
		target.SetMTime(time.Now().UnixNano())
		cmdTarget, err := c.PrepareUpdate(ctx, *target)
		if err != nil {
			return err
		}
		cmds = append(cmds, cmdTarget)

		parentKey, err := c.UnlockInode(ctx, parent)
		if err != nil {
			return fmt.Errorf("failed to unlock parent for name encryption: %w", err)
		}

		if parent.Children == nil {
			parent.Children = make(map[string]metadata.ChildEntry)
		}

		encNameBlob, nameNonce, err := c.EncryptEntryName(parentKey, name)
		if err != nil {
			return err
		}
		parent.Children[encName] = metadata.ChildEntry{
			ID:            targetID,
			EncryptedName: encNameBlob,
			Nonce:         nameNonce,
		}
		cmdParent, err := c.PrepareUpdate(ctx, *parent)
		if err != nil {
			return err
		}
		cmdParent.LeaseBindings = map[string]string{encName: parentID + ":" + encName}
		cmds = append(cmds, cmdParent)

		// 3. Submit Atomic Batch
		_, err = c.ApplyBatch(ctx, cmds)
		return err
	})
}

func (c *Client) addEntry(ctx context.Context, path string, iType metadata.InodeType, r io.Reader, size int64, symlinkTarget string, mode uint32, opts MkdirOptions) error {
	path = strings.Trim(path, "/")
	if path == "" {
		return fmt.Errorf("cannot create root")
	}

	dir, name := filepath.Split(path)

	parentInode, parentKey, err := c.ResolvePath(ctx, dir)
	if err != nil {
		return fmt.Errorf("addEntry ResolvePath failed for dir %s: %w", dir, err)
	}

	if parentInode.Type != metadata.DirType {
		return fmt.Errorf("parent is not a directory")
	}

	// Check if it already exists
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	if existing, ok := parentInode.Children[encName]; ok {
		existingID := existing.ID
		if iType == metadata.FileType {
			// Update existing file content
			err := c.writeInodeContent(ctx, existingID, nil, iType, nil, r, size, name, nil, mode, "", parentInode.ID, encName, 0, 0, opts.AccessACL)
			if err != nil {
				return fmt.Errorf("addEntry writeInodeContent (existing) failed: %w", err)
			}
			return nil
		}
		return metadata.ErrExists
	}

	groupID := parentInode.GroupID
	if opts.OwnerID != "" && opts.OwnerID != c.userID {
		// Provisioning for another user: clear the parent's group to avoid lockbox errors
		// if the new user isn't a member of the parent's group.
		groupID = ""
	}

	_, _, err = c.addEntryInternal(ctx, parentInode.ID, parentKey, name, iType, r, size, symlinkTarget, mode, groupID, 0, 0, opts)
	if err != nil {
		return fmt.Errorf("addEntry AddEntry failed: %w", err)
	}
	return nil
}

func (c *Client) createLockbox(ctx context.Context, key []byte, mode uint32, ownerID, groupID string, acl *metadata.POSIXAccess) (crypto.Lockbox, error) {
	lb := crypto.NewLockbox()

	effectiveOwner := ownerID
	if effectiveOwner == "" {
		effectiveOwner = c.userID
	}

	if effectiveOwner == c.userID {
		if c.decKey != nil {
			lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), key)
		}
	} else {
		// User Owner
		user, err := c.GetUser(ctx, effectiveOwner)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch user owner %s: %w", effectiveOwner, err)
		}
		upk, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal user enc key: %w", err)
		}
		lb.AddRecipient(effectiveOwner, upk, key)
	}

	if (mode & 0004) != 0 {
		wpk, err := c.GetWorldPublicKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch world public key: %w", err)
		}
		lb.AddRecipient(metadata.WorldID, wpk, key)
	}

	if groupID != "" && (mode&0040) != 0 {
		group, err := c.GetGroup(ctx, groupID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch group %s: %w", groupID, err)
		}
		gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal group enc key: %w", err)
		}
		lb.AddRecipient(groupID, gpk, key)
	}

	// Add users/groups granted read access via POSIX ACL
	if acl != nil {
		for uid, bits := range acl.Users {
			if (bits & 4) != 0 { // Has read permission
				user, err := c.GetUser(ctx, uid)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch ACL user %s: %w", uid, err)
				}
				upk, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal ACL user enc key: %w", err)
				}
				lb.AddRecipient(uid, upk, key)
			}
		}
		for gid, bits := range acl.Groups {
			if (bits & 4) != 0 { // Has read permission
				group, err := c.GetGroup(ctx, gid)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch ACL group %s: %w", gid, err)
				}
				gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal ACL group enc key: %w", err)
				}
				lb.AddRecipient(gid, gpk, key)
			}
		}
	}

	return lb, nil
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
