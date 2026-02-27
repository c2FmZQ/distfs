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
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// EnsureRoot initializes the root directory inode. It returns an error if it already exists.
func (c *Client) EnsureRoot(ctx context.Context) error {
	inode, err := c.getInode(ctx, c.rootID)
	if err == nil {
		c.rootOwner = inode.OwnerID
		c.rootVersion = inode.Version
		return metadata.ErrExists
	}

	if c.decKey == nil {
		return fmt.Errorf("cannot create secure root without identity")
	}

	rootKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rootKey); err != nil {
		return err
	}

	lb := c.createLockbox(ctx, rootKey, 0755, "")
	newInode := metadata.Inode{
		ID:       c.rootID,
		Type:     metadata.DirType,
		Mode:     0755,
		Children: make(map[string]string),
		Lockbox:  lb,
		OwnerID:  c.userID,
		NLink:    1,
	}
	newInode.SetFileKey(rootKey)
	newInode.SetAuthorizedSigners([]string{c.userID})
	newInode.Version = 1
	_, err = c.createInode(ctx, newInode)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusConflict {
			// Already exists, but we MUST fetch it to capture the anchor (owner/version)
			_, err = c.getInode(ctx, c.rootID)
			return err
		}
		return err
	}
	return nil
}

// ResolvePath resolves a string path to an Inode and its FileKey.
func (c *Client) ResolvePath(ctx context.Context, path string) (*metadata.Inode, []byte, error) {
	path = "/" + strings.Trim(path, "/")

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			c.clearPathCache()
		}

		inode, key, err := c.resolvePathInternal(ctx, path)
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

func (c *Client) resolvePathInternal(ctx context.Context, path string) (*metadata.Inode, []byte, error) {
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
					return inode, entry.key, nil
				}
				return c.resolveSequential(ctx, inode, entry.key, remainingPath, prefix)
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

	return c.resolveSequential(ctx, rootInode, rootKey, strings.TrimPrefix(path, "/"), "")
}

func (c *Client) resolveSequential(ctx context.Context, currentInode *metadata.Inode, currentKey []byte, remainingPath string, prefix string) (*metadata.Inode, []byte, error) {
	parts := strings.Split(remainingPath, "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if currentInode.Type != metadata.DirType {
			return nil, nil, fmt.Errorf("path component %s is not a directory", prefix)
		}

		mac := hmac.New(sha256.New, currentKey)
		mac.Write([]byte(part))
		encName := hex.EncodeToString(mac.Sum(nil))

		childID, ok := currentInode.Children[encName]
		if !ok {
			return nil, nil, fmt.Errorf("path component %s not found in %s", part, prefix)
		}

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

		currentInode = childInode
		currentKey = childKey
	}

	return currentInode, currentKey, nil
}

// AddEntry creates a new directory entry.
func (c *Client) AddEntry(ctx context.Context, parentID string, parentKey []byte, name string, iType metadata.InodeType, r io.Reader, size int64, symlinkTarget string, mode uint32, groupID string, uid, gid uint32) (*metadata.Inode, []byte, error) {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	newID := generateID()
	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, nil, err
	}

	encNameBlob, err := crypto.EncryptDEM(newKey, []byte(name))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt name: %w", err)
	}

	var newInode *metadata.Inode
	if iType == metadata.FileType {
		if err := c.writeInodeContent(ctx, newID, iType, newKey, r, size, name, encNameBlob, mode, groupID, parentID, encName, uid, gid); err != nil {
			return nil, nil, err
		}
		newInode, err = c.getInode(ctx, newID)
		if err != nil {
			return nil, nil, err
		}
	} else {
		lb := c.createLockbox(ctx, newKey, mode, groupID)
		inode := metadata.Inode{
			ID: newID,
			Links: map[string]bool{
				parentID + ":" + encName: true,
			},
			Type:     iType,
			Mode:     mode,
			Children: make(map[string]string),
			Lockbox:  lb,
			OwnerID:  c.userID,
			GroupID:  groupID,
		}
		inode.SetName(name)
		inode.SetSymlinkTarget(symlinkTarget)
		inode.SetFileKey(newKey)
		inode.Version = 1

		newInode, err = c.createInode(ctx, inode)
		if err != nil {
			return nil, nil, err
		}
	}

	// 3. ATOMIC MERGE PARENT
	_, err = c.UpdateInode(ctx, parentID, func(p *metadata.Inode) error {
		p.SetFileKey(parentKey)
		if p.Children == nil {
			p.Children = make(map[string]string)
		}
		// MERGE: Only add our specific new entry
		p.Children[encName] = newID
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update parent: %w", err)
	}

	return newInode, newKey, nil
}

// Mkdir creates a directory.
func (c *Client) Mkdir(ctx context.Context, path string, perm fs.FileMode) error {
	return c.addEntry(ctx, path, metadata.DirType, nil, 0, "", uint32(perm))
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
	return c.addEntry(ctx, path, metadata.FileType, r, size, "", 0600)
}

// Chmod changes the mode of a file or directory.
func (c *Client) Chmod(ctx context.Context, path string, mode fs.FileMode) error {
	return c.SetAttr(ctx, path, metadata.SetAttrRequest{
		Mode: ptr(uint32(mode)),
	})
}

// Chown changes the owner and group of a file or directory.
func (c *Client) Chown(ctx context.Context, path string, ownerID, groupID string) error {
	return c.SetAttr(ctx, path, metadata.SetAttrRequest{
		OwnerID: &ownerID,
		GroupID: &groupID,
	})
}

// Symlink creates a symbolic link.
func (c *Client) Symlink(ctx context.Context, target, linkPath string) error {
	return c.addEntry(ctx, linkPath, metadata.SymlinkType, nil, 0, target, 0777)
}

// Rename moves or renames a directory entry.
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

	return c.withRetry(ctx, func() error {
		// 1. Get Inode to move
		oldParent, err := c.getInode(ctx, oldParentID)
		if err != nil {
			return fmt.Errorf("failed to get old parent: %w", err)
		}
		childID, ok := oldParent.Children[encOldName]
		if !ok {
			return syscall.ENOENT
		}

		child, err := c.getInode(ctx, childID)
		if err != nil {
			return fmt.Errorf("failed to get child: %w", err)
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

		// 2. Prepare Updates
		var cmds []metadata.LogCommand

		// Update Old Parent (Remove)
		delete(oldParent.Children, encOldName)

		// Handle Overwrite: If target exists, unlink it
		if existingID, exists := newParent.Children[encNewName]; exists {
			existing, err := c.getInode(ctx, existingID)
			if err == nil {
				if existing.NLink > 0 {
					existing.NLink--
				}
				delete(existing.Links, newParentID+":"+encNewName)

				cmd, err := c.PrepareUpdate(ctx, *existing)
				if err != nil {
					return err
				}
				cmds = append(cmds, cmd)
			}
		}

		// Update New Parent (Add)
		if newParent.Children == nil {
			newParent.Children = make(map[string]string)
		}
		newParent.Children[encNewName] = childID

		// Build batch
		if oldParentID != newParentID {
			cmd1, _ := c.PrepareUpdate(ctx, *oldParent)
			cmd2, _ := c.PrepareUpdate(ctx, *newParent)
			cmds = append(cmds, cmd1, cmd2)
		} else {
			cmd1, _ := c.PrepareUpdate(ctx, *oldParent)
			cmds = append(cmds, cmd1)
		}

		// Update Child Links
		if child.Links == nil {
			child.Links = make(map[string]bool)
		}
		delete(child.Links, oldParentID+":"+encOldName)
		child.Links[newParentID+":"+encNewName] = true
		cmdChild, _ := c.PrepareUpdate(ctx, *child)
		cmds = append(cmds, cmdChild)

		if _, err := c.ApplyBatch(ctx, cmds); err != nil {
			return err
		}
		return nil
	})
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

	// 1. Get ChildID
	parent, err := c.getInode(ctx, parentID)
	if err != nil {
		return err
	}
	childID, ok := parent.Children[encName]
	if !ok {
		return nil // Already gone
	}

	// 2. Atomic Merge Removal from Parent
	_, err = c.UpdateInode(ctx, parentID, func(p *metadata.Inode) error {
		delete(p.Children, encName)
		return nil
	})
	if err != nil {
		return err
	}

	// 3. Decrement NLink / Delete Child
	_, err = c.UpdateInode(ctx, childID, func(child *metadata.Inode) error {
		if child.Type == metadata.DirType && len(child.Children) > 0 {
			return fmt.Errorf("directory not empty")
		}
		if child.NLink > 0 {
			child.NLink--
		}
		if child.Links != nil {
			delete(child.Links, parentID+":"+encName)
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// Stat returns file info for the given path.
func (c *Client) Stat(ctx context.Context, path string) (*DistFileInfo, error) {
	inode, _, err := c.ResolvePath(ctx, path)
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
func (c *Client) Lstat(ctx context.Context, path string) (*DistFileInfo, error) {
	// Our ResolvePath currently follows all symlinks.
	// TODO: Support Lstat properly by adding a 'followFinal' flag to ResolvePath.
	return c.Stat(ctx, path)
}

// ReadDir returns a list of directory entries for the given path.
func (c *Client) ReadDir(ctx context.Context, path string) ([]*DistDirEntry, error) {
	return c.ReadDirExtended(ctx, path)
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
func (c *Client) Link(ctx context.Context, targetPath, linkPath string) error {
	target, _, err := c.ResolvePath(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}

	if target.Type == metadata.DirType {
		return syscall.EISDIR
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

	// 1. Update Target (Link Count)
	_, err := c.UpdateInode(ctx, targetID, func(t *metadata.Inode) error {
		t.NLink++
		if t.Links == nil {
			t.Links = make(map[string]bool)
		}
		// MERGE: Add our specific new link
		t.Links[parentID+":"+encName] = true
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update target for link: %w", err)
	}

	// 2. Atomic Merge Parent
	_, err = c.UpdateInode(ctx, parentID, func(p *metadata.Inode) error {
		if p.Children == nil {
			p.Children = make(map[string]string)
		}
		p.Children[encName] = targetID
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update parent for link: %w", err)
	}

	return nil
}

func (c *Client) addEntry(ctx context.Context, path string, iType metadata.InodeType, r io.Reader, size int64, symlinkTarget string, mode uint32) error {
	path = strings.Trim(path, "/")
	if path == "" {
		return fmt.Errorf("cannot create root")
	}

	dir, name := filepath.Split(path)

	parentInode, parentKey, err := c.ResolvePath(ctx, dir)
	if err != nil {
		return err
	}

	if parentInode.Type != metadata.DirType {
		return fmt.Errorf("parent is not a directory")
	}

	// Check if it already exists
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	if existingID, ok := parentInode.Children[encName]; ok {
		if iType == metadata.FileType {
			// Update existing file content
			return c.writeInodeContent(ctx, existingID, iType, nil, r, size, name, nil, mode, "", parentInode.ID, encName, 0, 0)
		}
		return metadata.ErrExists
	}

	_, _, err = c.AddEntry(ctx, parentInode.ID, parentKey, name, iType, r, size, symlinkTarget, mode, parentInode.GroupID, 0, 0)
	return err
}

func (c *Client) createLockbox(ctx context.Context, key []byte, mode uint32, groupID string) crypto.Lockbox {
	lb := crypto.NewLockbox()
	if c.decKey != nil {
		lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), key)
	}
	if (mode & 0004) != 0 {
		wpk, err := c.GetWorldPublicKey(ctx)
		if err == nil {
			lb.AddRecipient(metadata.WorldID, wpk, key)
		}
	}
	if groupID != "" && (mode&0060) != 0 {
		group, err := c.GetGroup(ctx, groupID)
		if err == nil {
			gpk, err := crypto.UnmarshalEncapsulationKey(group.EncKey)
			if err == nil {
				lb.AddRecipient(groupID, gpk, key)
			}
		}
	}
	return lb
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
