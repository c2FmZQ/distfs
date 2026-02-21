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
	"net/http"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// EnsureRoot makes sure the root directory inode exists.
func (c *Client) EnsureRoot(ctx context.Context) error {
	_, err := c.getInode(ctx, metadata.RootID)
	if err == nil {
		return nil
	}

	if c.decKey == nil {
		return fmt.Errorf("cannot create secure root without identity")
	}

	rootKey := make([]byte, 32)
	if _, err := rand.Read(rootKey); err != nil {
		return err
	}

	lb := c.createLockbox(ctx, rootKey, 0755, "")
	inode := metadata.Inode{
		ID:       metadata.RootID,
		Type:     metadata.DirType,
		Mode:     0755,
		Children: make(map[string]string),
		Lockbox:  lb,
		OwnerID:  c.userID,
	}
	inode.SetFileKey(rootKey)
	inode.SetAuthorizedSigners([]string{c.userID})
	_, err = c.createInode(ctx, inode)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusConflict {
			// Already exists, but we MUST fetch it to capture the anchor (owner/version)
			_, err = c.getInode(ctx, metadata.RootID)
			return err
		}
		return err
	}
	return nil
}

// ResolvePath traverses the directory tree to find the inode and key for a path.
func (c *Client) ResolvePath(ctx context.Context, path string) (*metadata.Inode, []byte, error) {
	path = "/" + strings.Trim(path, "/")

	// 1. Check Path Cache for longest prefix
	var currentInode *metadata.Inode
	var currentKey []byte
	var remainingPath string

	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = []string{""}
	}

	for i := len(parts); i >= 0; i-- {
		prefix := "/" + strings.Join(parts[:i], "/")
		if entry, ok := c.getPathCache(prefix); ok {
			inode, err := c.getInode(ctx, entry.inodeID)
			if err == nil {
				// Validate hint integrity
				valid := false
				if prefix == "/" {
					valid = inode.ID == metadata.RootID
				} else if inode.Links != nil {
					valid = inode.Links[entry.linkTag]
				}

				if valid {
					currentInode = inode
					currentKey = entry.key
					remainingPath = strings.Join(parts[i:], "/")
					break
				}
				c.invalidatePathCache(prefix)
			} else if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
				c.invalidatePathCache(prefix)
			}
		}
	}

	// 2. Sequential Resolution from the found prefix or root
	if currentInode == nil {
		rootInode, err := c.getInode(ctx, metadata.RootID)
		if err != nil {
			if err := c.EnsureRoot(ctx); err != nil {
				return nil, nil, fmt.Errorf("failed to ensure root inode: %w", err)
			}
			rootInode, err = c.getInode(ctx, metadata.RootID)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get root inode after creation: %w", err)
			}
		}

		if c.decKey == nil {
			return nil, nil, fmt.Errorf("client has no identity to unlock root")
		}

		rootKey, err := c.UnlockInode(ctx, rootInode)
		if err != nil {
			return nil, nil, fmt.Errorf("access denied to root: %w", err)
		}

		// Populate cache for root
		c.putPathCache("/", pathCacheEntry{inodeID: metadata.RootID, key: rootKey})

		currentInode = rootInode
		currentKey = rootKey
		remainingPath = strings.TrimPrefix(path, "/")
	}

	if remainingPath == "" || remainingPath == "." {
		return currentInode, currentKey, nil
	}

	remParts := strings.Split(remainingPath, "/")
	currPath := path[:strings.Index(path, remainingPath)]
	if !strings.HasSuffix(currPath, "/") {
		currPath += "/"
	}

	for _, part := range remParts {
		if part == "" || part == "." {
			continue
		}

		mac := hmac.New(sha256.New, currentKey)
		mac.Write([]byte(part))
		encName := hex.EncodeToString(mac.Sum(nil))

		childID, ok := currentInode.Children[encName]
		if !ok {
			return nil, nil, fmt.Errorf("entry %s not found", part)
		}

		parentID := currentInode.ID
		var err error
		currentInode, err = c.getInode(ctx, childID)
		if err != nil {
			return nil, nil, err
		}

		key, err := c.UnlockInode(ctx, currentInode)
		if err != nil {
			return nil, nil, fmt.Errorf("access denied to %s: %w", part, err)
		}

		currPath += part
		c.putPathCache(currPath, pathCacheEntry{
			inodeID: currentInode.ID,
			key:     key,
			linkTag: parentID + ":" + encName,
		})
		currentKey = key
		currPath += "/"
	}

	return currentInode, currentKey, nil
}

// Mkdir creates a new directory.
func (c *Client) Mkdir(ctx context.Context, path string) error {
	return c.addEntry(ctx, path, metadata.DirType, nil, 0, "", 0700)
}

// CreateFile creates a new file with the given content.
func (c *Client) CreateFile(ctx context.Context, path string, r io.Reader, size int64) error {
	return c.addEntry(ctx, path, metadata.FileType, r, size, "", 0600)
}

// Symlink creates a new symbolic link.
func (c *Client) Symlink(ctx context.Context, target, path string) error {
	return c.addEntry(ctx, path, metadata.SymlinkType, nil, 0, target, 0777)
}

// AddEntry adds a new directory entry to the given parent.

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
		if err := c.writeInodeContent(ctx, newID, iType, newKey, r, size, name, encNameBlob, mode, groupID, parentID, encName); err != nil {
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

		newInode, err = c.createInode(ctx, inode)

		if err != nil {

			return nil, nil, err

		}

	}

	// UPDATE PARENT (Phase 31: Manifest Signing)
	parent, err := c.getInode(ctx, parentID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get parent for update: %w", err)
	}
	parent.SetFileKey(parentKey)
	if parent.Children == nil {
		parent.Children = make(map[string]string)
	}
	parent.Children[encName] = newID
	_, err = c.updateInode(ctx, *parent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update parent: %w", err)
	}

	return newInode, newKey, nil
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
	return nil
}

// RenameRaw performs a rename operation using raw IDs and names.
func (c *Client) RenameRaw(ctx context.Context, oldParentID string, oldParentKey []byte, oldName string, newParentID string, newParentKey []byte, newName string) error {
	macOld := hmac.New(sha256.New, oldParentKey)
	macOld.Write([]byte(oldName))
	encOldName := hex.EncodeToString(macOld.Sum(nil))

	macNew := hmac.New(sha256.New, newParentKey)
	macNew.Write([]byte(newName))
	encNewName := hex.EncodeToString(macNew.Sum(nil))

	return c.withConflictRetry(ctx, func() error {
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
		// If parents are same, we update newParent later (which is same pointer)

		// Handle Overwrite: If target exists, unlink it
		if existingID, exists := newParent.Children[encNewName]; exists {
			existing, err := c.getInode(ctx, existingID)
			if err == nil {
				if existing.NLink > 0 {
					existing.NLink--
				}
				delete(existing.Links, newParentID+":"+encNewName)

				if existing.NLink == 0 {
					cmd, err := c.PrepareDelete(existing.ID)
					if err != nil {
						return err
					}
					cmds = append(cmds, cmd)
				} else {
					cmd, err := c.PrepareUpdate(ctx, *existing)
					if err != nil {
						return err
					}
					cmds = append(cmds, cmd)
				}
			} else {
				// If we can't load the existing file, it might be corrupted or we lack permissions.
				// For rename, we should arguably fail if we can't clean up.
				// But we definitely shouldn't leave a dangling pointer.
				// If it's 404, just proceed.
				if apiErr, ok := err.(*APIError); !ok || apiErr.StatusCode != http.StatusNotFound {
					return fmt.Errorf("failed to handle overwrite: %w", err)
				}
			}
		}

		// Update New Parent (Add)
		if newParent.Children == nil {
			newParent.Children = make(map[string]string)
		}
		newParent.Children[encNewName] = childID

		// If parents are different, we add both. If same, we add "oldParent" (which is modified twice).
		if oldParentID != newParentID {
			cmd, err := c.PrepareUpdate(ctx, *oldParent)
			if err != nil {
				return err
			}
			cmds = append(cmds, cmd)

			cmd2, err := c.PrepareUpdate(ctx, *newParent)
			if err != nil {
				return err
			}
			cmds = append(cmds, cmd2)
		} else {
			cmd, err := c.PrepareUpdate(ctx, *oldParent)
			if err != nil {
				return err
			}
			cmds = append(cmds, cmd)
		}

		// Update Child Links
		if child.Links == nil {
			child.Links = make(map[string]bool)
		}
		delete(child.Links, oldParentID+":"+encOldName)
		child.Links[newParentID+":"+encNewName] = true
		cmdChild, err := c.PrepareUpdate(ctx, *child)
		if err != nil {
			return err
		}
		cmds = append(cmds, cmdChild)

		// 3. Apply Batch
		if err := c.ApplyBatch(ctx, cmds); err != nil {
			// Don't wrap error here, return raw error so withConflictRetry detects it
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

// RemoveEntryRaw performs a removal operation using raw IDs and names.
func (c *Client) RemoveEntryRaw(ctx context.Context, parentID string, parentKey []byte, name string) error {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	return c.withConflictRetry(ctx, func() error {
		// 1. Get Parent and find ChildID
		parent, err := c.getInode(ctx, parentID)
		if err != nil {
			return fmt.Errorf("failed to get parent for removal: %w", err)
		}
		childID, ok := parent.Children[encName]
		if !ok {
			return nil // Already gone
		}

		// 2. Load Child
		child, err := c.getInode(ctx, childID)
		if err != nil {
			return fmt.Errorf("failed to get child for removal: %w", err)
		}

		// 3. POSIX check: Directory must be empty
		if child.Type == metadata.DirType && len(child.Children) > 0 {
			return fmt.Errorf("directory not empty")
		}

		var cmds []metadata.LogCommand

		// 4. Update Parent
		delete(parent.Children, encName)
		cmdParent, err := c.PrepareUpdate(ctx, *parent)
		if err != nil {
			return err
		}
		cmds = append(cmds, cmdParent)

		// 5. Update Child
		if child.NLink > 0 {
			child.NLink--
		}
		if child.Links != nil {
			delete(child.Links, parentID+":"+encName)
		}

		if child.NLink == 0 {
			// Delete child inode
			cmdChild, err := c.PrepareDelete(child.ID)
			if err != nil {
				return err
			}
			cmds = append(cmds, cmdChild)
		} else {
			// Update child inode
			cmdChild, err := c.PrepareUpdate(ctx, *child)
			if err != nil {
				return err
			}
			cmds = append(cmds, cmdChild)
		}

		return c.ApplyBatch(ctx, cmds)
	})
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

	return c.withConflictRetry(ctx, func() error {
		// 1. Update Target (Link Count)
		target, err := c.getInode(ctx, targetID)
		if err != nil {
			return fmt.Errorf("failed to get target for link: %w", err)
		}
		target.NLink++
		if target.Links == nil {
			target.Links = make(map[string]bool)
		}
		target.Links[parentID+":"+encName] = true
		cmdTarget, err := c.PrepareUpdate(ctx, *target)
		if err != nil {
			return err
		}

		// 2. Update Parent
		parent, err := c.getInode(ctx, parentID)
		if err != nil {
			return fmt.Errorf("failed to get parent for link: %w", err)
		}
		if parent.Children == nil {
			parent.Children = make(map[string]string)
		}
		parent.Children[encName] = targetID
		cmdParent, err := c.PrepareUpdate(ctx, *parent)
		if err != nil {
			return err
		}

		return c.ApplyBatch(ctx, []metadata.LogCommand{cmdTarget, cmdParent})
	})
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
			inode, err := c.getInode(ctx, existingID)
			if err != nil {
				return err
			}
			key, err := c.UnlockInode(ctx, inode)
			if err != nil {
				return err
			}
			var linkTag string
			for tag := range inode.Links {
				linkTag = tag
				break
			}
			parts := strings.SplitN(linkTag, ":", 2)
			pID, nHMAC := "", ""
			if len(parts) == 2 {
				pID, nHMAC = parts[0], parts[1]
			}
			return c.writeInodeContent(ctx, existingID, metadata.FileType, key, r, size, name, nil, inode.Mode, inode.GroupID, pID, nHMAC)
		}
		return fmt.Errorf("entry %s already exists and is not a file", name)
	}

	inode, key, err := c.AddEntry(ctx, parentInode.ID, parentKey, name, iType, r, size, symlinkTarget, mode, parentInode.GroupID, 0, 0)
	if err == nil {
		c.putPathCache("/"+path, pathCacheEntry{
			inodeID: inode.ID,
			key:     key,
			linkTag: parentInode.ID + ":" + encName,
		})
	}
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
