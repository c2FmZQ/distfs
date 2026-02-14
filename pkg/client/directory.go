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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type DirectoryEntry struct {
	Name string             `json:"name"`
	ID   string             `json:"id"`
	Type metadata.InodeType `json:"type"`
}

func (c *Client) EnsureRoot() error {
	_, err := c.getInode(metadata.RootID)
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

	lb := c.createLockbox(rootKey, 0755, "")
	inode := metadata.Inode{
		ID:       metadata.RootID,
		Type:     metadata.DirType,
		Children: make(map[string]string),
		Lockbox:  lb,
		OwnerID:  c.userID,
	}
	_, err = c.createInode(inode)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusConflict {
			return nil
		}
	}
	return err
}

func (c *Client) ResolvePath(path string) (*metadata.Inode, []byte, error) {
	path = strings.Trim(path, "/")

	rootInode, err := c.getInode(metadata.RootID)
	if err != nil {
		if err := c.EnsureRoot(); err != nil {
			return nil, nil, fmt.Errorf("failed to ensure root inode: %w", err)
		}
		rootInode, err = c.getInode(metadata.RootID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get root inode after creation: %w", err)
		}
	}

	if c.decKey == nil {
		return nil, nil, fmt.Errorf("client has no identity to unlock root")
	}

	rootKey, err := c.UnlockInode(rootInode)
	if err != nil {
		return nil, nil, fmt.Errorf("access denied to root: %w", err)
	}

	if path == "" {
		return rootInode, rootKey, nil
	}

	parts := strings.Split(path, "/")
	currentKey := rootKey
	var inode *metadata.Inode = rootInode

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}

		mac := hmac.New(sha256.New, currentKey)
		mac.Write([]byte(part))
		encName := hex.EncodeToString(mac.Sum(nil))

		childID, ok := inode.Children[encName]
		if !ok {
			return nil, nil, fmt.Errorf("entry %s not found", part)
		}

		inode, err = c.getInode(childID)
		if err != nil {
			return nil, nil, err
		}

		key, err := c.UnlockInode(inode)
		if err != nil {
			return nil, nil, fmt.Errorf("access denied to %s: %w", part, err)
		}
		currentKey = key
	}

	return inode, currentKey, nil
}

func (c *Client) Mkdir(path string) error {
	return c.addEntry(path, metadata.DirType, nil, 0, "", 0700)
}

func (c *Client) CreateFile(path string, r io.Reader, size int64) error {
	return c.addEntry(path, metadata.FileType, r, size, "", 0600)
}

func (c *Client) Symlink(target, path string) error {
	return c.addEntry(path, metadata.SymlinkType, nil, 0, target, 0777)
}

func (c *Client) AddEntry(parentID string, parentKey []byte, name string, iType metadata.InodeType, r io.Reader, size int64, symlinkTarget string, mode uint32, groupID string) (*metadata.Inode, []byte, error) {
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
		// Create empty inode first? No, writeInodeContent handles creation if not found.
		// BUT we need to pass Mode to writeInodeContent.
		if err := c.writeInodeContent(newID, iType, newKey, r, size, encNameBlob, mode, groupID); err != nil {
			return nil, nil, err
		}
		newInode, err = c.GetInode(newID)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Try to see if it already exists (unlikely for newID, but for completeness)
		lb := c.createLockbox(newKey, mode, groupID)
		inode := metadata.Inode{
			ID:            newID,
			Type:          iType,
			Mode:          mode,
			UID:           0, // TODO: set from client info
			GID:           0,
			Children:      make(map[string]string),
			Lockbox:       lb,
			EncryptedName: encNameBlob,
			OwnerID:       c.userID,
			GroupID:       groupID,
			SymlinkTarget: symlinkTarget,
		}
		newInode, err = c.createInode(inode)
		if err != nil {
			return nil, nil, err
		}
	}

	update := metadata.ChildUpdate{Name: encName, ChildID: newID}
	data, _ := json.Marshal(update)
	req, _ := http.NewRequest("PUT", c.metaURL+"/v1/meta/directory/"+parentID+"/entry", nil)
	if err := c.authenticateRequest(req); err != nil {
		return nil, nil, fmt.Errorf("auth failed: %w", err)
	}
	if err := c.sealBody(req, data); err != nil {
		return nil, nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("add child failed: %d %s", resp.StatusCode, string(b))
	}
	return newInode, newKey, nil
}

func (c *Client) Rename(oldPath, newPath string) error {
	oldDir, oldName := filepath.Split(strings.TrimRight(oldPath, "/"))
	newDir, newName := filepath.Split(strings.TrimRight(newPath, "/"))

	oldParent, oldParentKey, err := c.ResolvePath(oldDir)
	if err != nil {
		return fmt.Errorf("resolve old parent: %w", err)
	}
	newParent, newParentKey, err := c.ResolvePath(newDir)
	if err != nil {
		return fmt.Errorf("resolve new parent: %w", err)
	}

	return c.RenameRaw(oldParent.ID, oldParentKey, oldName, newParent.ID, newParentKey, newName)
}

func (c *Client) RenameRaw(oldParentID string, oldParentKey []byte, oldName string, newParentID string, newParentKey []byte, newName string) error {
	macOld := hmac.New(sha256.New, oldParentKey)
	macOld.Write([]byte(oldName))
	encOldName := hex.EncodeToString(macOld.Sum(nil))

	macNew := hmac.New(sha256.New, newParentKey)
	macNew.Write([]byte(newName))
	encNewName := hex.EncodeToString(macNew.Sum(nil))

	req := metadata.RenameRequest{
		OldParentID: oldParentID,
		OldName:     encOldName,
		NewParentID: newParentID,
		NewName:     encNewName,
	}
	data, _ := json.Marshal(req)

	hReq, err := http.NewRequest("POST", c.metaURL+"/v1/meta/rename", nil)
	if err != nil {
		return err
	}
	if err := c.authenticateRequest(hReq); err != nil {
		return err
	}
	if err := c.sealBody(hReq, data); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rename failed: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) RemoveEntry(path string) error {
	dir, name := filepath.Split(strings.TrimRight(path, "/"))
	parent, parentKey, err := c.ResolvePath(dir)
	if err != nil {
		return err
	}
	return c.RemoveEntryRaw(parent.ID, parentKey, name)
}

func (c *Client) RemoveEntryRaw(parentID string, parentKey []byte, name string) error {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	update := metadata.ChildUpdate{ParentID: parentID, Name: encName}
	data, _ := json.Marshal(update)

	req, err := http.NewRequest("DELETE", c.metaURL+"/v1/meta/directory/"+parentID+"/entry", nil)
	if err != nil {
		return err
	}
	if err := c.authenticateRequest(req); err != nil {
		return err
	}
	if err := c.sealBody(req, data); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove entry failed: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) Link(targetPath, linkPath string) error {
	target, _, err := c.ResolvePath(targetPath)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}

	dir, name := filepath.Split(strings.TrimRight(linkPath, "/"))
	parent, parentKey, err := c.ResolvePath(dir)
	if err != nil {
		return fmt.Errorf("resolve parent: %w", err)
	}

	return c.LinkRaw(parent.ID, parentKey, name, target.ID)
}

func (c *Client) LinkRaw(parentID string, parentKey []byte, name string, targetID string) error {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	req := metadata.LinkRequest{
		ParentID: parentID,
		Name:     encName,
		TargetID: targetID,
	}
	data, _ := json.Marshal(req)

	hReq, err := http.NewRequest("POST", c.metaURL+"/v1/meta/link", nil)
	if err != nil {
		return err
	}
	if err := c.authenticateRequest(hReq); err != nil {
		return err
	}
	if err := c.sealBody(hReq, data); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("link failed: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) addEntry(path string, iType metadata.InodeType, r io.Reader, size int64, symlinkTarget string, mode uint32) error {
	path = strings.Trim(path, "/")
	if path == "" {
		return fmt.Errorf("cannot create root")
	}

	dir, name := filepath.Split(path)

	parentInode, parentKey, err := c.ResolvePath(dir)
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
			inode, err := c.GetInode(existingID)
			if err != nil {
				return err
			}
			key, err := c.UnlockInode(inode)
			if err != nil {
				return err
			}
			return c.writeInodeContent(existingID, metadata.FileType, key, r, size, nil, inode.Mode, inode.GroupID)
		}
		return fmt.Errorf("entry %s already exists and is not a file", name)
	}

	_, _, err = c.AddEntry(parentInode.ID, parentKey, name, iType, r, size, symlinkTarget, mode, parentInode.GroupID)
	return err
}

func (c *Client) createLockbox(key []byte, mode uint32, groupID string) crypto.Lockbox {
	lb := crypto.NewLockbox()
	if c.decKey != nil {
		lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), key)
	}
	if (mode & 0004) != 0 {
		wpk, err := c.GetWorldPublicKey()
		if err == nil {
			lb.AddRecipient(metadata.WorldID, wpk, key)
		}
	}
	if groupID != "" && (mode&0060) != 0 {
		group, err := c.GetGroup(groupID)
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
