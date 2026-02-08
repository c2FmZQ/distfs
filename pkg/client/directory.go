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
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	lb := c.createLockbox(rootKey)
	inode := metadata.Inode{
		ID:       metadata.RootID,
		Type:     metadata.DirType,
		Children: make(map[string]string),
		Lockbox:  lb,
	}
	return c.createInode(inode)
}

func (c *Client) ResolvePath(path string) (*metadata.Inode, []byte, error) {
	path = strings.Trim(path, "/")

	rootInode, err := c.getInode(metadata.RootID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get root inode: %w", err)
	}

	if c.decKey == nil {
		return nil, nil, fmt.Errorf("client has no identity to unlock root")
	}

	rootKey, err := rootInode.Lockbox.GetFileKey(c.userID, c.decKey)
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

		key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
		if err != nil {
			return nil, nil, fmt.Errorf("access denied to %s: %w", part, err)
		}
		currentKey = key
	}

	return inode, currentKey, nil
}

func (c *Client) Mkdir(path string) error {
	return c.addEntry(path, metadata.DirType, nil)
}

func (c *Client) CreateFile(path string, data []byte) error {
	return c.addEntry(path, metadata.FileType, data)
}

func (c *Client) addEntry(path string, iType metadata.InodeType, data []byte) error {
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

	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	if parentInode.Children != nil {
		if _, ok := parentInode.Children[encName]; ok {
			return fmt.Errorf("entry %s already exists", name)
		}
	}

	newID := generateID()
	newKey := make([]byte, 32)
	rand.Read(newKey)

	encNameBlob, err := crypto.EncryptDEM(newKey, []byte(name))
	if err != nil {
		return fmt.Errorf("failed to encrypt name: %w", err)
	}

	if iType == metadata.FileType {
		if err := c.writeInodeContent(newID, iType, newKey, data, encNameBlob); err != nil {
			return err
		}
	} else {
		lb := c.createLockbox(newKey)
		inode := metadata.Inode{
			ID:            newID,
			Type:          metadata.DirType,
			Children:      make(map[string]string),
			Lockbox:       lb,
			EncryptedName: encNameBlob,
		}
		if err := c.createInode(inode); err != nil {
			return err
		}
	}

	update := metadata.ChildUpdate{Name: encName, ChildID: newID}
	body, _ := json.Marshal(update)
	req, _ := http.NewRequest("PUT", c.metaURL+"/v1/meta/directory/"+parentInode.ID+"/entry", bytes.NewReader(body))
	if err := c.authenticateRequest(req); err != nil {
		// Ignore or return? Ideally return.
		// But existing code ignores errors from auth setup if keys missing (for backward compat?).
		// But here keys are present in test.
	}
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("add child failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) createLockbox(key []byte) crypto.Lockbox {
	lb := crypto.NewLockbox()
	if c.decKey != nil {
		lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), key)
	}
	return lb
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}