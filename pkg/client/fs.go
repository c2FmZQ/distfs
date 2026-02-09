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
	"fmt"
	"io"
	"io/fs"
	"sort"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type DistFS struct {
	client *Client
}

func (c *Client) FS() *DistFS {
	return &DistFS{client: c}
}

func (d *DistFS) ReadDir(name string) ([]fs.DirEntry, error) {
	f, err := d.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rdf, ok := f.(fs.ReadDirFile)
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fmt.Errorf("not a directory")}
	}

	return rdf.ReadDir(-1)
}

func (d *DistFS) Open(name string) (fs.File, error) {
	inode, key, err := d.client.ResolvePath(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	if inode.Type == metadata.DirType {
		return &DistDir{
			client: d.client,
			inode:  inode,
			key:    key,
		}, nil
	}

	// It's a file
	reader, err := d.client.NewReader(inode.ID, key)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	return &DistFile{reader: reader}, nil
}

// DistFile implements fs.File
type DistFile struct {
	reader *FileReader
}

func (f *DistFile) Stat() (fs.FileInfo, error) {
	return &DistFileInfo{inode: f.reader.Stat()}, nil
}

func (f *DistFile) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *DistFile) Close() error {
	return nil
}

// DistDir implements fs.ReadDirFile
type DistDir struct {
	client *Client
	inode  *metadata.Inode
	key    []byte // The key for this directory (used to unlock children?) No, parent key is not used to unlock children directly.
	// But we need the client identity to unlock children's lockboxes.
	offset     int
	sortedKeys []string
}

func (d *DistDir) Stat() (fs.FileInfo, error) {
	return &DistFileInfo{inode: d.inode}, nil
}

func (d *DistDir) Read(p []byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.inode.ID, Err: fmt.Errorf("is a directory")}
}

func (d *DistDir) Close() error {
	return nil
}

func (d *DistDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.inode.Children == nil {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	// Cache sorted keys
	if d.sortedKeys == nil {
		keys := make([]string, 0, len(d.inode.Children))
		for k := range d.inode.Children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		d.sortedKeys = keys
	}

	if d.offset >= len(d.sortedKeys) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	remainingKeys := d.sortedKeys[d.offset:]
	if n > 0 && len(remainingKeys) > n {
		remainingKeys = remainingKeys[:n]
	}

	// Batch fetch
	var ids []string
	for _, encName := range remainingKeys {
		id := d.inode.Children[encName]
		ids = append(ids, id)
	}

	inodes, err := d.client.getInodes(ids)
	if err != nil {
		return nil, err
	}

	// Update offset only if successful
	d.offset += len(remainingKeys)

	var entries []fs.DirEntry
	for _, childInode := range inodes {
		// Unlock child
		var childName string
		childKey, err := childInode.Lockbox.GetFileKey(d.client.userID, d.client.decKey)
		if err == nil {
			// Decrypt name
			nameBytes, err := crypto.DecryptDEM(childKey, childInode.EncryptedName)
			if err == nil {
				childName = string(nameBytes)
			} else {
				childName = "decryption-failed-" + childInode.ID[:8]
			}
		} else {
			childName = "locked-" + childInode.ID[:8]
		}

		entries = append(entries, &DistDirEntry{
			inode: childInode,
			name:  childName,
		})
	}

	return entries, nil
}

type DistDirEntry struct {
	inode *metadata.Inode
	name  string
}

func (e *DistDirEntry) Name() string { return e.name }
func (e *DistDirEntry) IsDir() bool  { return e.inode.Type == metadata.DirType }
func (e *DistDirEntry) Type() fs.FileMode {
	if e.IsDir() {
		return fs.ModeDir | fs.FileMode(e.inode.Mode)
	}
	return fs.FileMode(e.inode.Mode)
}
func (e *DistDirEntry) Info() (fs.FileInfo, error) {
	return &DistFileInfo{inode: e.inode}, nil
}

type DistFileInfo struct {
	inode *metadata.Inode
}

func (i *DistFileInfo) Name() string       { return i.inode.ID } // Info().Name() is usually the base name, but here ID is safer if name is unknown.
func (i *DistFileInfo) Size() int64        { return int64(i.inode.Size) }
func (i *DistFileInfo) Mode() fs.FileMode  { return fs.FileMode(i.inode.Mode) }
func (i *DistFileInfo) ModTime() time.Time { return time.Now() }
func (i *DistFileInfo) IsDir() bool        { return i.inode.Type == metadata.DirType }
func (i *DistFileInfo) Sys() any           { return i.inode }
