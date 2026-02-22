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
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

var _ fs.FS = (*DistFS)(nil)
var _ fs.ReadDirFS = (*DistFS)(nil)
var _ fs.ReadFileFS = (*DistFS)(nil)
var _ fs.GlobFS = (*DistFS)(nil)
var _ fs.StatFS = (*DistFS)(nil)
var _ fs.SubFS = (*DistFS)(nil)

// fs.ReadLinkFS is defined in Go 1.23+. We implement the method to satisfy it if available.
// If the compiler is older, this check would fail if we uncommented it, so we leave it implicitly satisfied.
// var _ fs.ReadLinkFS = (*DistFS)(nil)

// DistFS implements fs.FS and extended interfaces.
type DistFS struct {
	client   *Client
	ctx      context.Context
	basePath string
}

// FS returns an fs.FS compatible wrapper around the client.
func (c *Client) FS(ctx context.Context) *DistFS {
	return &DistFS{client: c, ctx: ctx, basePath: "/"}
}

// Open implements fs.FS.
func (d *DistFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	fullPath := path.Join(d.basePath, name)
	inode, key, err := d.client.ResolvePath(d.ctx, fullPath)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	if inode.Type == metadata.DirType {
		return &DistDir{
			client: d.client,
			ctx:    d.ctx,
			inode:  inode,
			key:    key,
		}, nil
	}

	// It's a file
	reader, err := d.client.NewReader(d.ctx, inode.ID, key)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	return &DistFile{reader: reader}, nil
}

// ReadDir implements fs.ReadDirFS.
func (d *DistFS) ReadDir(name string) ([]fs.DirEntry, error) {
	// Open handles validation and path joining
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

// ReadFile implements fs.ReadFileFS.
func (d *DistFS) ReadFile(name string) ([]byte, error) {
	f, err := d.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

// Glob implements fs.GlobFS.
func (d *DistFS) Glob(pattern string) ([]string, error) {
	// Check pattern validity
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}
	// Use standard fs.Glob implementation which falls back to ReadDir
	// We wrap d in a struct that hides the Glob method to prevent infinite recursion
	return fs.Glob(&noGlobFS{dfs: d}, pattern)
}

// Stat implements fs.StatFS.
func (d *DistFS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	fullPath := path.Join(d.basePath, name)
	inode, _, err := d.client.ResolvePath(d.ctx, fullPath)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return &DistFileInfo{inode: inode, name: path.Base(name)}, nil
}

// Sub implements fs.SubFS.
func (d *DistFS) Sub(dir string) (fs.FS, error) {
	if !fs.ValidPath(dir) {
		return nil, &fs.PathError{Op: "sub", Path: dir, Err: fs.ErrInvalid}
	}
	return &DistFS{
		client:   d.client,
		ctx:      d.ctx,
		basePath: path.Join(d.basePath, dir),
	}, nil
}

// ReadLink implements fs.ReadLinkFS (if available in stdlib).
func (d *DistFS) ReadLink(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	fullPath := path.Join(d.basePath, name)
	inode, _, err := d.client.ResolvePath(d.ctx, fullPath)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	if inode.Type != metadata.SymlinkType {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fmt.Errorf("not a symlink")}
	}
	return inode.GetSymlinkTarget(), nil
}

// noGlobFS wraps DistFS but hides the Glob method to allow fs.Glob fallback.
type noGlobFS struct {
	dfs *DistFS
}

func (f *noGlobFS) Open(name string) (fs.File, error) {
	return f.dfs.Open(name)
}

func (f *noGlobFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return f.dfs.ReadDir(name)
}

// DistFile implements fs.File
type DistFile struct {
	reader *FileReader
}

func (f *DistFile) Stat() (fs.FileInfo, error) {
	return &DistFileInfo{inode: f.reader.Stat(), name: f.reader.inode.ID}, nil
}

func (f *DistFile) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *DistFile) Close() error {
	return nil
}

// DistDir implements fs.ReadDirFile
type DistDir struct {
	client     *Client
	ctx        context.Context
	inode      *metadata.Inode
	key        []byte // The symmetric key for this directory.
	offset     int
	sortedKeys []string
}

func (d *DistDir) Stat() (fs.FileInfo, error) {
	return &DistFileInfo{inode: d.inode, name: d.inode.ID}, nil
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

	inodes, err := d.client.getInodes(d.ctx, ids)
	if err != nil {
		return nil, err
	}

	// Update offset only if successful
	d.offset += len(remainingKeys)

	var entries []fs.DirEntry
	for _, childInode := range inodes {
		// Name is already decrypted and verified by getInodes -> VerifyInode
		childName := childInode.GetName()
		if childName == "" {
			childName = "unnamed-" + childInode.ID[:8]
		}

		entries = append(entries, &DistDirEntry{
			inode: childInode,
			name:  childName,
		})
	}

	return entries, nil
}

// DistDirEntry implements fs.DirEntry.
type DistDirEntry struct {
	inode *metadata.Inode
	name  string
	key   []byte
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
	return &DistFileInfo{inode: e.inode, name: e.name}, nil
}

func (e *DistDirEntry) Inode() *metadata.Inode { return e.inode }

func (e *DistDirEntry) InodeID() string { return e.inode.ID }
func (e *DistDirEntry) Mode() fs.FileMode {
	m := fs.FileMode(e.inode.Mode)
	if e.IsDir() {
		m |= fs.ModeDir
	}
	return m
}
func (e *DistDirEntry) Size() int64 { return int64(e.inode.Size) }

func (e *DistDirEntry) ModTime() time.Time { return time.Unix(0, e.inode.GetMTime()) }

// DistFileInfo implements fs.FileInfo.
type DistFileInfo struct {
	inode *metadata.Inode
	name  string
}

func (i *DistFileInfo) Name() string       { return i.name }
func (i *DistFileInfo) Size() int64        { return int64(i.inode.Size) }
func (i *DistFileInfo) Mode() fs.FileMode  { return fs.FileMode(i.inode.Mode) }
func (i *DistFileInfo) ModTime() time.Time { return time.Unix(0, i.inode.GetMTime()) }
func (i *DistFileInfo) IsDir() bool        { return i.inode.Type == metadata.DirType }
func (i *DistFileInfo) Sys() any           { return i.inode }

// ReadDirExtended returns a list of directory entries with full metadata.
func (c *Client) ReadDirExtended(ctx context.Context, path string) ([]*DistDirEntry, error) {
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.readDirExtended(ctx, inode, key)
}

func (c *Client) readDirExtended(ctx context.Context, inode *metadata.Inode, key []byte) ([]*DistDirEntry, error) {
	if inode.Type != metadata.DirType {
		return nil, fmt.Errorf("not a directory")
	}

	if len(inode.Children) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(inode.Children))
	for _, id := range inode.Children {
		ids = append(ids, id)
	}

	inodes, err := c.getInodes(ctx, ids)
	if err != nil {
		return nil, err
	}

	var entries []*DistDirEntry
	for _, childInode := range inodes {
		childName := childInode.GetName()
		if childName == "" {
			childName = "unnamed-" + childInode.ID[:8]
		}

		c.keyMu.RLock()
		meta, ok := c.keyCache[childInode.ID]
		c.keyMu.RUnlock()

		var childKey []byte
		if ok {
			childKey = meta.key
		} else {
			childKey = childInode.GetFileKey()
		}

		entries = append(entries, &DistDirEntry{
			inode: childInode,
			name:  childName,
			key:   childKey,
		})
	}

	return entries, nil
}

// ReadDirRecursive returns all entries in the directory tree starting at path.
func (c *Client) ReadDirRecursive(ctx context.Context, path string) (map[string][]*DistDirEntry, error) {
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		return nil, err
	}

	results := make(map[string][]*DistDirEntry)
	var walk func(string, *metadata.Inode, []byte) error
	walk = func(p string, currInode *metadata.Inode, currKey []byte) error {
		entries, err := c.readDirExtended(ctx, currInode, currKey)
		if err != nil {
			return err
		}
		results[p] = entries
		for _, e := range entries {
			if e.IsDir() {
				childPath := p
				if !strings.HasSuffix(childPath, "/") {
					childPath += "/"
				}
				childPath += e.Name()
				if err := walk(childPath, e.inode, e.key); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(path, inode, key); err != nil {
		return nil, err
	}
	return results, nil
}

// NewDirEntry creates a new DistDirEntry from an Inode and name.
func (c *Client) NewDirEntry(inode *metadata.Inode, name string, key []byte) *DistDirEntry {
	return &DistDirEntry{inode: inode, name: name, key: key}
}

// DecryptName decrypts the name of an Inode using the client's identity.
func (c *Client) DecryptName(ctx context.Context, inode *metadata.Inode) (string, []byte, error) {
	if err := c.VerifyInode(ctx, inode); err != nil {
		return "", nil, err
	}
	return inode.GetName(), inode.GetFileKey(), nil
}

// NewDirEntryForTest is used for testing purposes to create a DistDirEntry.
func NewDirEntryForTest(inode *metadata.Inode, name string, key []byte) *DistDirEntry {
	return &DistDirEntry{inode: inode, name: name, key: key}
}
