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
	"path/filepath"
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
	inode, key, err := d.client.resolvePath(d.ctx, fullPath)
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
	reader, err := d.client.newReader(d.ctx, inode.ID, key)
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
	inode, _, err := d.client.resolvePath(d.ctx, fullPath)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return d.client.newFileInfo(inode, path.Base(name)), nil
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
	inode, _, err := d.client.resolvePathExtended(d.ctx, fullPath, false)
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
	client *Client
	reader *FileReader
}

func (f *DistFile) Stat() (fs.FileInfo, error) {
	return f.client.newFileInfo(f.reader.inode, f.reader.inode.ID), nil
}

func (f *DistFile) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *DistFile) ReadAt(p []byte, off int64) (int, error) {
	return f.reader.ReadAt(p, off)
}

func (f *DistFile) Close() error {
	return f.reader.Close()
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
	return d.client.newFileInfo(d.inode, d.inode.ID), nil
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
		ids = append(ids, d.inode.Children[encName].ID)
	}

	inodesSlice, err := d.client.getInodes(d.ctx, ids)
	if err != nil {
		return nil, err
	}
	inodesMap := make(map[string]*metadata.Inode)
	for _, i := range inodesSlice {
		inodesMap[i.ID] = i
	}

	// Update offset only if successful
	d.offset += len(remainingKeys)

	var entries []fs.DirEntry
	for _, encName := range remainingKeys {
		entry := d.inode.Children[encName]
		childInode, ok := inodesMap[entry.ID]
		if !ok {
			continue
		}

		childName, err := d.client.decryptEntryName(d.ctx, d.key, entry.EncryptedName, entry.Nonce)
		if err != nil {
			continue
		}

		entries = append(entries, d.client.newDirEntry(childInode, childName, entry.ID, nil))
	}

	return entries, nil
}

// DistDirEntry implements fs.DirEntry.
type DistDirEntry struct {
	client *Client
	info   InodeInfo
	name   string
	id     string
	key    []byte
}

func (e *DistDirEntry) Name() string { return e.name }
func (e *DistDirEntry) IsDir() bool {
	return e.info.IsDir()
}
func (e *DistDirEntry) Type() fs.FileMode {
	if e.IsDir() {
		return fs.ModeDir | fs.FileMode(e.info.Mode)
	}
	return fs.FileMode(e.info.Mode)
}
func (e *DistDirEntry) Info() (fs.FileInfo, error) {
	return &DistFileInfo{info: e.info, name: e.name}, nil
}

func (e *DistDirEntry) InodeID() string {
	return e.id
}
func (e *DistDirEntry) Mode() fs.FileMode {
	m := fs.FileMode(e.info.Mode)
	if e.IsDir() {
		m |= fs.ModeDir
	}
	return m
}
func (e *DistDirEntry) Size() int64 {
	return int64(e.info.Size)
}

func (e *DistDirEntry) ModTime() time.Time {
	return time.Unix(0, e.info.MTime)
}

// StatDirEntry returns a directory entry for the given path, following symlinks.
func (c *Client) StatDirEntry(ctx context.Context, path string) (*DistDirEntry, error) {
	inode, key, err := c.resolvePathExtended(ctx, path, true)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(strings.TrimRight(path, "/"))
	if name == "" || name == "." {
		name = "/"
	}
	return c.newDirEntry(inode, name, inode.ID, key), nil
}

// LstatDirEntry returns a directory entry for the given path, without following the final symlink.
func (c *Client) LstatDirEntry(ctx context.Context, path string) (*DistDirEntry, error) {
	inode, key, err := c.resolvePathExtended(ctx, path, false)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(strings.TrimRight(path, "/"))
	if name == "" || name == "." {
		name = "/"
	}
	return c.newDirEntry(inode, name, inode.ID, key), nil
}

func (c *Client) populateInodeInfo(i *metadata.Inode) InodeInfo {
	info := InodeInfo{
		ID:            i.ID,
		Type:          i.Type,
		Mode:          i.Mode,
		Size:          i.Size,
		OwnerID:       i.OwnerID,
		GroupID:       i.GroupID,
		NLink:         i.NLink,
		Version:       i.Version,
		MTime:         i.GetMTime(),
		SymlinkTarget: i.GetSymlinkTarget(),
		AccessACL:     fromInternalACL(i.AccessACL),
		DefaultACL:    fromInternalACL(i.DefaultACL),
	}
	if i.Lockbox != nil {
		info.Lockbox = make(map[string]struct {
			KEM []byte
			DEM []byte
		})
		for k, v := range i.Lockbox {
			info.Lockbox[k] = struct {
				KEM []byte
				DEM []byte
			}{
				KEM: v.KEMCiphertext,
				DEM: v.DEMCiphertext,
			}
		}
	}
	return info
}

func (c *Client) newFileInfo(i *metadata.Inode, name string) *DistFileInfo {
	return &DistFileInfo{
		info: c.populateInodeInfo(i),
		name: name,
	}
}

// DistFileInfo implements fs.FileInfo.
type DistFileInfo struct {
	info InodeInfo
	name string
}

func (i *DistFileInfo) Name() string       { return i.name }
func (i *DistFileInfo) Size() int64        { return int64(i.info.Size) }
func (i *DistFileInfo) Mode() fs.FileMode  { return fs.FileMode(i.info.Mode) }
func (i *DistFileInfo) ModTime() time.Time { return time.Unix(0, i.info.MTime) }
func (i *DistFileInfo) IsDir() bool        { return i.info.IsDir() }
func (i *DistFileInfo) Sys() any           { return &i.info }

// ReadDirExtended returns a list of directory entries with optional metadata.
func (c *Client) ReadDirExtended(ctx context.Context, path string, fetchMetadata bool) ([]*DistDirEntry, error) {
	inode, key, err := c.resolvePath(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.readDirExtended(ctx, inode, key, fetchMetadata)
}

// ReadDirPaginated returns a paginated list of directory entries and the total count.
func (c *Client) ReadDirPaginated(ctx context.Context, path string, offset, limit int) ([]*DistDirEntry, int, error) {
	inode, key, err := c.resolvePath(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	return c.readDirPaginated(ctx, inode, key, offset, limit)
}

func (c *Client) readDirPaginated(ctx context.Context, inode *metadata.Inode, key []byte, offset, limit int) ([]*DistDirEntry, int, error) {
	if inode.Type != metadata.DirType {
		return nil, 0, fmt.Errorf("not a directory")
	}

	total := len(inode.Children)
	if total == 0 {
		return nil, 0, nil
	}

	// Extract and sort keys for stable pagination
	keys := make([]string, 0, total)
	for k := range inode.Children {
		keys = append(keys, k)
	}
	// Sort by encrypted name hash for stable deterministic order
	// Real alphabetical sort requires decrypting all names, which is too slow for large dirs.
	// Optimization: If directory is massive, we should cache this sorted list or use a server-side iterator.
	sort.Strings(keys)

	end := offset + limit
	if limit < 0 || end > total {
		end = total
	}

	if offset >= total {
		return nil, total, nil
	}

	var entries []*DistDirEntry
	for _, k := range keys[offset:end] {
		entry := inode.Children[k]
		childName, err := c.decryptEntryName(ctx, key, entry.EncryptedName, entry.Nonce)
		if err != nil {
			continue
		}

		entries = append(entries, &DistDirEntry{
			client: c,
			info:   InodeInfo{ID: entry.ID},
			id:     entry.ID,
			name:   childName,
		})
	}

	// Sort the returned page alphabetically by decrypted name for better UX on small pages
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})

	return entries, total, nil
}

func (c *Client) readDirExtended(ctx context.Context, inode *metadata.Inode, key []byte, fetchMetadata bool) ([]*DistDirEntry, error) {
	if inode.Type != metadata.DirType {
		return nil, fmt.Errorf("not a directory")
	}

	if len(inode.Children) == 0 {
		return nil, nil
	}

	var inodesMap map[string]*metadata.Inode
	if fetchMetadata {
		ids := make([]string, 0, len(inode.Children))
		for _, entry := range inode.Children {
			ids = append(ids, entry.ID)
		}

		inodesSlice, err := c.getInodes(ctx, ids)
		if err != nil {
			return nil, err
		}
		inodesMap = make(map[string]*metadata.Inode)
		for _, i := range inodesSlice {
			inodesMap[i.ID] = i
		}
	}

	var entries []*DistDirEntry
	for _, entry := range inode.Children {
		var childInode *metadata.Inode
		if fetchMetadata {
			var ok bool
			childInode, ok = inodesMap[entry.ID]
			if !ok {
				continue
			}
		}

		childName, err := c.decryptEntryName(ctx, key, entry.EncryptedName, entry.Nonce)
		if err != nil {
			continue
		}

		var childKey []byte
		if childInode != nil {
			c.keyMu.RLock()
			meta, ok := c.keyCache[childInode.ID]
			c.keyMu.RUnlock()

			if ok {
				childKey = meta.key
			} else {
				childKey = childInode.GetFileKey()
			}
		}

		entries = append(entries, c.newDirEntry(childInode, childName, entry.ID, childKey))
	}

	return entries, nil
}

// ReadDirRecursive returns all entries in the directory tree starting at path.
func (c *Client) ReadDirRecursive(ctx context.Context, path string) (map[string][]*DistDirEntry, error) {
	inode, key, err := c.resolvePath(ctx, path)
	if err != nil {
		return nil, err
	}

	results := make(map[string][]*DistDirEntry)
	var walk func(string, string, []byte) error
	walk = func(p string, currID string, currKey []byte) error {
		currInode, err := c.getInode(ctx, currID)
		if err != nil {
			return err
		}
		entries, err := c.readDirExtended(ctx, currInode, currKey, true)
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
				if err := walk(childPath, e.id, e.key); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(path, inode.ID, key); err != nil {
		return nil, err
	}
	return results, nil
}

// newDirEntry creates a new DistDirEntry from an Inode and name.
func (c *Client) newDirEntry(i *metadata.Inode, name string, inodeID string, key []byte) *DistDirEntry {
	res := &DistDirEntry{
		client: c,
		name:   name,
		id:     inodeID,
		key:    key,
	}
	if i != nil {
		res.info = c.populateInodeInfo(i)
	} else {
		res.info = InodeInfo{ID: inodeID}
	}
	return res
}

// NewDirEntryForTest is used for testing purposes to create a DistDirEntry.
func NewDirEntryForTest(i *metadata.Inode, name string, key []byte) *DistDirEntry {
	return &DistDirEntry{
		info: InodeInfo{
			ID:            i.ID,
			Type:          i.Type,
			Mode:          i.Mode,
			Size:          i.Size,
			OwnerID:       i.OwnerID,
			GroupID:       i.GroupID,
			Version:       i.Version,
			MTime:         i.GetMTime(),
			SymlinkTarget: i.GetSymlinkTarget(),
			AccessACL:     fromInternalACL(i.AccessACL),
			DefaultACL:    fromInternalACL(i.DefaultACL),
		},
		name: name,
		id:   i.ID,
		key:  key,
	}
}
