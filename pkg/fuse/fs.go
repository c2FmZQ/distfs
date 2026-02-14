// Copyright 2026 TTBT Enterprises LLC
package fuse

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// FS implements the fuse.FS interface for DistFS.
type FS struct {
	client *client.Client
}

// NewFS creates a new FUSE file system.
func NewFS(c *client.Client) *FS {
	return &FS{client: c}
}

func (f *FS) Root() (fs.Node, error) {
	var err error
	var inode *metadata.Inode
	var key []byte

	// Retry root resolution to handle Raft propagation delays after registration
	for i := 0; i < 30; i++ {
		if err = f.client.EnsureRoot(); err == nil {
			inode, key, err = f.client.ResolvePath("/")
			if err == nil {
				return &Dir{fs: f, inode: inode, key: key}, nil
			}
		}
		log.Printf("FUSE Root initialization failed (attempt %d/30): %v", i+1, err)
		time.Sleep(1 * time.Second)
	}

	return nil, err
}

// Dir implements both fs.Node and fs.Handle for directories.
type Dir struct {
	fs    *FS
	inode *metadata.Inode
	key   []byte
	mu    sync.Mutex
}

var _ fs.Node = (*Dir)(nil)
var _ fs.HandleReadDirAller = (*Dir)(nil)
var _ fs.NodeStringLookuper = (*Dir)(nil)
var _ fs.NodeCreater = (*Dir)(nil)
var _ fs.NodeMkdirer = (*Dir)(nil)
var _ fs.NodeRenamer = (*Dir)(nil)
var _ fs.NodeRemover = (*Dir)(nil)
var _ fs.NodeSymlinker = (*Dir)(nil)
var _ fs.NodeSetattrer = (*Dir)(nil)
var _ fs.NodeLinker = (*Dir)(nil)

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	a.Mode = os.ModeDir | os.FileMode(d.inode.Mode)
	a.Size = uint64(len(d.inode.Children))
	a.Uid = d.inode.UID
	a.Gid = d.inode.GID
	a.Mtime = time.Unix(0, d.inode.MTime)
	a.Ctime = time.Unix(0, d.inode.CTime)
	a.Nlink = d.inode.NLink
	return nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	log.Printf("FUSE Lookup: %s", name)
	d.mu.Lock()
	// Refetch inode to see new children
	if updated, err := d.fs.client.GetInode(d.inode.ID); err == nil {
		d.inode = updated
	}

	mac := hmac.New(sha256.New, d.key)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	childID, ok := d.inode.Children[encName]
	d.mu.Unlock()

	if !ok {
		return nil, syscall.ENOENT
	}

	inode, err := d.fs.client.GetInode(childID)
	if err != nil {
		return nil, syscall.EIO
	}

	key, err := d.fs.client.UnlockInode(inode)
	if err != nil {
		return nil, syscall.EACCES
	}

	if inode.Type == metadata.DirType {
		return &Dir{fs: d.fs, inode: inode, key: key}, nil
	}
	return &File{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	d.mu.Lock()
	log.Printf("FUSE ReadDirAll for %s", d.inode.ID)
	// Refetch inode to see new children
	if updated, err := d.fs.client.GetInode(d.inode.ID); err == nil {
		d.inode = updated
	}
	childMap := make(map[string]string)
	var ids []string
	for encName, id := range d.inode.Children {
		childMap[id] = encName
		ids = append(ids, id)
	}
	d.mu.Unlock()

	log.Printf("FUSE ReadDirAll fetching %d children metadata", len(ids))
	if len(ids) == 0 {
		return nil, nil
	}

	inodes, err := d.fs.client.GetInodes(ids)
	if err != nil {
		log.Printf("FUSE ReadDirAll: batch fetch failed: %v", err)
		return nil, syscall.EIO
	}

	var dirents []fuse.Dirent
	for _, childInode := range inodes {
		childKey, err := d.fs.client.UnlockInode(childInode)
		if err != nil {
			log.Printf("FUSE ReadDirAll: failed to unlock child %s: %v", childInode.ID, err)
			continue
		}

		nameBytes, err := crypto.DecryptDEM(childKey, childInode.EncryptedName)
		if err != nil {
			log.Printf("FUSE ReadDirAll: failed to decrypt name for child %s: %v", childInode.ID, err)
			continue
		}

		t := fuse.DT_File
		if childInode.Type == metadata.DirType {
			t = fuse.DT_Dir
		}
		log.Printf("FUSE ReadDirAll: adding entry %s (%s)", string(nameBytes), childInode.ID)
		dirents = append(dirents, fuse.Dirent{Name: string(nameBytes), Type: t})
	}
	return dirents, nil
}

func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fs.Node, fs.Handle, error) {
	log.Printf("FUSE Create: %s", req.Name)
	inode, key, err := d.fs.client.AddEntry(d.inode.ID, d.key, req.Name, metadata.FileType, nil, 0, "", uint32(req.Mode), d.inode.GroupID)
	if err != nil {
		log.Printf("FUSE Create failed: %v", err)
		return nil, nil, syscall.EIO
	}
	f := &File{fs: d.fs, inode: inode, key: key}
	h, err := f.Open(ctx, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	resp.Attr.Mode = os.FileMode(inode.Mode)
	resp.Attr.Size = inode.Size
	return f, h, nil
}

func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {
	log.Printf("FUSE Mkdir: %s", req.Name)
	inode, key, err := d.fs.client.AddEntry(d.inode.ID, d.key, req.Name, metadata.DirType, nil, 0, "", uint32(req.Mode), d.inode.GroupID)
	if err != nil {
		log.Printf("FUSE Mkdir failed: %v", err)
		return nil, syscall.EIO
	}
	return &Dir{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fs.Node) error {
	log.Printf("FUSE Rename: %s -> %s", req.OldName, req.NewName)
	targetDir := newDir.(*Dir)
	err := d.fs.client.RenameRaw(d.inode.ID, d.key, req.OldName, targetDir.inode.ID, targetDir.key, req.NewName)
	if err != nil {
		log.Printf("FUSE Rename failed: %v", err)
		return syscall.EIO
	}
	return nil
}

func (d *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	log.Printf("FUSE Remove: %s", req.Name)
	err := d.fs.client.RemoveEntryRaw(d.inode.ID, d.key, req.Name)
	if err != nil {
		log.Printf("FUSE Remove failed: %v", err)
		if strings.Contains(err.Error(), "directory not empty") {
			return syscall.ENOTEMPTY
		}
		return syscall.EIO
	}
	return nil
}

func (d *Dir) Symlink(ctx context.Context, req *fuse.SymlinkRequest) (fs.Node, error) {
	log.Printf("FUSE Symlink: %s -> %s", req.NewName, req.Target)
	inode, key, err := d.fs.client.AddEntry(d.inode.ID, d.key, req.NewName, metadata.SymlinkType, nil, 0, req.Target, 0777, d.inode.GroupID)
	if err != nil {
		log.Printf("FUSE Symlink failed: %v", err)
		return nil, syscall.EIO
	}
	return &File{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	log.Printf("FUSE Setattr Dir: %s", d.inode.ID)
	return setAttr(d.fs.client, d.inode, d.key, req, &resp.Attr)
}

func (d *Dir) Link(ctx context.Context, req *fuse.LinkRequest, old fs.Node) (fs.Node, error) {
	log.Printf("FUSE Link: %s -> %s", req.NewName, old.(*File).inode.ID)
	oldFile := old.(*File)
	err := d.fs.client.LinkRaw(d.inode.ID, d.key, req.NewName, oldFile.inode.ID)
	if err != nil {
		log.Printf("FUSE Link failed: %v", err)
		return nil, syscall.EIO
	}
	// Update target node's metadata to reflect new nlink
	if updated, err := d.fs.client.GetInode(oldFile.inode.ID); err == nil {
		oldFile.mu.Lock()
		*oldFile.inode = *updated
		oldFile.mu.Unlock()
	}
	return old, nil
}

// File implements both fs.Node and fs.Handle for files.
type File struct {
	fs    *FS
	inode *metadata.Inode
	key   []byte
	mu    sync.Mutex
}

var _ fs.Node = (*File)(nil)
var _ fs.NodeOpener = (*File)(nil)
var _ fs.NodeReadlinker = (*File)(nil)
var _ fs.NodeSetattrer = (*File)(nil)

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Refetch to get current NLink/Size
	if updated, err := f.fs.client.GetInode(f.inode.ID); err == nil {
		*f.inode = *updated
	}

	a.Mode = os.FileMode(f.inode.Mode)
	if f.inode.Type == metadata.SymlinkType {
		a.Mode |= os.ModeSymlink
	}
	a.Size = f.inode.Size
	a.Uid = f.inode.UID
	a.Gid = f.inode.GID
	a.Mtime = time.Unix(0, f.inode.MTime)
	a.Ctime = time.Unix(0, f.inode.CTime)
	a.Nlink = f.inode.NLink
	return nil
}

func (f *File) Readlink(ctx context.Context, req *fuse.ReadlinkRequest) (string, error) {
	return f.inode.SymlinkTarget, nil
}

func (f *File) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	log.Printf("FUSE Setattr File: %s", f.inode.ID)
	return setAttr(f.fs.client, f.inode, f.key, req, &resp.Attr)
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
	if f.inode.Type == metadata.SymlinkType {
		return nil, syscall.ELOOP
	}
	reader, err := f.fs.client.NewReader(f.inode.ID, f.key)
	if err != nil {
		return nil, syscall.EIO
	}
	return &FileHandle{file: f, reader: reader}, nil
}

// FileHandle manages the state of an open file, including buffering writes to a temporary file.
type FileHandle struct {
	file   *File
	reader *client.FileReader
	mu     sync.Mutex
	tmp    *os.File
	dirty  bool
}

var _ fs.HandleReader = (*FileHandle)(nil)
var _ fs.HandleWriter = (*FileHandle)(nil)
var _ fs.HandleFlusher = (*FileHandle)(nil)
var _ fs.HandleReleaser = (*FileHandle)(nil)

func (h *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.dirty {
		data := make([]byte, req.Size)
		n, err := h.tmp.ReadAt(data, req.Offset)
		if err != nil && err != io.EOF {
			return syscall.EIO
		}
		resp.Data = data[:n]
		return nil
	}

	data := make([]byte, req.Size)
	n, err := h.reader.ReadAt(data, req.Offset)
	if err != nil && err != io.EOF {
		return syscall.EIO
	}
	resp.Data = data[:n]
	return nil
}

func (h *FileHandle) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	log.Printf("FUSE Write: %s offset=%d size=%d", h.file.inode.ID, req.Offset, len(req.Data))
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.dirty {
		f, err := os.CreateTemp("", "distfs-write-*")
		if err != nil {
			return syscall.EIO
		}
		rc, err := h.file.fs.client.ReadFile(h.file.inode.ID, h.file.key)
		if err != nil {
			f.Close()
			os.Remove(f.Name())
			return syscall.EIO
		}
		defer rc.Close()
		if _, err := io.Copy(f, rc); err != nil {
			f.Close()
			os.Remove(f.Name())
			return syscall.EIO
		}
		h.tmp = f
		h.dirty = true
	}

	if _, err := h.tmp.WriteAt(req.Data, req.Offset); err != nil {
		return syscall.EIO
	}
	resp.Size = len(req.Data)
	return nil
}

func (h *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.dirty {
		log.Printf("FUSE Flush: committing %s", h.file.inode.ID)
		info, err := h.tmp.Stat()
		if err != nil {
			return syscall.EIO
		}

		if _, err := h.tmp.Seek(0, io.SeekStart); err != nil {
			return syscall.EIO
		}

		_, err = h.file.fs.client.WriteFile(h.file.inode.ID, h.tmp, info.Size(), uint32(h.file.inode.Mode))
		if err != nil {
			log.Printf("FUSE Flush commit failed: %v", err)
			return syscall.EIO
		}
		h.dirty = false
		h.file.inode.Size = uint64(info.Size())
	}
	return nil
}

func (h *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tmp != nil {
		h.tmp.Close()
		os.Remove(h.tmp.Name())
		h.tmp = nil
	}
	return nil
}

func setAttr(c *client.Client, inode *metadata.Inode, inodeKey []byte, req *fuse.SetattrRequest, respAttr *fuse.Attr) error {
	var mode *uint32
	if req.Valid.Mode() {
		m := uint32(req.Mode)
		mode = &m
	}
	var uid *uint32
	if req.Valid.Uid() {
		uid = &req.Uid
	}
	var gid *uint32
	if req.Valid.Gid() {
		gid = &req.Gid
	}
	var size *uint64
	if req.Valid.Size() {
		size = &req.Size
	}
	var mtime *int64
	if req.Valid.Mtime() {
		mt := req.Mtime.UnixNano()
		mtime = &mt
	}

	err := c.SetAttrByID(inode, inodeKey, metadata.SetAttrRequest{
		InodeID: inode.ID,
		Mode:    mode,
		UID:     uid,
		GID:     gid,
		Size:    size,
		MTime:   mtime,
	})
	if err != nil {
		log.Printf("FUSE Setattr failed: %v", err)
		return syscall.EIO
	}

	// Update local cache
	if updated, err := c.GetInode(inode.ID); err == nil {
		*inode = *updated
	}
	return nil
}
