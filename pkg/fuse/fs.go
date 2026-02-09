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
	"sync"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type FS struct {
	client *client.Client
}

func NewFS(c *client.Client) *FS {
	return &FS{client: c}
}

func (f *FS) Root() (fs.Node, error) {
	if err := f.client.EnsureRoot(); err != nil {
		return nil, err
	}
	inode, key, err := f.client.ResolvePath("/")
	if err != nil {
		return nil, err
	}
	return &Dir{fs: f, inode: inode, key: key}, nil
}

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

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	a.Mode = os.ModeDir | 0755
	a.Size = uint64(len(d.inode.Children))
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
	inode, key, err := d.fs.client.AddEntry(d.inode.ID, d.key, req.Name, metadata.FileType, nil)
	if err != nil {
		log.Printf("FUSE Create failed: %v", err)
		return nil, nil, syscall.EIO
	}
	f := &File{fs: d.fs, inode: inode, key: key}
	h, err := f.Open(ctx, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	resp.Attr.Mode = 0644
	resp.Attr.Size = inode.Size
	return f, h, nil
}

func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {
	log.Printf("FUSE Mkdir: %s", req.Name)
	inode, key, err := d.fs.client.AddEntry(d.inode.ID, d.key, req.Name, metadata.DirType, nil)
	if err != nil {
		log.Printf("FUSE Mkdir failed: %v", err)
		return nil, syscall.EIO
	}
	return &Dir{fs: d.fs, inode: inode, key: key}, nil
}

type File struct {
	fs    *FS
	inode *metadata.Inode
	key   []byte
}

var _ fs.Node = (*File)(nil)
var _ fs.NodeOpener = (*File)(nil)

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = 0644
	a.Size = f.inode.Size
	return nil
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
	reader, err := f.fs.client.NewReader(f.inode.ID, f.key)
	if err != nil {
		return nil, syscall.EIO
	}
	return &FileHandle{file: f, reader: reader}, nil
}

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
		data, err := h.file.fs.client.ReadFile(h.file.inode.ID, h.file.key)
		if err != nil {
			f.Close()
			os.Remove(f.Name())
			return syscall.EIO
		}
		if _, err := f.Write(data); err != nil {
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
		data := make([]byte, info.Size())
		if _, err := h.tmp.ReadAt(data, 0); err != nil {
			return syscall.EIO
		}

		_, err = h.file.fs.client.WriteFile(h.file.inode.ID, data)
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
