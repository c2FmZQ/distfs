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

var _ fs.FS = (*FS)(nil)
var _ fs.FSStatfser = (*FS)(nil)

// NewFS creates a new FUSE file system.
func NewFS(c *client.Client) *FS {
	return &FS{client: c}
}

func (f *FS) Poll(ctx context.Context, req *fuse.PollRequest, resp *fuse.PollResponse) error {
	return syscall.ENOSYS
}

func (f *FS) Statfs(ctx context.Context, req *fuse.StatfsRequest, resp *fuse.StatfsResponse) error {
	stats, err := f.client.GetClusterStats()
	if err != nil {
		return mapError(err)
	}

	// 1MB Block Size (matches chunk size)
	bsize := uint32(1024 * 1024)
	resp.Bsize = bsize
	resp.Blocks = uint64(stats.TotalCapacity) / uint64(bsize)

	freeBytes := stats.TotalCapacity - stats.TotalUsed
	if freeBytes < 0 {
		freeBytes = 0
	}
	resp.Bfree = uint64(freeBytes) / uint64(bsize)

	// Default to cluster free space
	resp.Bavail = resp.Bfree

	// Check User Quota
	user, err := f.client.GetUser(f.client.UserID())
	if err == nil && user.Quota.MaxBytes > 0 {
		quotaFree := user.Quota.MaxBytes - user.Usage.TotalBytes
		if quotaFree < 0 {
			quotaFree = 0
		}
		quotaBlocks := uint64(quotaFree) / uint64(bsize)
		if quotaBlocks < resp.Bavail {
			resp.Bavail = quotaBlocks
		}
	}

	// Inodes
	resp.Files = 1000000 // Soft limit from DISTFS.md
	if err == nil && user.Quota.MaxInodes > 0 {
		resp.Files = uint64(user.Quota.MaxInodes)
	}

	usedFiles := uint64(0)
	if err == nil {
		usedFiles = uint64(user.Usage.InodeCount)
	}

	if usedFiles > resp.Files {
		resp.Ffree = 0
	} else {
		resp.Ffree = resp.Files - usedFiles
	}

	return nil
}

func (f *FS) Root() (fs.Node, error) {
	// Return lazy root immediately. Real initialization happens on access.
	return &Dir{fs: f, isRoot: true}, nil
}

// Dir implements both fs.Node and fs.Handle for directories.
type Dir struct {
	fs         *FS
	inode      *metadata.Inode
	key        []byte
	mu         sync.Mutex
	lastUpdate time.Time
	isRoot     bool
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
var _ fs.NodeForgetter = (*Dir)(nil)
var _ fs.NodePoller = (*Dir)(nil)

func (h *Dir) Poll(ctx context.Context, req *fuse.PollRequest, resp *fuse.PollResponse) error {
	return syscall.ENOSYS
}

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.inode == nil {
		if !d.isRoot {
			return syscall.EIO
		}
		if err := d.fs.client.EnsureRoot(); err == nil {
			if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
				d.inode = inode
				d.key = key
			}
		}
		if d.inode == nil {
			a.Mode = os.ModeDir | 0000 // Unreachable
			a.Inode = 1                // Root hint
			return nil
		}
	}

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
	d.mu.Lock()

	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, syscall.EAGAIN
		}
	}

	// Freshness check: only refetch if older than 1s
	if time.Since(d.lastUpdate) > 1*time.Second {
		if updated, err := d.fs.client.GetInode(ctx, d.inode.ID); err == nil {
			d.inode = updated
			d.lastUpdate = time.Now()
		}
	}

	mac := hmac.New(sha256.New, d.key)
	mac.Write([]byte(name))
	encName := hex.EncodeToString(mac.Sum(nil))

	childID, ok := d.inode.Children[encName]
	d.mu.Unlock()

	if !ok {
		return nil, syscall.ENOENT
	}

	inode, err := d.fs.client.GetInode(ctx, childID)
	if err != nil {
		return nil, mapError(err)
	}

	key, err := d.fs.client.UnlockInode(inode)
	if err != nil {
		return nil, mapError(err)
	}

	if inode.Type == metadata.DirType {
		return &Dir{fs: d.fs, inode: inode, key: key}, nil
	}
	return &File{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	d.mu.Lock()

	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, syscall.EAGAIN
		}
	}

	// Refetch inode to see new children
	if updated, err := d.fs.client.GetInode(ctx, d.inode.ID); err == nil {
		d.inode = updated
	}
	var ids []string
	for _, id := range d.inode.Children {
		ids = append(ids, id)
	}
	d.mu.Unlock()

	if len(ids) == 0 {
		return nil, nil
	}

	inodes, err := d.fs.client.GetInodes(ctx, ids)
	if err != nil {
		return nil, mapError(err)
	}

	var dirents []fuse.Dirent
	for _, childInode := range inodes {
		childKey, err := d.fs.client.UnlockInode(childInode)
		if err != nil {
			continue
		}

		nameBytes, err := crypto.DecryptDEM(childKey, childInode.EncryptedName)
		if err != nil {
			continue
		}

		t := fuse.DT_File
		if childInode.Type == metadata.DirType {
			t = fuse.DT_Dir
		}
		dirents = append(dirents, fuse.Dirent{Name: string(nameBytes), Type: t})
	}
	return dirents, nil
}

func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fs.Node, fs.Handle, error) {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, nil, syscall.EIO
		}
	}
	id := d.inode.ID
	key := d.key
	groupID := d.inode.GroupID
	d.mu.Unlock()

	inode, key, err := d.fs.client.AddEntry(id, key, req.Name, metadata.FileType, nil, 0, "", uint32(req.Mode), groupID, req.Uid, req.Gid)
	if err != nil {
		return nil, nil, mapError(err)
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
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, syscall.EIO
		}
	}
	id := d.inode.ID
	key := d.key
	groupID := d.inode.GroupID
	d.mu.Unlock()

	inode, key, err := d.fs.client.AddEntry(id, key, req.Name, metadata.DirType, nil, 0, "", uint32(req.Mode), groupID, req.Uid, req.Gid)
	if err != nil {
		return nil, mapError(err)
	}
	return &Dir{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fs.Node) error {
	targetDir := newDir.(*Dir)

	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return syscall.EIO
		}
	}
	oldID := d.inode.ID
	oldKey := d.key
	d.mu.Unlock()

	targetDir.mu.Lock()
	if targetDir.inode == nil {
		if targetDir.isRoot {
			if err := targetDir.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := targetDir.fs.client.ResolvePath("/"); err == nil {
					targetDir.inode = inode
					targetDir.key = key
				}
			}
		}
		if targetDir.inode == nil {
			targetDir.mu.Unlock()
			return syscall.EIO
		}
	}
	newID := targetDir.inode.ID
	newKey := targetDir.key
	targetDir.mu.Unlock()

	err := d.fs.client.RenameRaw(oldID, oldKey, req.OldName, newID, newKey, req.NewName)
	if err != nil {
		return mapError(err)
	}
	return nil
}

func (d *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return syscall.EIO
		}
	}
	id := d.inode.ID
	key := d.key
	d.mu.Unlock()

	err := d.fs.client.RemoveEntryRaw(id, key, req.Name)
	if err != nil {
		return mapError(err)
	}
	return nil
}

func (d *Dir) Symlink(ctx context.Context, req *fuse.SymlinkRequest) (fs.Node, error) {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, syscall.EIO
		}
	}
	id := d.inode.ID
	key := d.key
	groupID := d.inode.GroupID
	d.mu.Unlock()

	inode, key, err := d.fs.client.AddEntry(id, key, req.NewName, metadata.SymlinkType, nil, 0, req.Target, 0777, groupID, req.Uid, req.Gid)
	if err != nil {
		return nil, mapError(err)
	}
	return &File{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return syscall.EIO
		}
	}
	inode := d.inode
	key := d.key
	d.mu.Unlock()

	return setAttr(d.fs.client, inode, key, req, &resp.Attr)
}

func (d *Dir) Link(ctx context.Context, req *fuse.LinkRequest, old fs.Node) (fs.Node, error) {
	oldFile := old.(*File)

	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if err := d.fs.client.EnsureRoot(); err == nil {
				if inode, key, err := d.fs.client.ResolvePath("/"); err == nil {
					d.inode = inode
					d.key = key
				}
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, syscall.EIO
		}
	}
	id := d.inode.ID
	key := d.key
	d.mu.Unlock()

	err := d.fs.client.LinkRaw(id, key, req.NewName, oldFile.inode.ID)
	if err != nil {
		return nil, mapError(err)
	}
	// Update target node's metadata to reflect new nlink
	if updated, err := d.fs.client.GetInode(ctx, oldFile.inode.ID); err == nil {
		oldFile.mu.Lock()
		*oldFile.inode = *updated
		oldFile.mu.Unlock()
	}
	return old, nil
}

func (d *Dir) Forget() {
}

// File implements both fs.Node and fs.Handle for files.
type File struct {
	fs      *FS
	inode   *metadata.Inode
	key     []byte
	mu      sync.Mutex
	handles []*FileHandle
}

var _ fs.Node = (*File)(nil)
var _ fs.NodeOpener = (*File)(nil)
var _ fs.NodeReadlinker = (*File)(nil)
var _ fs.NodeSetattrer = (*File)(nil)
var _ fs.NodeForgetter = (*File)(nil)
var _ fs.NodeFsyncer = (*File)(nil)
var _ fs.NodePoller = (*File)(nil)

func (f *File) Poll(ctx context.Context, req *fuse.PollRequest, resp *fuse.PollResponse) error {
	return syscall.ENOSYS
}

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Refetch to get current NLink/Size
	if updated, err := f.fs.client.GetInode(ctx, f.inode.ID); err == nil {
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
	return setAttr(f.fs.client, f.inode, f.key, req, &resp.Attr)
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
	if f.inode.Type == metadata.SymlinkType {
		return nil, syscall.ELOOP
	}
	reader, err := f.fs.client.NewReader(f.inode.ID, f.key)
	if err != nil {
		return nil, mapError(err)
	}
	h := &FileHandle{file: f, reader: reader}
	f.mu.Lock()
	f.handles = append(f.handles, h)
	f.mu.Unlock()
	return h, nil
}

func (f *File) Forget() {
}

func (f *File) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
	f.mu.Lock()
	handles := make([]*FileHandle, len(f.handles))
	copy(handles, f.handles)
	f.mu.Unlock()

	for _, h := range handles {
		if err := h.Fsync(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// FileHandle manages the state of an open file, including buffering writes to a temporary file.
type FileHandle struct {
	file   *File
	reader *client.FileReader
	mu     sync.Mutex
	pages  map[int64][]byte
	size   uint64
}

var _ fs.HandleReader = (*FileHandle)(nil)
var _ fs.HandleWriter = (*FileHandle)(nil)
var _ fs.HandleFlusher = (*FileHandle)(nil)
var _ fs.HandleReleaser = (*FileHandle)(nil)
var _ fs.HandlePoller = (*FileHandle)(nil)

func (h *FileHandle) Poll(ctx context.Context, req *fuse.PollRequest, resp *fuse.PollResponse) error {
	return syscall.ENOSYS
}

func (h *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	const chunkSize = 1024 * 1024
	totalSize := int64(h.size)
	if h.pages == nil {
		totalSize = int64(h.file.inode.Size)
	}

	readOffset := req.Offset
	readSize := req.Size
	if readOffset >= totalSize {
		return nil
	}
	if readOffset+int64(readSize) > totalSize {
		readSize = int(totalSize - readOffset)
	}

	data := make([]byte, readSize)
	bytesRead := 0

	for bytesRead < readSize {
		currentOff := readOffset + int64(bytesRead)
		pageIdx := currentOff / chunkSize
		pageOff := int(currentOff % chunkSize)

		toRead := readSize - bytesRead
		remainingInPage := int(chunkSize - pageOff)
		if toRead > remainingInPage {
			toRead = remainingInPage
		}

		if h.pages != nil {
			if page, ok := h.pages[pageIdx]; ok {
				if pageOff < len(page) {
					avail := copy(data[bytesRead:], page[pageOff:])
					if avail > toRead {
						avail = toRead
					}
				}
				bytesRead += toRead
				continue
			}
		}

		// Fetch from reader
		n, err := h.reader.ReadAt(data[bytesRead:bytesRead+toRead], currentOff)
		if err != nil && err != io.EOF {
			return mapError(err)
		}
		if n == 0 && err == io.EOF {
			break
		}
		bytesRead += n
		if n < toRead && err == io.EOF {
			break
		}
	}

	resp.Data = data[:bytesRead]
	return nil
}

func (h *FileHandle) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.pages == nil {
		h.pages = make(map[int64][]byte)
		h.size = h.file.inode.Size
	}

	const chunkSize = 1024 * 1024

	// Handle writes spanning multiple pages
	written := 0
	for written < len(req.Data) {
		offset := req.Offset + int64(written)
		pageIdx := offset / chunkSize
		pageOffset := int(offset % chunkSize)

		remainingInPage := int(chunkSize) - pageOffset
		toWrite := len(req.Data) - written
		if toWrite > remainingInPage {
			toWrite = remainingInPage
		}

		// Load Page
		page, ok := h.pages[pageIdx]
		if !ok {
			// Fetch from server if it exists
			if pageIdx < int64(len(h.file.inode.ChunkManifest)) {
				// Fetch
				data, err := h.file.fs.client.FetchChunk(ctx, h.file.inode.ID, h.file.key, pageIdx)
				if err != nil {
					return mapError(err)
				}
				page = data
			} else {
				// New Page (zeroed)
				page = make([]byte, 0, chunkSize)
			}
			h.pages[pageIdx] = page
		}

		// Ensure page is big enough (handling sparse/append)
		neededLen := pageOffset + toWrite
		if len(page) < neededLen {
			// Extend with zeros if gap
			if len(page) < pageOffset {
				padding := make([]byte, pageOffset-len(page))
				page = append(page, padding...)
			}
			// Extend for data
			extension := make([]byte, neededLen-len(page))
			page = append(page, extension...)
		}

		// Copy Data
		copy(page[pageOffset:], req.Data[written:written+toWrite])
		h.pages[pageIdx] = page

		written += toWrite
	}

	// Update Size
	newEnd := req.Offset + int64(len(req.Data))
	if uint64(newEnd) > h.size {
		h.size = uint64(newEnd)
	}

	resp.Size = len(req.Data)
	return nil
}

func (h *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.pages) > 0 {
		dirtyMap := make(map[int64]bool)
		for idx := range h.pages {
			dirtyMap[idx] = true
		}

		// Use FileHandle as ReaderAt
		// SyncFile uses this to read the modified chunks
		updated, err := h.file.fs.client.SyncFile(h.file.inode.ID, h, int64(h.size), dirtyMap)
		if err != nil {
			log.Printf("FUSE Flush sync failed: %v", err)
			return mapError(err)
		}

		// Update file metadata
		h.file.mu.Lock()
		h.file.inode = updated
		h.file.mu.Unlock()

		// Clear dirty pages after successful sync
		h.pages = make(map[int64][]byte)
		h.size = updated.Size
	}
	return nil
}

// ReadAt implements io.ReaderAt for SyncFile usage
func (h *FileHandle) ReadAt(p []byte, off int64) (n int, err error) {
	// SyncFile only calls this for dirty chunks, so they MUST be in h.pages
	const chunkSize = 1024 * 1024
	pageIdx := off / chunkSize

	page, ok := h.pages[pageIdx]
	if !ok {
		// Should not happen if logic is correct
		return 0, io.EOF
	}

	// Logic for copying from page
	// SyncFile asks for full chunk (or up to EOF)
	// 'off' passed to ReadAt is usually aligned to chunk start (from SyncFile)
	// But let's be generic

	pageOffset := int(off % chunkSize)
	if pageOffset >= len(page) {
		return 0, io.EOF
	}

	n = copy(p, page[pageOffset:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (h *FileHandle) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
	// Flush handles the sync logic now efficiently
	return h.Flush(ctx, &fuse.FlushRequest{})
}

func (h *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	h.mu.Lock()
	// Clear memory
	h.pages = nil
	h.mu.Unlock()

	if h.reader != nil {
		h.reader.Close()
	}

	h.file.mu.Lock()
	for i, fh := range h.file.handles {
		if fh == h {
			h.file.handles = append(h.file.handles[:i], h.file.handles[i+1:]...)
			break
		}
	}
	h.file.mu.Unlock()
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
		return mapError(err)
	}

	respAttr.Mode = os.FileMode(inode.Mode)
	if inode.Type == metadata.SymlinkType {
		respAttr.Mode |= os.ModeSymlink
	}
	respAttr.Size = inode.Size
	respAttr.Uid = inode.UID
	respAttr.Gid = inode.GID
	respAttr.Mtime = time.Unix(0, inode.MTime)
	respAttr.Ctime = time.Unix(0, inode.CTime)
	respAttr.Nlink = inode.NLink

	return nil
}
