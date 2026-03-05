// Copyright 2026 TTBT Enterprises LLC
package fuse

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/client"
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
	fsys := &FS{client: c}
	// Configure lease expiration callback to notify VFS
	c = c.WithLeaseExpiredCallback(func(id string, err error) {
		log.Printf("DEBUG FUSE: Lease expired for %s: %v", id, err)
		// We don't have easy access to the fuse.Server or mountpoint here to call Invalidate,
		// but distfs-fuse is mostly stateless anyway.
		// The main benefit is that the client will refetch on next access.
	})
	fsys.client = c
	return fsys
}

func (f *FS) Poll(ctx context.Context, req *fuse.PollRequest, resp *fuse.PollResponse) error {
	return syscall.ENOSYS
}

func (f *FS) Statfs(ctx context.Context, req *fuse.StatfsRequest, resp *fuse.StatfsResponse) error {
	stats, err := f.client.GetClusterStats(ctx)
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
	user, err := f.client.GetUser(ctx, f.client.UserID())
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
		if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
			d.inode = inode
			d.key = key
		}
		if d.inode == nil {
			a.Mode = os.ModeDir | 0000 // Unreachable
			a.Inode = 1                // Root hint
			return nil
		}
	}

	a.Inode = inodeToUint64(d.inode.ID)
	a.Mode = os.ModeDir | os.FileMode(d.inode.Mode)
	a.Size = uint64(len(d.inode.Children))
	a.Uid = d.inode.GetUID()
	a.Gid = d.inode.GetGID()
	a.Ctime = time.Unix(0, d.inode.CTime)
	a.Mtime = time.Unix(0, d.inode.GetMTime())
	return nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	d.mu.Lock()

	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, syscall.EAGAIN
		}
	}

	// Freshness check: only refetch if older than 100ms
	forceRefresh := d.lastUpdate.IsZero()
	since := time.Since(d.lastUpdate)
	if forceRefresh || since > 100*time.Millisecond {
		id := d.inode.ID
		d.mu.Unlock() // Release lock for network call

		// Retry refresh a few times if it's a forced refresh (just after mutation)
		maxAttempts := 1
		if forceRefresh {
			maxAttempts = 3
		}

		var updated *metadata.Inode
		var err error
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(50 * time.Millisecond)
			}
			updated, err = d.fs.client.GetInode(ctx, id)
			if err == nil {
				break
			}
		}

		d.mu.Lock() // Re-acquire
		if err == nil {
			d.inode = updated
			d.lastUpdate = time.Now()
		} else if forceRefresh {
			d.mu.Unlock()
			return nil, mapError(err)
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

	key, err := d.fs.client.UnlockInode(ctx, inode)
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
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
			}
		}
		if d.inode == nil {
			d.mu.Unlock()
			return nil, syscall.EAGAIN
		}
	}

	// Refetch inode to see new children
	id := d.inode.ID
	d.mu.Unlock()
	updated, err := d.fs.client.GetInode(ctx, id)
	d.mu.Lock()
	if err == nil {
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
		name := childInode.GetName()
		if name == "" {
			continue
		}

		t := fuse.DT_File
		if childInode.Type == metadata.DirType {
			t = fuse.DT_Dir
		}
		dirents = append(dirents, fuse.Dirent{Name: name, Type: t})
	}
	return dirents, nil
}

func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fs.Node, fs.Handle, error) {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
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

	inode, key, err := d.fs.client.AddEntry(ctx, id, key, req.Name, metadata.FileType, nil, 0, "", uint32(req.Mode), groupID, req.Uid, req.Gid)
	if err != nil {
		if errors.Is(err, metadata.ErrExists) && inode != nil {
			// Created concurrently, open existing
			f := &File{fs: d.fs, inode: inode, key: key}
			h, openErr := f.Open(ctx, nil, nil)
			if openErr != nil {
				return nil, nil, openErr
			}
			return f, h, nil
		}
		return nil, nil, mapError(err)
	}
	d.mu.Lock()
	d.lastUpdate = time.Time{} // Invalidate cache
	d.mu.Unlock()
	f := &File{fs: d.fs, inode: inode, key: key}
	h, err := f.Open(ctx, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	resp.Attr.Mode = os.FileMode(inode.Mode)
	resp.Attr.Size = inode.Size
	resp.EntryValid = 100 * time.Millisecond
	return f, h, nil
}

func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
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

	inode, key, err := d.fs.client.AddEntry(ctx, id, key, req.Name, metadata.DirType, nil, 0, "", uint32(req.Mode), groupID, req.Uid, req.Gid)
	if err != nil {
		return nil, mapError(err)
	}
	d.mu.Lock()
	d.lastUpdate = time.Time{} // Invalidate cache
	d.mu.Unlock()
	return &Dir{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fs.Node) error {
	targetDir := newDir.(*Dir)

	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
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
			if inode, key, err := targetDir.fs.client.ResolvePath(ctx, "/"); err == nil {
				targetDir.inode = inode
				targetDir.key = key
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

	err := d.fs.client.RenameRaw(ctx, oldID, oldKey, req.OldName, newID, newKey, req.NewName)
	if err != nil {
		return mapError(err)
	}
	d.mu.Lock()
	d.lastUpdate = time.Time{}
	d.mu.Unlock()
	targetDir.mu.Lock()
	targetDir.lastUpdate = time.Time{}
	targetDir.mu.Unlock()
	return nil
}

func (d *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
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

	err := d.fs.client.RemoveEntryRaw(ctx, id, key, req.Name)
	if err != nil {
		log.Printf("DEBUG FUSE: Remove(%s) in dir %s failed: %v", req.Name, id, err)
		return mapError(err)
	}
	d.mu.Lock()
	d.lastUpdate = time.Time{}
	d.mu.Unlock()
	return nil
}

func (d *Dir) Symlink(ctx context.Context, req *fuse.SymlinkRequest) (fs.Node, error) {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
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

	inode, key, err := d.fs.client.AddEntry(ctx, id, key, req.NewName, metadata.SymlinkType, nil, 0, req.Target, 0777, groupID, req.Uid, req.Gid)
	if err != nil {
		return nil, mapError(err)
	}
	d.mu.Lock()
	d.lastUpdate = time.Time{}
	d.mu.Unlock()
	return &File{fs: d.fs, inode: inode, key: key}, nil
}

func (d *Dir) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
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

	updated, err := setAttr(ctx, d.fs.client, inode, key, req, &resp.Attr)
	if err == nil {
		d.mu.Lock()
		d.inode = updated
		d.mu.Unlock()
	}
	return err
}

func (d *Dir) Link(ctx context.Context, req *fuse.LinkRequest, old fs.Node) (fs.Node, error) {
	oldFile := old.(*File)

	d.mu.Lock()
	if d.inode == nil {
		if d.isRoot {
			if inode, key, err := d.fs.client.ResolvePath(ctx, "/"); err == nil {
				d.inode = inode
				d.key = key
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

	err := d.fs.client.LinkRaw(ctx, id, key, req.NewName, oldFile.inode.ID)
	if err != nil {
		return nil, mapError(err)
	}
	d.mu.Lock()
	d.lastUpdate = time.Time{}
	d.mu.Unlock()
	// Update target node's metadata to reflect new nlink
	if updated, err := d.fs.client.GetInode(ctx, oldFile.inode.ID); err == nil {
		oldFile.mu.Lock()
		oldFile.inode = updated
		oldFile.mu.Unlock()
	}
	return old, nil
}

func (d *Dir) Forget() {
	// In a more complex implementation, we would prune local caches here.
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
		f.inode = updated
	}

	a.Inode = inodeToUint64(f.inode.ID)
	a.Mode = os.FileMode(f.inode.Mode)
	if f.inode.Type == metadata.SymlinkType {
		a.Mode |= os.ModeSymlink
	}
	a.Size = f.inode.Size
	a.Uid = f.inode.GetUID()
	a.Gid = f.inode.GetGID()
	a.Ctime = time.Unix(0, f.inode.CTime)
	a.Mtime = time.Unix(0, f.inode.GetMTime())
	return nil
}

func (f *File) Readlink(ctx context.Context, req *fuse.ReadlinkRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inode.Type != metadata.SymlinkType {
		return "", syscall.EINVAL
	}
	return f.inode.GetSymlinkTarget(), nil
}

func (f *File) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	log.Printf("DEBUG FUSE: Setattr(id=%s valid=%v size=%v)", f.inode.ID, req.Valid, req.Size)
	f.mu.Lock()
	inode := f.inode
	key := f.key
	f.mu.Unlock()

	updated, err := setAttr(ctx, f.fs.client, inode, key, req, &resp.Attr)
	if err == nil {
		f.mu.Lock()
		f.inode = updated
		f.mu.Unlock()
	}
	return err
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
	if f.inode.Type == metadata.SymlinkType {
		return nil, syscall.ELOOP
	}
	reader, err := f.fs.client.NewReader(ctx, f.inode.ID, f.key)
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

// FileHandle manages the state of an open file, including buffering writes.
type FileHandle struct {
	file            *File
	reader          *client.FileReader
	mu              sync.Mutex
	pages           map[int64][]byte
	stagingManifest map[int64]metadata.ChunkEntry // index -> entry
	size            uint64
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

	// Sync reader with node's latest metadata (Phase 39: POSIX read-after-write)
	h.file.mu.Lock()
	if h.file.inode.Unlinked {
		if updated, err := h.file.fs.client.GetInode(ctx, h.file.inode.ID); err == nil {
			h.file.inode = updated
		}
	}
	inodeID := h.file.inode.ID
	fileKey := h.file.key
	currentInodeSize := h.file.inode.Size
	h.reader.SetInode(h.file.inode)
	h.file.mu.Unlock()

	const chunkSize = 1024 * 1024
	totalSize := int64(h.size)
	if h.pages == nil {
		totalSize = int64(currentInodeSize)
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
					bytesRead += avail
				}
				continue
			}
		}

		if h.stagingManifest != nil {
			if entry, ok := h.stagingManifest[pageIdx]; ok {
				// Evicted but uncommitted chunk
				page, err := h.file.fs.client.DownloadChunkData(ctx, inodeID, entry.ID, entry.URLs, fileKey, uint64(pageIdx))
				if err != nil {
					return mapError(err)
				}
				if pageOff < len(page) {
					avail := copy(data[bytesRead:], page[pageOff:])
					if avail > toRead {
						avail = toRead
					}
					bytesRead += avail
				}
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
		h.file.mu.Lock()
		h.size = h.file.inode.Size
		h.file.mu.Unlock()
	}
	if h.stagingManifest == nil {
		h.stagingManifest = make(map[int64]metadata.ChunkEntry)
	}

	// Ensure we have the latest size (may have been truncated via Setattr on the File)
	h.file.mu.Lock()
	inodeID := h.file.inode.ID
	fileKey := h.file.key
	if h.file.inode.Size < h.size {
		h.size = h.file.inode.Size
	}
	h.file.mu.Unlock()

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
			// Check staging first (evicted page)
			if entry, staged := h.stagingManifest[pageIdx]; staged {
				// Fetch back for modification (Read-Modify-Write)
				data, err := h.file.fs.client.DownloadChunkData(ctx, inodeID, entry.ID, entry.URLs, fileKey, uint64(pageIdx))
				if err != nil {
					return mapError(err)
				}
				page = data
			} else if pageIdx < int64(len(h.file.inode.ChunkManifest)) {
				// Fetch from server if it exists committed
				data, err := h.file.fs.client.FetchChunk(ctx, inodeID, fileKey, pageIdx)
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

		// Incremental Flush: If page is full, upload and evict
		if len(page) == chunkSize {
			bgCtx := context.Background()
			entry, err := h.file.fs.client.UploadChunkData(bgCtx, h.file.inode.ID, h.file.key, uint64(pageIdx), page)
			if err != nil {
				log.Printf("Incremental upload failed: %v", err)
				return mapError(err)
			}
			h.stagingManifest[pageIdx] = entry
			// Only evict if it's still the SAME data we uploaded
			if p, exists := h.pages[pageIdx]; exists && len(p) == chunkSize {
				delete(h.pages, pageIdx) // Evict
			}
		}

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

	if h.pages == nil && len(h.stagingManifest) == 0 {
		return nil
	}

	// 1. Upload remaining dirty pages
	// Collect indices first to avoid concurrent map access panic when unlocking
	var indices []int64
	for idx := range h.pages {
		indices = append(indices, idx)
	}

	h.file.mu.Lock()
	inodeID := h.file.inode.ID
	fileKey := h.file.key
	h.file.mu.Unlock()

	bgCtx := context.Background()
	for _, idx := range indices {
		page, ok := h.pages[idx]
		if !ok {
			continue
		}
		entry, err := h.file.fs.client.UploadChunkData(bgCtx, inodeID, fileKey, uint64(idx), page)
		if err != nil {
			log.Printf("FUSE Flush upload failed (idx=%d): %v", idx, err)
			return mapError(err)
		}
		if h.stagingManifest == nil {
			h.stagingManifest = make(map[int64]metadata.ChunkEntry)
		}
		h.stagingManifest[idx] = entry
		// Remove from pages only if it hasn't been modified/re-added
		if p, exists := h.pages[idx]; exists && len(p) == len(page) {
			delete(h.pages, idx)
		}
	}

	// 2. Commit Manifest if there are changes
	if len(h.stagingManifest) > 0 {
		commitSize := h.size
		staging := h.stagingManifest
		h.stagingManifest = make(map[int64]metadata.ChunkEntry) // Clear staging early, we'll restore on failure

		updated, err := h.file.fs.client.UpdateInode(bgCtx, inodeID, func(i *metadata.Inode) error {
			// Determine new length
			maxIdx := int64(len(i.ChunkManifest)) - 1
			for idx := range staging {
				if idx > maxIdx {
					maxIdx = idx
				}
			}

			// Grow manifest if needed
			if maxIdx >= int64(len(i.ChunkManifest)) {
				newManifest := make([]metadata.ChunkEntry, maxIdx+1)
				copy(newManifest, i.ChunkManifest)
				i.ChunkManifest = newManifest
			}

			// Apply updates from staging
			for idx, entry := range staging {
				i.ChunkManifest[idx] = entry
			}

			// Update size if it grew
			if i.Size < commitSize {
				i.Size = commitSize
			}
			i.SetInlineData(nil)
			return nil
		})

		if err != nil {
			log.Printf("FUSE Flush commit failed: %v", err)
			// Restore staging on failure
			for k, v := range staging {
				h.stagingManifest[k] = v
			}
			return mapError(err)
		}

		// Update file metadata
		h.file.mu.Lock()
		h.file.inode = updated
		h.file.mu.Unlock()

		// If size hasn't changed concurrently, sync it
		if h.size == commitSize {
			h.size = updated.Size
		}
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

func setAttr(ctx context.Context, c *client.Client, inode *metadata.Inode, inodeKey []byte, req *fuse.SetattrRequest, respAttr *fuse.Attr) (*metadata.Inode, error) {
	var mode *uint32
	if req.Valid.Mode() {
		m := uint32(req.Mode)
		mode = &m
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

	updated, err := c.SetAttrByID(ctx, inode, inodeKey, metadata.SetAttrRequest{
		InodeID: inode.ID,
		Mode:    mode,
		Size:    size,
		MTime:   mtime,
	})
	if err != nil {
		log.Printf("FUSE Setattr failed: %v", err)
		return nil, mapError(err)
	}

	respAttr.Mode = os.FileMode(updated.Mode)
	if updated.Type == metadata.SymlinkType {
		respAttr.Mode |= os.ModeSymlink
	}
	respAttr.Size = updated.Size
	respAttr.Ctime = time.Unix(0, updated.CTime)
	respAttr.Mtime = time.Unix(0, updated.GetMTime())

	return updated, nil
}

func inodeToUint64(id string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(id))
	return h.Sum64()
}
