# DistFS Client API Documentation (v1)

This document describes the exported API of the `pkg/client` and `pkg/fuse` packages.

---

## 1. Lifecycle and Identity

### 1.1 Client Construction
- `NewClient(serverAddr string) *Client`: Creates a base client pointing to a metadata server.
- `(c *Client) WithIdentity(userID string, key *mlkem.DecapsulationKey768) *Client`: Configures user identity and encryption keys.
- `(c *Client) WithSignKey(key *crypto.IdentityKey) *Client`: Configures user signing keys.
- `(c *Client) WithServerKey(key *mlkem.EncapsulationKey768) *Client`: Manually configures the cluster encryption public key.
- `(c *Client) WithRootAnchor(id, owner string, pk, ek []byte, version uint64) *Client`: Configures the initial trust anchor for the root directory.
- `(c *Client) WithRootID(id string) *Client`: Sets a specific Inode ID as the logical root (chroot).
- `(c *Client) WithAdmin(admin bool) *Client`: Enables administrative bypass mode (requires server-side admin privileges).
- `(c *Client) WithLeaseExpiredCallback(fn func(id string, err error)) *Client`: Sets a callback to be invoked when a lease expires or its renewal fails.

### 1.2 Authentication & Session
- `(c *Client) Login(ctx context.Context) error`: Performs challenge-response authentication.
- `(c *Client) UserID() string`: Returns the configured User ID.
- `(c *Client) GetRootAnchor() (id, owner string, pk, ek []byte, version uint64)`: Returns the current root anchoring metadata.

### 1.3 Onboarding Utilities
- `PerformUnifiedOnboarding(ctx context.Context, opts OnboardingOptions) error`: High-level flow for registering new accounts or pulling existing ones.
- `GetOIDCToken(ctx context.Context, opts OnboardingOptions) (string, error)`: Helper to retrieve an OIDC token via device flow.

---

## 2. Atomic Operation Interface (High-Level)

These operations provide strongest consistency and multi-file atomicity.

### 2.1 Atomic Batch Writes
- `(c *Client) OpenBlobWrite(ctx context.Context, path string) (io.WriteCloser, error)`: Opens a writer that buffers data and performs an atomic metadata swap on `Close()`.
- `(c *Client) SaveDataFile(ctx context.Context, name string, data any) error`: Serializes `data` to JSON and performs an atomic write to `name`.
- `(c *Client) SaveDataFiles(ctx context.Context, names []string, data []any) error`: Atomically writes multiple files in a single metadata transaction.

### 2.2 Consistent Batch Reads
- `(c *Client) OpenBlobRead(ctx context.Context, path string) (io.ReadCloser, error)`: Opens a reader for streaming data.
- `(c *Client) ReadDataFile(ctx context.Context, name string, data any) error`: Reads and deserializes JSON data from a file.
- `(c *Client) ReadDataFiles(ctx context.Context, names []string, targets []any) error`: Reads multiple files using shared leases to ensure they reflect a single point-in-time snapshot.

### 2.3 Transactional Updates
- `(c *Client) OpenManyForUpdate(ctx context.Context, names []string, data []any) (func(bool), error)`:
    - Acquires **Exclusive Leases** on all paths.
    - Reads all files into `data`.
    - Returns a callback: `commit(true)` to save and release, `commit(false)` to abort and release.

---

## 3. Streaming I/O (Chunked)

For large files, use the streaming interfaces to avoid loading the entire file into memory.

### 3.1 FileReader
- `(c *Client) NewReader(ctx context.Context, id string, fileKey []byte) (*FileReader, error)`: Creates a reader with background prefetching.
- `(r *FileReader) Read(p []byte) (int, error)`
- `(r *FileReader) ReadAt(p []byte, off int64) (int, error)`
- `(r *FileReader) Close() error`: Releases leases and stops prefetching.

### 3.2 FileWriter
- `(c *Client) OpenBlobWrite(ctx context.Context, path string) (io.WriteCloser, error)`
- `(w *FileWriter) Write(p []byte) (int, error)`
- `(w *FileWriter) Close() error`: Commits all chunks and performs the atomic metadata swap.
- `(w *FileWriter) Abort()`: Discards all written data and releases leases without committing.

---

## 4. POSIX-like Interface

These methods provide standard filesystem operations mimicking Go standard library patterns (`io/fs` and `os`). They are generally synchronous and perform path resolution internally.

### 4.1 Standard Operations
- `(c *Client) Open(ctx context.Context, path string, flag int, perm fs.FileMode) (*DistFile, error)`
- `(c *Client) Stat(ctx context.Context, path string) (*DistFileInfo, error)`
- `(c *Client) Lstat(ctx context.Context, path string) (*DistFileInfo, error)`
- `(c *Client) ReadDir(ctx context.Context, path string) ([]*DistDirEntry, error)`
- `(c *Client) Mkdir(ctx context.Context, path string, perm fs.FileMode) error`
- `(c *Client) Remove(ctx context.Context, path string) error`
- `(c *Client) Rename(ctx context.Context, oldPath, newPath string) error`
- `(c *Client) Chmod(ctx context.Context, path string, mode fs.FileMode) error`
- `(c *Client) Chown(ctx context.Context, path string, ownerID, groupID string) error`
- `(c *Client) Symlink(ctx context.Context, target, linkPath string) error`
- `(c *Client) Link(ctx context.Context, targetPath, linkPath string) error`

### 4.2 POSIX Semantics and Guarantees

DistFS provides a subset of POSIX semantics optimized for a distributed, end-to-end encrypted environment.

#### 4.2.1 Consistency and Visibility
- **Metadata Consistency:** All metadata operations (Rename, Mkdir, etc.) are **Linearizable** and strongly consistent across the cluster via Raft.
- **Write Visibility:**
    - Read-after-write is supported within a single `Client` instance (including its FUSE mount) for convenience.
    - However, persistent readback from the server and visibility to other clients is **ONLY guaranteed** after a successful `Close()`, `Sync()`, or `Flush()`.
- **Atomic Swap:** File writes do not modify existing Inodes in-place. Instead, a new Inode is created and swapped into the parent directory atomically upon `Close()`.

#### 4.2.2 Atomicity
- **Renames:** Cross-directory renames are atomic and safe from partial failures.
- **Unlinks:** Removing a file is atomic. If the file has active links, the data is preserved until the last link is removed (`NLink == 0`).

#### 4.2.3 Links
- **Hard Links:** Supported for files. Hard links to directories are forbidden.
- **Symbolic Links:** Fully supported. Path resolution handles absolute and relative symlinks.

---

## 5. Standard Library Interface (`io/fs`)

DistFS implements the standard Go `io/fs` interfaces, allowing it to be used with any library that expects an `fs.FS`.

- `(c *Client) FS(ctx context.Context) *DistFS`: Returns an `fs.FS` implementation rooted at the client's current root.

---

## 6. Metadata and Coordination

### 6.1 Inode Operations
- `(c *Client) Stat(ctx context.Context, path string) (*DistFileInfo, error)`: High-level path resolution returning safe `InodeInfo`.
- `(c *Client) Lstat(ctx context.Context, path string) (*DistFileInfo, error)`: Stat without following terminal symlinks.
- `(c *Client) ReadDir(ctx context.Context, path string) ([]*DistDirEntry, error)`: Returns directory entries.
- *(Note: Raw `metadata.Inode` and `UpdateInode` methods are now unexported to encapsulate internal cryptographic state. Use high-level filesystem methods like `Chmod`, `Setfacl`, and `Rename` for mutations.)*

### 6.2 Distributed Leases

Leases are the primary mechanism for coordination in DistFS. They are managed by the Metadata Raft cluster and provide strong consistency guarantees.

#### 6.2.1 Scope: Inode vs. Path
Leases can be acquired on two types of identifiers:
1.  **Inode ID**: Freezes the metadata and data of a specific object. Prevents concurrent `UpdateInode` operations from other sessions.
2.  **Path Name**: Freezes path resolution. Prevents the path from being renamed or unlinked, ensuring it always resolves to the same Inode for the duration of the lease.

#### 6.2.2 Lifecycle
- `(c *Client) AcquireLeases(ctx context.Context, ids []string, duration time.Duration, opts LeaseOptions) error`
- `(c *Client) ReleaseLeases(ctx context.Context, ids []string, nonce string) error`

---

## 7. Security and Group Management

DistFS uses groups for shared access. All encryption is end-to-end; the server never sees group keys.

### 7.1 Group Operations
- `(c *Client) CreateGroup(ctx context.Context, name string, quotaEnabled bool) (*GroupInfo, error)`
- `(c *Client) CreateGroupWithOptions(ctx context.Context, name string, quotaEnabled bool, ownerID string) (*GroupInfo, error)`
- `(c *Client) CreateSystemGroup(ctx context.Context, name string, quotaEnabled bool) (*GroupInfo, error)` (Admin only)
- `(c *Client) AddUserToGroup(ctx context.Context, groupID, userID, info string, ci *ContactInfo) error`: Adds a named member to a group. 
- `(c *Client) AddAnonymousUserToGroup(ctx context.Context, groupID string, pubKey *mlkem.EncapsulationKey768) error`: Adds an anonymous member to a group.
- `(c *Client) RemoveUserFromGroup(ctx context.Context, groupID, userID string) error`: Convenience method for revoking a named member.
- `(c *Client) RevokeGroupMember(ctx context.Context, groupID, targetUserID string, targetAnonPubKey []byte) error`: Removes a member (named or anonymous) and performs O(1) key ratchet revocation.
- `(c *Client) ListGroups(ctx context.Context) iter.Seq2[metadata.GroupListEntry, error]`

### 7.2 Discovery
- `(c *Client) GenerateContactString() (string, error)`: Exports the user's public identity for group invites.
- `(c *Client) ParseContactString(s string) (*ContactInfo, error)`: Parses an identity string.

---

## 8. Error Handling and Registry

DistFS clients report errors through structured `APIError` objects for server-side failures and standard `syscall` errors in the FUSE layer.

| DistFS Code | HTTP | Description | client.FS / FUSE Mapping |
| :--- | :--- | :--- | :--- |
| `DISTFS_NOT_FOUND` | 404 | The requested resource (Inode, User, Group) does not exist. | `syscall.ENOENT` |
| `DISTFS_EXISTS` | 409 | Resource already exists. | `syscall.EEXIST` |
| `DISTFS_VERSION_CONFLICT` | 409 | OCC failure. | `syscall.EAGAIN` |
| `DISTFS_LEASE_REQUIRED` | 409 | Operation requires an exclusive lease. | `syscall.EACCES` |
| `DISTFS_QUOTA_EXCEEDED` | 403 | Storage/inode limit reached. | `syscall.EDQUOT` |
| `DISTFS_UNAUTHORIZED` | 401 | Invalid session token. | `syscall.EACCES` |
| `DISTFS_FORBIDDEN` | 403 | Authenticated user lacks permission. | `syscall.EACCES` |
| `DISTFS_NOT_LEADER` | 503 | Server is not the current leader. | `syscall.EAGAIN` |

---

## 9. Administrative API (Admin Only)

These functions return iterators or perform privileged metadata overrides.

- `(c *Client) AdminPromote(ctx context.Context, userID string) error`
- `(c *Client) AdminListUsers(ctx context.Context) iter.Seq2[*metadata.User, error]`
- `(c *Client) AdminListGroups(ctx context.Context) iter.Seq2[*metadata.Group, error]`
- `(c *Client) AdminListLeases(ctx context.Context) iter.Seq2[*metadata.LeaseInfo, error]`
- `(c *Client) AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error`
- `(c *Client) AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error`
- `(c *Client) AdminListNodes(ctx context.Context) iter.Seq[*metadata.Node]`
- `(c *Client) AdminJoinNode(ctx context.Context, address string) error`
- `(c *Client) AdminRemoveNode(ctx context.Context, id string) error`
- `(c *Client) AdminClusterStatus(ctx context.Context) (map[string]interface{}, error)`

---

## 10. FUSE Interface (`pkg/fuse`)

- `NewFS(c *client.Client) *FS`: Initializes a FUSE filesystem object.
- `(f *FS) Root() (fs.Node, error)`: Entry point for mounting.
