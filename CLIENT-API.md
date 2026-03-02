# DistFS Client API Documentation (v1)

This document describes the exported API of the `pkg/client` and `pkg/fuse` packages.

---

## 1. Lifecycle and Identity

### 1.1 Client Construction
- `NewClient(serverAddr string) *Client`: Creates a base client pointing to a metadata server.
- `(c *Client) WithIdentity(userID string, key *mlkem.DecapsulationKey768) *Client`: Configures user identity and encryption keys.
- `(c *Client) WithSignKey(key *crypto.IdentityKey) *Client`: Configures user signing keys.
- `(c *Client) WithServerKey(key *mlkem.EncapsulationKey768) *Client`: Manually configures the cluster encryption public key.
- `(c *Client) WithRootAnchor(id, owner string, version uint64) *Client`: Configures the initial trust anchor for the root directory.
- `(c *Client) WithRootID(id string) *Client`: Sets a specific Inode ID as the logical root (chroot).
- `(c *Client) WithAdmin(admin bool) *Client`: Enables administrative bypass mode (requires server-side admin privileges).

### 1.2 Authentication & Session
- `(c *Client) Login(ctx context.Context) error`: Performs challenge-response authentication.
- `(c *Client) UserID() string`: Returns the configured User ID.
- `(c *Client) GetRootAnchor() (id, owner string, version uint64)`: Returns the current root anchoring metadata.

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

## 3. POSIX-like Interface

These methods provide standard filesystem operations mimicking Go standard library patterns (`io/fs` and `os`). They are generally synchronous and perform path resolution internally.

### 3.1 Standard Operations
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

### 3.2 POSIX Semantics and Guarantees

DistFS provides a subset of POSIX semantics optimized for a distributed, end-to-end encrypted environment.

#### 3.2.1 Consistency and Visibility
- **Metadata Consistency:** All metadata operations (Rename, Mkdir, etc.) are **Linearizable** and strongly consistent across the cluster via Raft.
- **Write Visibility:**
    - Read-after-write is supported within a single `Client` instance (including its FUSE mount) for convenience.
    - However, persistent readback from the server and visibility to other clients is **ONLY guaranteed** after a successful `Close()`, `Sync()`, or `Flush()`.
- **Atomic Swap:** File writes do not modify existing Inodes in-place. Instead, a new Inode is created and swapped into the parent directory atomically upon `Close()`.

#### 3.2.2 Atomicity
- **Renames:** Cross-directory renames are atomic and safe from partial failures.
- **Unlinks:** Removing a file is atomic. If the file has active links, the data is preserved until the last link is removed (`NLink == 0`).

#### 3.2.3 Links
- **Hard Links:** Supported for files. Hard links to directories are forbidden.
- **Symbolic Links:** Fully supported. Path resolution handles absolute and relative symlinks.

---

## 4. Standard Library Interface (`io/fs`)

DistFS implements the standard Go `io/fs` interfaces, allowing it to be used with any library that expects an `fs.FS`.

- `(c *Client) FS(ctx context.Context) *DistFS`: Returns an `fs.FS` implementation rooted at the client's current root.

### Supported Interfaces:
- `fs.FS` (`Open`)
- `fs.ReadDirFS` (`ReadDir`)
- `fs.StatFS` (`Stat`)
- `fs.ReadFileFS` (`ReadFile`)

---

## 5. Metadata and Coordination

### 5.1 Inode Operations
- `(c *Client) ResolvePath(ctx context.Context, path string) (*metadata.Inode, []byte, error)`: Low-level path resolution. Returns the Inode and the raw FileKey.
- `(c *Client) GetInode(ctx context.Context, id string) (*metadata.Inode, error)`: Fetches an Inode by ID.
- `(c *Client) UpdateInode(ctx context.Context, id string, fn InodeUpdateFunc) (*metadata.Inode, error)`: Atomic mutation of Inode metadata. Handles automatic version incrementing and signing.

### 5.2 Distributed Leases

Leases are the primary mechanism for coordination in DistFS. They are managed by the Metadata Raft cluster and provide strong consistency guarantees.

#### 5.2.1 Lease Types and Conflicts
- **Shared Lease (`LeaseShared`)**: Requested by readers. Multiple sessions can hold shared leases on the same resource.
- **Exclusive Lease (`LeaseExclusive`)**: Requested by writers or for transactional updates. Only one session can hold an exclusive lease.
- **Conflict Rules**:
    - An Exclusive request is rejected if **any** other session holds a lease (Shared or Exclusive).
    - A Shared request is rejected if **another** session holds an Exclusive lease.

#### 5.2.2 Scope: Inode vs. Path
Leases can be acquired on two types of identifiers:
1.  **Inode ID**: Freezes the metadata and data of a specific object. Prevents concurrent `UpdateInode` operations from other sessions.
2.  **Path Name**: Freezes path resolution. Prevents the path from being renamed or unlinked, ensuring it always resolves to the same Inode for the duration of the lease.

#### 5.2.3 Guarantees
- **Namespace Stability**: Holding a lease on a path ensures that `ResolvePath` will return the same Inode ID until the lease is released.
- **Snapshot Isolation**: By acquiring shared leases on multiple paths simultaneously (as done in `ReadDataFiles`), a client can read a consistent point-in-time snapshot of a set of files.
- **Mutual Exclusion**: Exclusive leases on Inode IDs enable safe Read-Modify-Write cycles across different clients.

#### 5.2.4 Lifecycle
- `(c *Client) AcquireLeases(ctx context.Context, ids []string, duration time.Duration, opts LeaseOptions) error`
- `(c *Client) ReleaseLeases(ctx context.Context, ids []string, nonce string) error`

### 5.3 Lease Options and Callbacks
```go
type LeaseOptions struct {
    Type    metadata.LeaseType
    Nonce   string
    Lockbox crypto.Lockbox
    // OnExpired is called if the background renewal loop fails (e.g., network partition)
    // and the lease actually expires on the server.
    OnExpired func(id string, err error)
}
```

### 5.4 Optimistic Concurrency Control (OCC)

DistFS primarily uses OCC for metadata mutations to achieve high throughput without the overhead of heavy locking for every operation.

- **Versioning**: Every Inode and Group carries a monotonic `Version` number.
- **Precondition Check**: When a client submits a mutation (via `UpdateInode` or a batch), the FSM enforces that the `submittedVersion` MUST be exactly `existingVersion + 1`.
- **Integrity**: The client signs the entire manifest, including the new version number. The server rejects any mutation if the signature is invalid or the version number is incorrect.
- **Conflict Handling**: If another client commits a change simultaneously, the server returns `DISTFS_VERSION_CONFLICT`. The high-level Client API (e.g., `UpdateInode`) automatically re-fetches the latest metadata, re-applies the user's mutation callback, and retries the commit.

### 5.4 Cache Management
- `(c *Client) ClearCache()`: Flushes local metadata, path, and key caches. Necessary when external changes are suspected or after certain administrative actions.

---

## 6. Security and Group Management

DistFS uses groups for shared access. All encryption is end-to-end; the server never sees group keys.

### 6.1 Group Operations
- `(c *Client) CreateGroup(ctx context.Context, name string, quotaEnabled bool) (*metadata.Group, error)`
- `(c *Client) CreateSystemGroup(ctx context.Context, name string, quotaEnabled bool) (*metadata.Group, error)` (Admin only)
- `(c *Client) AddUserToGroup(ctx context.Context, groupID, userID, info string, ci *ContactInfo) error`: Adds a member to a group. 
- `(c *Client) RemoveUserFromGroup(ctx context.Context, groupID, userID string) error`: Removes a member.
- `(c *Client) ListGroups(ctx context.Context) iter.Seq2[metadata.GroupListEntry, error]`
- `(c *Client) GetGroupMembers(ctx context.Context, groupID string) iter.Seq2[metadata.MemberEntry, error]`

*Note: Iterators terminate on context cancellation or after yielding their first error.*

### 6.2 Zero-Knowledge Group Membership (Lockbox)
To maintain E2EE, group keys are never shared with the server. When a user is added to a group:
1. The inviting client fetches the new member's `ContactInfo` (containing their Public Encryption Key).
2. The client encapsulates the **Group Key** for the new member using ML-KEM-768.
3. The resulting ciphertext is stored in the group's `Lockbox` or `RegistryLockbox`.
4. The server merely stores and serves these ciphertexts; only the intended recipient can decrypt them using their private key.

### 6.3 Discovery
- `(c *Client) GenerateContactString() (string, error)`: Exports the user's public identity for group invites.
- `(c *Client) ParseContactString(s string) (*ContactInfo, error)`: Parses an identity string.

---

## 7. Data Structures

### 7.1 `DistDirEntry`
Implements `os.DirEntry`. Used by `ReadDirExtended`.
- `Name() string`: Plaintext filename.
- `IsDir() bool`
- `Type() os.FileMode`
- `Info() (os.FileInfo, error)`
- `Inode() *metadata.Inode`: Access to full underlying metadata.
- `InodeID() string`
- `Size() int64`
- `ModTime() time.Time`

### 7.2 `ContactInfo`
Public identity for key exchange.
- `UserID string`
- `EncKey []byte` (ML-KEM-768 Public)
- `SignKey []byte` (ML-DSA-65 Public)

### 7.3 `APIError`
- `StatusCode int`: HTTP Status.
- `Code string`: DistFS-specific error code.
- `Message string`: Human-readable error.

---

## 8. Error Handling and Registry

DistFS clients report errors through three primary mechanisms: structured `APIError` objects for server-side failures, wrapped `fmt.Errorf` for client-side validation/integrity, and standard `syscall` errors in the FUSE layer.

### 8.1 Structured Server Errors (`APIError`)
When the Metadata or Data server returns a non-200 status, the client returns an `*APIError`.

| DistFS Code | HTTP | Description | client.FS / FUSE Mapping |
| :--- | :--- | :--- | :--- |
| `DISTFS_NOT_FOUND` | 404 | The requested resource (Inode, User, Group) does not exist. | `syscall.ENOENT` |
| `DISTFS_EXISTS` | 409 | Resource already exists. | `syscall.EEXIST` |
| `DISTFS_VERSION_CONFLICT` | 409 | OCC failure. High-level APIs retry automatically; low-level ones return this. | `syscall.EAGAIN` |
| `DISTFS_LEASE_REQUIRED` | 409 | Operation requires an exclusive lease that was not provided. | `syscall.EACCES` |
| `DISTFS_QUOTA_EXCEEDED` | 403 | User or Group storage/inode limit reached. | `syscall.EDQUOT` |
| `DISTFS_QUOTA_DISABLED` | 403 | Attempted to set quota on a group where it is disabled. | `syscall.EACCES` |
| `DISTFS_UNAUTHORIZED` | 401 | Invalid session token or expired authentication. | `syscall.EACCES` |
| `DISTFS_FORBIDDEN` | 403 | Authenticated user lacks permission for the resource. | `syscall.EACCES` |
| `DISTFS_NOT_LEADER` | 503 | Server is not the current leader. Client automatically retries other nodes. | `syscall.EAGAIN` |
| `DISTFS_STRUCTURAL_INCONSISTENCY`| 409 | Mutation violates filesystem topology. | `syscall.EIO` |
| `DISTFS_ATOMIC_ROLLBACK` | 500/409 | Atomic batch failure. | `syscall.EIO` |

### 8.2 Client-Side Integrity and Security Errors
These errors are generated locally by the client during verification of server responses. They typically indicate serious security or consistency issues.

| Error Message Pattern | Description | Impact |
| :--- | :--- | :--- |
| `ROOT COMPROMISE DETECTED` | The root Inode's owner does not match the client's configured `RootAnchor`. | **CRITICAL**: Potential server takeover or malicious node. |
| `ROOT ROLLBACK DETECTED` | The root Inode's version is older than the last known version in `RootAnchor`. | **CRITICAL**: Replay attack or server state rollback. |
| `integrity check failed` | The cryptographic signature on an Inode or Group does not match its contents. | **CRITICAL**: Malicious metadata tampering detected. |
| `invalid manifest signature` | The Inode manifest signature was not created by an authorized signer. | **HIGH**: Unauthorized metadata update. |
| `access denied: no applicable recipient in lockbox` | The client possesses a valid identity but is not listed as a recipient for the file/group key. | **MEDIUM**: Normal ACL enforcement failure. |

### 8.3 Path and Logic Errors
Standard errors returned during normal path resolution or filesystem operations.

| Error Message | Description | FUSE Mapping |
| :--- | :--- | :--- |
| `path component %s not found` | Part of the path does not exist. | `syscall.ENOENT` |
| `path component %s is not a directory` | Attempted to resolve through a file/symlink as if it were a directory. | `syscall.ENOTDIR` |
| `is a directory` | Attempted to read data from a directory inode. | `syscall.EISDIR` |
| `not a directory` | Attempted to list entries of a file inode. | `syscall.ENOTDIR` |
| `directory not empty` | Attempted to `Remove` a non-empty directory. | `syscall.ENOTEMPTY` |
| `client identity not fully configured` | Mutation attempted before `WithIdentity` or `WithSignKey` was called. | `syscall.EACCES` |

### 8.4 FUSE Mapping (`pkg/fuse`)
The `fuse` package uses a `mapError` helper to ensure the OS kernel receives appropriate POSIX error codes. If an internal error does not match any specific mapping, it defaults to `syscall.EIO`.

- **Context Cancellations:** `context.Canceled` -> `syscall.EINTR`, `context.DeadlineExceeded` -> `syscall.ETIMEDOUT`.
- **String Matching:** For non-structured errors, FUSE performs case-insensitive substring matching for "directory not empty", "not a directory", "access denied", etc.

### 8.5 Data Layer and Cryptographic Errors
Errors occurring during chunk retrieval or cryptographic primitive execution.

| Error Message Pattern | Description | Impact |
| :--- | :--- | :--- |
| `failed to download chunk %s` | The client could not retrieve an encrypted chunk from any of the allocated storage nodes. | **HIGH**: Data unavailability. Possible network partition or node failure. |
| `decapsulate failed` | ML-KEM-768 decapsulation of a File or Group key failed. | **HIGH**: Likely invalid ciphertext or corrupted local private key. |
| `decrypt failed` | AES-GCM decryption of a data chunk or `client_blob` failed. | **HIGH**: Data corruption or incorrect/stale symmetric key. |
| `integrity check failed` | Post-download hash or signature verification failed for a chunk. | **CRITICAL**: In-transit data tampering detected. |

---

## 9. Recipes

### 9.1 Atomic Multi-file Update
Use `OpenManyForUpdate` to ensure multiple related files are updated as a single atomic unit.

```go
// Atomically update app.json and version.txt
configs := []any{&AppConfig{}, &VersionInfo{}}
commit, err := client.OpenManyForUpdate(ctx, []string{"/app.json", "/version.txt"}, configs)
if err != nil {
    return err
}

// Modify the data objects
configs[0].(*AppConfig).Enabled = true
configs[1].(*VersionInfo).Revision++

// Commit both changes in a single Raft transaction
commit(true) 
```

---

## 10. Administrative API (Admin Only)

These functions return iterators (`iter.Seq` or `iter.Seq2`) for efficient streaming of large result sets.

### 10.1 Iterator Semantics
- **Context Cancellation**: Iterators respect the `ctx` passed to the method. If the context is cancelled, the iterator will terminate immediately.
- **Error Handling**: For `iter.Seq2[T, error]`, if a non-nil error is yielded, it is the **final** value of the sequence. Callers MUST stop processing upon receiving an error.
- **Backpressure**: Iterators pull data from the server in batches. Pausing the loop will pause network ingress.

### 10.2 Operations
- `(c *Client) AdminLookup(ctx context.Context, email, reason string) (string, error)`
- `(c *Client) AdminPromote(ctx context.Context, userID string) error`
- `(c *Client) AdminListUsers(ctx context.Context) iter.Seq2[*metadata.User, error]`
- `(c *Client) AdminListGroups(ctx context.Context) iter.Seq2[*metadata.Group, error]`
- `(c *Client) AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error`
- `(c *Client) AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error`
- `(c *Client) AdminListNodes(ctx context.Context) iter.Seq[*metadata.Node]`
- `(c *Client) AdminJoinNode(ctx context.Context, address string) error`
- `(c *Client) AdminRemoveNode(ctx context.Context, id string) error`
- `(c *Client) AdminClusterStatus(ctx context.Context) (map[string]interface{}, error)`

---

## 11. FUSE Interface (`pkg/fuse`)

The `fuse` package provides a bridge between the DistFS Client and the OS kernel via the `bazil.org/fuse` library.

- `NewFS(c *client.Client) *FS`: Initializes a FUSE filesystem object.
- `(f *FS) Root() (fs.Node, error)`: Entry point for mounting.

### Feature Mapping:
- **Streaming:** File reads/writes are streamed chunk-by-chunk.
- **Atomicity:** File creations and writes use the atomic swap model on `Close()`.
- **Metadata:** Attributes and directory listings are cached according to kernel defaults.
- **Quotas:** `Statfs` correctly reports cluster-wide and user-specific storage limits.
