# DistFS: Secure Distributed File System
**High-Level Design Document**

## 1. Overview
DistFS is a distributed, end-to-end encrypted file system designed for zero-knowledge privacy. It separates metadata management (strongly consistent via Raft) from data storage (scalable via chunked distribution). The system is designed to provide `fs.FS` compatibility for Go clients while ensuring that the storage providers (nodes) cannot read the user's data or metadata.

> **Technical Specification:** For the exhaustive Client<->Server protocol contract, refer to [SERVER-API.md](SERVER-API.md). For the high-level Go Client API, refer to [CLIENT-API.md](CLIENT-API.md).
>
> **Implementation Plan:** For the detailed, step-by-step execution strategy of this design, refer to [DISTFS-PLAN.md](DISTFS-PLAN.md).

## 2. Core Architecture

The system uses a unified node architecture to simplify deployment and management.

1.  **Client:** The entry point. Handles encryption, chunking, and file tree logic.
2.  **Storage Node:** A unified binary that performs two distinct roles:
    *   **Metadata Role:** Participates in the Raft consensus group (typically 3-5 nodes) to manage the namespace.
    *   **Data Role:** Stores encrypted binary blobs. *All* nodes in the cluster perform this role, allowing storage capacity to scale horizontally independent of the consensus group.

### 2.1 Priorities
1.  **SECURITY:** End-to-End Encryption (E2EE). Server trusts no one. Access control via cryptography.
2.  **RELIABILITY:** Metadata replicated via Raft logs. Data replicated via chunk copying (RepFactor=3).
3.  **SCALABILITY:** Metadata separated from data. Data writes go directly to Data Roles.
4.  **LOW LATENCY:** Clients cache metadata and stream chunk reads in parallel.

### 2.2 Scalability Targets & Constraints
The system is designed to scale horizontally, with the following soft limits:
*   **File Size:** Up to **100 GB** (100,000 chunks @ 1MB).
    *   *Design Implication:* Large files result in large Inode structures (100k UUIDs ~ 1.6MB). The Metadata Layer splits `ChunkManifests` into multiple pages to keep individual Raft log entries small.
*   **File Count:** Up to **1 Million Files** per cluster.
    *   *Design Implication:* This results in ~1M keys in the Raft FSM. The `LinkSnapshotStore` and `NoSnapshotRestoreOnStart` optimizations are critical for O(1) restarts. Metadata is grouped by "Directory" to allow LRU eviction of inactive trees from memory.

---

## 3. Security Architecture (Priority #1)

### 3.1 The "Trust No One" Model
*   **Data Privacy:** All file content is encrypted on the Client side using AES-256-GCM before it is sent to any node.
*   **Metadata Privacy:** Directory names and file names are encrypted. The MetaNode sees the file system as a graph of opaque IDs, not paths like `/home/alice/docs`.
*   **Node Security:** Leveraging `github.com/c2FmZQ/storage`, all data stored on MetaNodes and DataNodes (Raft logs, snapshots, chunk files, keys) is encrypted *at rest*.
    *   **Root Secret:** A `DISTFS_MASTER_KEY` environment variable provides the master passphrase.
    *   **Master Key:** A `crypto.MasterKey` is derived from this passphrase to decrypt the node-local key store (`data/master.key`).
    *   **ClusterSecret Vault:** Each node maintains a local encrypted vault containing the shared **ClusterSecret**. This vault is protected by the node's unique Master Key.
    *   **Isolation:** Encryption keys are node-local and never shared across the network.
*   **Key Rotation:** 
    *   **Raft Logs:** The encryption key for Raft logs MUST be rotated after every snapshot.
    *   **FSM Metadata:** Metadata values in BoltDB are encrypted using a cluster-wide **FSM KeyRing**. The active key is used for new writes, while old keys are retained for decryption.
    *   **Root of Trust (FSM):** Critical metadata anchors (the `FSM KeyRing` and `ClusterSignKey`) are stored in the BoltDB `system` bucket, **encrypted with a key derived from the ClusterSecret**. This ensures that the rotating KeyRing can be safely stored within the FSM itself.

### 3.2 Key Hierarchy & Cryptography
Users control their identity via an asymmetric key pair using **Post-Quantum Cryptography (PQC)** algorithms (e.g., CRYSTALS-Kyber for encapsulation, CRYSTALS-Dilithium for signatures) to future-proof against quantum threats.

1.  **User Identity Key:** Public key maps to the User ID. Private key signs requests.
    *   **User ID:** Derived from the user's email using a cluster-wide HMAC to ensure privacy.
2.  **Cluster Identity (Epoch Keys):** The cluster maintains a rotating set of shared PQC KEM keys ("Epoch Keys") stored in the Raft FSM.
    *   **Shared:** All nodes use the same keys to decrypt client requests, enabling stateless load balancing.
    *   **Rotating:** Keys rotate periodically (e.g., daily) to provide **Forward Secrecy**. Old keys are securely erased from memory and disk.
3.  **Group Identity Key:** A persistent Public/Private key pair representing a Group. The Group Private Key is shared among group members via the Group Lockbox.
4.  **File Key (FK):** A random symmetric key generated for *each* file. Encrypts the file content.
5.  **Lockbox:**
    *   **File Lockbox:** Stores the `File Key` encrypted for the Owner and/or the assigned Group.
    *   **Group Lockbox:** Stores the `Group Private Key` encrypted for each member's Public Key.
    *   **World Lockbox:** Special entry for ID `world`. Allows all registered users to retrieve the World Private Key (encrypted for them) to decrypt or modify "world-accessible" files.

### 3.3 Privacy & Identity (The "Dark Registry")
To minimize PII exposure, the metadata layer operates on opaque identifiers.
*   **Transient PII:** The server processes user emails (e.g., during OIDC registration) only momentarily in memory.
*   **Hashed Identifiers:** The persistent User ID is `HMAC-SHA256(Email, ClusterSecret)`.
    *   **Cluster Secret:** A high-entropy random key generated at cluster bootstrap, stored securely in the Raft FSM, and shared among nodes via mTLS. It never leaves the cluster.
    *   **Implication:** Logs, snapshots, and disk storage contain no emails or names.
*   **No Names:** The FSM does **not** store user names (e.g., "Alice"). Users who wish to share their display name must store it in an encrypted file (e.g., `/.profile`) within the file system itself.

### 3.4 Transport Privacy (Layer 7 E2EE)
While TLS (Layer 4) protects the connection, DistFS implements **Layer 7 End-to-End Encryption** for all metadata operations to ensure that infrastructure components (load balancers, WAFs, or malicious proxies) cannot observe or tamper with the file system structure.

1.  **Sealed Requests:** All mutation and sensitive query requests from the Client to the Metadata Server are wrapped in a `SealedRequest` envelope. The payload is encrypted for the Cluster and signed by the Client.
2.  **Sealed Responses:** All responses from the Metadata Server to authenticated clients are wrapped in a `SealedResponse` envelope. The payload is encrypted for the specific Client (using their registered public key) and signed by the Server.
3.  **Unsealed at Edges:** Encryption/Decryption happens exclusively at the Client and the Raft Leader. Intermediate nodes or proxies see only opaque blobs.
4.  **Replay Protection:** Each sealed envelope includes a high-resolution timestamp and is subject to sliding-window nonce verification.

### 3.5 Opaque Client Metadata (ClientBlob)
To maximize user privacy and minimize the server's knowledge of the filesystem content, all metadata that is not strictly required for server-side enforcement (e.g., filenames, timestamps, fine-grained ACLs) is consolidated into a single encrypted blob.

1.  **ClientBlob Envelope:** An AES-256-GCM encrypted structure stored within the `Inode` and `Group` objects.
2.  **Encryption Keys:**
    *   **Inode:** Encrypted with the **File Key**.
    *   **Group:** Encrypted with the **Group Encryption Key**.
3.  **Encapsulated Fields:**
    *   **Inodes:** Filenames (`Name`), symbolic link targets, modification times (`MTime`), small file content (`InlineData`), POSIX ownership (`UID`/`GID`), and the interaction history (`SignerID`, `AuthorizedSigners`).
    *   **Groups:** Human-readable group names.
4.  **Integrity:** The `ClientBlob` is included in the cryptographic hash signed by the client. The server verifies the signature to ensure the blob hasn't been tampered with, even though it cannot read the content.

### 3.6 Multi-Device Key Synchronization (Zero-Knowledge Sync)
To support seamless multi-device usage without compromising the "Trust No One" model, DistFS provides a unified onboarding flow that combines identity initialization, registration, and cloud-backed recovery.

1.  **Unified Onboarding (`init` command):**
    *   **New Account (`--new`):** The client generates PQC identity keys, executes the OAuth2 Device Flow to authenticate via OIDC, registers the keys with the server, encrypts the local configuration, and automatically pushes a synchronization blob to the server.
    *   **Existing Account:** On a new device, the user runs `init` without the `--new` flag. The client authenticates via OIDC, retrieves the encrypted synchronization blob from the server, and restores the local configuration after prompting for the passphrase.
2.  **Client-Side Preparation:** The client encrypts its `config.json` (containing the PQC Identity and Encryption keys) using a user-provided passphrase and **Argon2id** KDF.
3.  **Passphrase-Encrypted Blob:** The server only ever sees the opaque ciphertext (`KeySyncBlob`).
4.  **Security Enforcement:** To prevent unauthorized overwrites, storing or updating a sync blob requires a valid `Session-Token` and mandatory **Layer 7 E2EE (Sealing)**.

### 3.7 Secure Passphrase Entry (Pinentry)
To enhance security during passphrase entry, DistFS supports the **Assuan protocol** via the `pinentry` suite of tools.
1.  **Standard Protocol:** The client communicates with `pinentry` binaries (e.g., `pinentry-curses`, `pinentry-qt`, `pinentry-mac`) to securely capture user passphrases.
2.  **Environment Integration:** Supports `GPG_TTY` for terminal-based entry and respects `~/.gnupg/gpg-agent.conf` configurations.
3.  **Opt-in Usage:** Enabled via the `--use-pinentry` flag in CLI and FUSE tools.
4.  **Hardened Implementation:** Validates input environments and avoids insecure logging of captured passphrases.

---

## 4. Metadata Layer (MetaNodes)

This layer implements a distributed consensus architecture using the Raft protocol.

### 4.1 State Machine (FSM)
The Raft FSM stores the "Inode" table and Directory Structure.
*   **User Structure:**
    *   `HMAC(email) -> {UID, ML-KEM PK, ML-DSA PK, Usage, Quota}`.
*   **Group Structure:**
    *   `UUID -> {ID, OwnerID, GID, ML-KEM PK, ML-DSA PK, ClientBlob, MemberList, Lockbox, RegistryLockbox, EncryptedRegistry, Usage, Quota, Version, SignerID, Signature}`.
        *   **OwnerID:** Can be a `UserID` or another `GroupID`.
        *   **ClientBlob:** AES-GCM encrypted metadata (e.g., Group Name).
        *   **Lockbox:** Shares Group Private Keys among all members.
        *   **RegistryLockbox:** Shares a symmetric **Registry Key** only among authorized managers (`OwnerID`).
        *   **EncryptedRegistry:** An opaque blob containing member emails and UserIDs, encrypted with the Registry Key.
        *   **Usage:** Tracks inodes and bytes used by files assigned to this group.
        *   **Quota:** Optional resource limits for the group.
        *   **Version:** Incremental counter for optimistic concurrency control.
        *   **Signature:** ML-DSA signature over the group metadata, signed by the `SignerID`.
*   **Membership Indices:**
    *   `UserID -> List[GroupID]` (Direct Membership Index).
    *   `OwnerID -> List[GroupID]` (Ownership/Management Index).
*   **Inode Structure:**
    *   `UUID -> {OwnerID, GroupID, Mode, Manifest, Lockbox, ClientBlob, UserSig, GroupSig}`.
        *   **ClientBlob:** AES-GCM encrypted metadata (Name, MTime, ACLs, InlineData).
*   **Directory Structure:** The Metadata Layer MUST know the file system hierarchy to enforce permissions and perform Garbage Collection.
    *   **Directory Inodes:** Store a list of children: `HMAC(Name) -> InodeID`. This allows traversal and GC traversing without knowing plaintext names.
    *   **File Inodes:** Store `ChunkManifest` (List of Chunk IDs + DataNode locations).
    *   **Garbage Collection:** Orphaned Inodes and Chunks (not referenced by any live Inode) are garbage collected.

### 4.2 Metadata Integrity & Attribution
DistFS ensures the integrity of file metadata (chunk manifests) using **Dual-Signature Authorization**. This prevents a compromised Metadata Server from silently modifying file contents or rolling back to old versions.

*   **Individual Attribution (UserSig):** Every manifest update is signed by the writer's PQC Identity Key (ML-DSA). This provides non-repudiable proof of *who* modified the file.
*   **Group Authorization (GroupSig):** If a file is modified in a group context, it is also signed with the **Group Signing Key**. This proves the writer was an authorized member of the group at the time of the write.
*   **Verification:** Readers verify both signatures before processing data chunks. If the signatures do not match the current manifest, the client rejects the file as tampered.

### 4.3 Permissions Model
DistFS follows a strict subset of POSIX permissions designed for Zero-Knowledge security:

*   **Owner:** Full `rwx` support.
*   **Group:** Full `rwx` support via shared cryptographic keys.
*   **Other (World):** Strictly **Read-Only** or **None**.
    *   **Prohibition:** The "Write" bit for 'Other' (0002) is strictly prohibited. The Metadata Server will reject any `chmod` or `mkdir` request that attempts to grant world-write access. Verifiable integrity cannot be maintained for anonymous writers.

### 4.4 Persistence & Snapshots
*   **Engine:** Hashicorp Raft with BoltDB.
*   **Snapshot Strategy:** Use `MetadataSnapshot` (Streaming BoltDB).
    *   **Fast Startup:** `NoSnapshotRestoreOnStart = true`. MetaNodes rely on disk persistence and only replay trailing logs on startup to ensure fast recovery.

### 4.5 Consistency & Versioning
Metadata operations in DistFS follow an **Optimistic Concurrency Control (OCC)** model with client-side authority over versioning.

1.  **Strict Sequentiality:** The server enforces that every update to an Inode or Group must increment its `Version` field by exactly one.
2.  **Client-Side Authority:** The client is responsible for fetching the latest state, applying mutations, and signing the new version.
3.  **Lease Enforcement:** Linearizability is guaranteed via server-side lease enforcement (see Section 5 of [SERVER-API.md](SERVER-API.md)).
4.  **Atomic Merge Pattern:** The client library provides mutation callbacks that automatically re-fetch and retry on version conflicts (HTTP 409).
5.  **Structural Validation:** To maintain namespace integrity, the Metadata Server performs batch-wide structural checks:
    *   **NLink Consistency:** The server validates that changes to a directory's `Children` map are matched by corresponding changes to the child Inode's `NLink` count within the same atomic batch.
    *   **Link Bidirectionality:** For every addition to a directory's `Children` map, the child Inode MUST include a reciprocal entry in its `Links` map.
    *   **Type Integrity:** 
        *   `DirType` inodes cannot be hard-linked (maximum `NLink` of 1).
        *   `FileType` and `SymlinkType` inodes MUST have an empty `Children` map.
    *   **Root Protection:** Inodes with no parent links (Filesystem Roots) are protected from deletion and unlinking operations.
    *   **Empty Directory Protection:** A request to delete a directory Inode (NLink=0) is rejected if the directory still contains children in its metadata.

### 4.6 Group Management & Authorization
To prevent unauthorized hijacking and support collaborative administration, group mutations (updates to membership, keys, or names) are subject to strict cryptographic authorization.

1.  **Ownership Model:**
    *   **User-Owned:** If `OwnerID` matches a `UserID`, only that user can sign updates for the group and access the **Member Registry**.
    *   **Group-Owned:** If `OwnerID` matches a `GroupID`, any registered member of the owning group can sign updates and access the **Member Registry** of the target group.
    *   **Self-Managed:** If `OwnerID` equals the group's own `ID`, any member of the group can sign updates and access the **Member Registry**.
2.  **Member Registry (PII Isolation):** To comply with Zero-Knowledge principles while allowing administrative oversight, member emails are stored in the `EncryptedRegistry`. This blob is encrypted with a unique symmetric key shared only via the `RegistryLockbox`. Regular members who are not authorized managers cannot decrypt this registry and thus cannot see the emails of other members.
3.  **Signature Requirement:** All `UpdateGroup` requests must be signed by the requester's personal ML-DSA Identity Key. The server verifies that the `SignerID` is authorized based on the ownership model above.
4.  **No Recursion:** Management checks are limited to a single level. If Group A is owned by Group B, and Group B is owned by Group C, a member of Group C **cannot** manage Group A unless they are also a member of Group B.
5.  **Optimistic Concurrency:** Group updates follow the centralized consistency model described in Section 4.5.

### 4.7 Group Discovery
To support collaboration without a central directory, the metadata layer provides authenticated users with a way to discover groups they are involved in.

1.  **Group List API:** An authenticated user can query for a list of groups where they have a defined role.
2.  **Role Resolution:** The server identifies the user's role for each group:
    *   **Owner:** The user is the direct `OwnerID`.
    *   **Manager:** The user is a member of a group that is the `OwnerID`.
    *   **Member:** The user is a direct member of the group.
3.  **Privacy Preservation:** The server returns only the `GroupID`, the encrypted `ClientBlob`, and the resolved `Role`. The MetaNode does not know the plaintext names; the client must use its local keys to decrypt and display the group names to the user.

### 4.8 Resource Quotas
DistFS enforces multi-tenant resource limits at both the User and Group levels to ensure fair resource allocation and prevent accidental or malicious exhaustion of cluster storage.

1.  **Quota Metrics:** The system tracks two primary metrics:
    *   **Inodes:** The total number of files and directories owned by the entity.
    *   **Bytes:** The total logical size of all data chunks referenced by the entity's inodes.
2.  **Enforcement Hierarchy:** When an operation (e.g., file creation, write, or ownership transfer) occurs, the server identifies the target entity (Group or User) and enforces limits as follows:
    *   **Group Level:** If the target inode is assigned to a group, the server first checks for a **Group Quota**. If a group-level quota is defined (non-zero), it is enforced exclusively.
    *   **User Fallback:** If the group has no defined quota (all limits set to zero), the server falls back to enforcing the personal quota of the inode's `OwnerID`.
3.  **Atomic Accounting:** Usage counters are updated atomically within the same Raft transaction as the metadata mutation. Ownership transfers (chown/chgrp) automatically decrement usage from the source entity and increment it for the target, maintaining global consistency.
4.  **Admin Management:** Resource limits are managed by cluster administrators via the Admin CLI. Limits can be updated dynamically without affecting existing data availability.

### 4.9 Multiple Roots & Client Chroot
To support multi-tenancy and specialized organizational structures, DistFS supports the creation of multiple independent filesystem roots on a single cluster.

1.  **Independent Hierarchies:** While the system provides a default root (`metadata.RootID`), administrators can initialize any number of independent directory trees. Each root is a fully functional, self-contained filesystem with its own encryption keys and lockbox.
2.  **Explicit Initialization:** Roots must be explicitly initialized using the `admin-create-root` command. This ensures that the cluster does not automatically create namespace structures unless directed by an authorized administrator.
3.  **Client-Side Chroot:** The client library and FUSE mount tool support "chrooting" to any authorized Inode ID. When a client is rooted at a specific Inode, all path resolutions (starting from `/`) are relative to that Inode.
4.  **Isolation:** A chrooted client has no visibility or access to the original global root or other siblings in the hierarchy, providing a robust mechanism for namespace isolation.

---

## 5. Data Layer (Data Roles)

Files are split into fixed-size chunks of **1 MB**. The client library handles padding (hiding exact file size) and encryption.

### 5.1 Placement & Replication
*   **Goal:** 3 copies of each chunk (RepFactor=3).
*   **Constraint:** A node must never hold more than one copy of the same chunk.
*   **Distribution:** Chunks are distributed using Consistent Hashing weighted by available disk space.
*   **Fallback:** If `Nodes < 3`, redundancy is `min(3, NodeCount)`.

### 5.2 Write Flow (Pipeline)
1.  **Prepare:** Client encrypts the chunk and calculates its Hash (`ChunkID`).
2.  **Allocate:** Client requests allocation for `ChunkID` via Metadata API (`POST /v1/meta/allocate`). The Leader selects 3 target nodes.
3.  **Push:** Client pushes the *Encrypted* chunk to the **Primary Node** with `replicas=Secondary,Tertiary`.
4.  **Replicate:** Primary forwards the data to Secondary, which forwards to Tertiary (Pipelined).
5.  **Ack:** Once all 3 acknowledge, Primary acks the Client.
6.  **Commit:** Client updates the file metadata (Chunk Manifest) on the Raft Leader.

### 5.3 Reliability & Maintenance
*   **Replication Monitor:** The Leader periodically scans chunk manifests.
    *   **Under-Replicated:** If a node is missing for > `TBD` minutes, the Leader triggers a replication job to copy the chunk to a new healthy node.
    *   **Over-Replicated:** Extra copies (e.g., node returns after temporary partition) are garbage collected to reclaim space.
*   **Node Draining:** An admin API `POST /v1/node/{id}/drain` triggers a proactive replication of all chunks on a specific node to the rest of the cluster, allowing safe removal.
*   **Integrity Checks:** Each node runs a background "Scrubber" process. It periodically reads all local chunks and verifies their checksums against the filename (Content-Addressable Storage). Corrupt chunks are quarantined and reported to the Leader for repair.

### 5.4 Storage Format
*   Nodes store chunks as flat files: `data/chunks/{shard}/{chunk_id}`.
*   **Self-Validation:** Chunks are content-addressed (Hash of encrypted content).

### 5.5 Atomicity & Consistency
*   **Chunk Level:** Writes to DataNodes are atomic. A chunk is either fully written and validated or rejected. Replacements use new Chunk IDs or versioned writes; existing chunks are immutable.
*   **Path Level (Atomic Swap):** High-level mutation APIs (`OpenManyForUpdate`, `OpenBlobWrite`, `SaveDataFile`) utilize an **Atomic Path Swap** pattern. 
    1.  The client acquires an **Exclusive Lease on the Filename** (or Path) to prevent concurrent atomic updates.
    2.  The client writes data to a **New Inode**. Existing readers continue to see the old Inode.
    3.  On `Close()` or commit, the client performs a batch metadata update that atomically points the directory entry to the New Inode and decrements the old Inode's link count.
    4.  Active readers of the old Inode are unaffected as they hold leases on the Inode ID, not the path.
*   **POSIX Level:** Standard FUSE operations (e.g., `write`, `truncate`) follow traditional POSIX semantics, potentially mutating an existing Inode in-place if not unlinked.

### 5.6 Access Control (Capability Tokens)
Data Nodes enforce permissions using **Capability Tokens** issued by the Metadata Leader.
*   **Flow:**
    1.  Client requests access to File X from Metadata Leader.
    2.  Leader checks permissions (ACL/Group).
    3.  Leader issues a time-bound **Signed Token** granting READ/WRITE access to the specific Chunk IDs associated with File X.
    4.  Client presents Token to Data Node.
    5.  Data Node verifies signature and expiry before serving data.

### 5.7 POSIX Deletion (Open Handle Persistence)
To achieve high-fidelity POSIX compliance, DistFS ensures that unlinked files (where `NLink == 0`) persist on storage nodes as long as they are being actively read or written by a client.

1.  **Usage Leases:** When a client opens a file, it acquires a **Shared Usage Lease** on the Inode. This lease acts as a signal to the cluster that the file is in use.
2.  **Deferred Deletion:** If a file is deleted (e.g., via `unlink`), the Metadata Server decrements its link count. If `NLink` becomes zero:
    *   The Inode is removed from the directory namespace (it can no longer be "found" by new `Open` requests).
    *   If active leases exist, the Inode is marked as **Unlinked (Pending Delete)**.
    *   The Inode and its associated chunks are **not** enqueued for Garbage Collection yet.
3.  **Lease Heartbeat:** Clients periodically renew their usage leases as long as the file handle is open. If a client crashes, the lease will naturally expire.
4.  **Final Cleanup:** The Metadata Server triggers the final deletion (quota reclamation and chunk GC enqueuing) only when the link count is zero **and** all usage leases have expired or been explicitly released.

---

## 6. Client Library & API

### 6.1 Go Client (`fs.FS`)
The client library implements `io.fs.FS` and `io.fs.File`.

*   `Open(name string)`:
    1.  Resolve path by traversing Directory Inodes (fetching `Children`).
    2.  Decrypt `ClientBlob` from parent directory to find component IDs.
    3.  Fetch file metadata (`Lockbox` + `ChunkManifest` + `ClientBlob`).
    4.  Decrypt `ClientBlob` using **File Key** from `Lockbox`.
    5.  Return a `File` handle.
*   `Read(b []byte)`:
    1.  Calculate which Chunk(s) correspond to the requested byte range.
    2.  Lookup Chunk IDs and their associated Public URLs in the Inode's `ChunkManifest`.
    3.  Execute **Staggered Parallel Fetches** (Hedged Requests):
        *   Initiate a download from the primary node.
        *   If the download hasn't finished within a 1-second threshold, initiate a parallel fetch from the next replica.
        *   Repeat until all replicas are exhausted or a download succeeds.
    4.  Upon the first successful download, cancel all remaining parallel requests for that chunk.
    5.  Decrypt chunk in memory and copy to `b`.

*   **Data File API (`ReadDataFile` / `SaveDataFile`)**
    *   `ReadDataFile(ctx, name, data any)`: Reads and unmarshals a passphrase-encrypted JSON/Gob file from the namespace.
    *   `SaveDataFile(ctx, name, data any)`: Marshals and writes a file using the **Atomic Swap Protocol** (exclusive filename lease + new inode creation).
*   **Atomic Multi-File Operations**
    *   `OpenManyForUpdate(ctx, paths []string, targets []any) (commit func(bool), error)`: Provides transactional write semantics across multiple files.
    *   `ReadDataFiles(ctx, paths []string, targets []any) error`: Provides a point-in-time consistent snapshot of multiple files by using shared filename-based leases during the path-resolution phase.

### 6.2 REST API
Communication between the Client and Cluster uses JSON over HTTP/2. The Metadata Server requires Layer 7 End-to-End Encryption (Sealing) for all mutations.

> **Full API Catalog:** For exhaustive documentation of every endpoint, request/response schema, and error code, refer to [SERVER-API.md](SERVER-API.md).

### 6.3 Identity & Authentication
*   **Identity Registry:**
    *   **Users:** `HMAC(Email) -> Public Keys`. No PII (names/emails) stored.
    *   **Groups:** `UUID -> Public Keys`.
*   **User Registration:**
    *   **Federated Identity:** Users must register via `POST /v1/user/register` providing a valid OIDC ID Token (JWT). The server calculates `HMAC(email)` using the internal Cluster Secret and registers the keys against this hash. The email is discarded immediately.
    *   **Automated Configuration:** The cluster leader is configured with an OIDC Discovery URL. It exposes the necessary authorization and token endpoints to clients via the `/v1/auth/config` endpoint, enabling zero-config onboarding.
*   **Authentication:**
    *   **Client Auth:** Client authenticates with Metadata Server via Sealed Tokens (signed/encrypted) proving identity.
    *   **Chunk Access:** Client authenticates with Data Nodes via Signed Capability Tokens issued by Metadata Server.

### 6.4 FUSE Implementation Details
To provide high-fidelity POSIX compatibility, DistFS implements the following specialized operations:
*   **`Fsync`**: Ensures that all dirty data for a file is committed to the data nodes and the inode metadata is updated on the Raft leader before returning.
*   **`Statfs`**: Reports cluster-wide storage capacity and user-specific remaining quota (MaxBytes/MaxInodes).
*   **`Forget`**: Handles kernel-level node eviction to prevent memory leaks in the client during long-running mounts.
*   **Incremental `ReadDir`**: Uses streaming directory entries to support large directories without blocking on a single massive metadata fetch.

**Out of Scope: `CopyFileRange`**
Server-side copying is currently not supported because DistFS maintains Zero-Knowledge privacy. Since every file is encrypted with a unique symmetric key, copying data between files would require the server to decrypt and re-encrypt the content (or reuse keys, which weakens the security model), violating the core security mandate. All copies must be performed client-side.

## 7. Cluster Architecture & Operations

### 7.1 Network Topology & Ports
The backend utilizes three primary ports for its operations, ensuring separation of concerns:
1.  **Public HTTP Port (`--addr`):** Client-facing API port (default `:8080`).
2.  **Internal HTTP Port (`--cluster-addr`):** Dedicated mTLS-secured API for inter-node communication (default `:9090`).
3.  **Raft Port (`--raft-bind`):** Internal TCP transport for Raft consensus traffic (default `:8081`).

**Port Advertisement:**
To support containerized and NATed environments, nodes must explicitly advertise their public addresses:
*   `--cluster-advertise`: Public `host:port` for the internal cluster API.
*   **`--raft-advertise`**: Public `host:port` for Raft traffic.

### 7.2 Node Identity & Security (Zero-Trust)
The cluster employs a **Zero-Trust security model** where no node is inherently trusted.
*   **Node Key:** Each node generates a persistent **Ed25519 private key** (`node.key`) on first startup.
*   **Node ID:** The unique Raft Node ID is derived from the first 8 bytes of the public key.
*   **Mutual TLS (mTLS):** All inter-node communication (Cluster API and Raft) is secured via mTLS. Nodes exchange self-signed certificates signed by their `node.key`. Connections are only accepted if the peer's public key is in the authorized `NodeMeta` list.

### 7.3 Trust Bootstrapping (TOFU)
To solve the initial trust problem, new nodes use **Trust On First Use (TOFU)**:
1.  **Fresh State:** A node with no history enters TOFU mode.
2.  **Temporary Trust:** It temporarily accepts a connection from an unknown peer (assumed to be the Cluster Leader).
3.  **State Acquisition:** The node receives the authoritative `NodeMeta` (list of trusted public keys) from the Leader.
4.  **Strict Mode:** Upon initialization, the node permanently switches to **Strict Mode**, enforcing the authorized key list for all future connections.

### 7.4 Cluster Management & Admin Console
DistFS provides a comprehensive administrative interface for cluster operators. To ensure maximal security, management is performed via an interactive **Command-line User Interface (CUI)** within the `distfs` binary.

*   **PQC-Powered Authorization:** Access to administrative functions is controlled by individual user identities rather than a shared secret.
    *   **Admin Registry:** The FSM maintains a persistent `admins` bucket. 
    *   **Bootstrap:** The first user to register with a new cluster is automatically granted administrative privileges.
    *   **Promotion:** Existing admins can promote other users to admin status via signed Raft commands.
*   **Secure Authentication:** Admins authenticate using their standard PQC Identity Keys. All admin requests are **SealedRequests** (Layer 7 E2EE), ensuring that actions are cryptographically signed and non-repudiable.
*   **Management Features:**
    *   **Overview:** Real-time visibility into Raft state, leadership, and commit index.
    *   **User Management:** Monitor anonymized usage (`TotalBytes`, `InodeCount`) and adjust quotas.
    *   **Group Management:** Monitor group usage and manage group resource quotas.
    *   **Node Operations:** Monitor storage node health, join new nodes, or decommission existing ones.
    *   **Metadata Overrides (Namespace Management):**
        *   **admin-chown:** Reassign ownership of a path to a different user (by email). 
            *   **LIMITATION:** This modifies the UID/GID for quota and namespace purposes. It **DOES NOT** grant the new owner access to encrypted file data, as the administrator cannot re-key the Lockbox.
        *   **admin-chmod:** Modify permission bits of any path to resolve lockouts or reclaim names.
            *   **LIMITATION:** This only modifies metadata visibility. It **DOES NOT** grant access to encrypted data if the requester is not already a recipient in the Lockbox.
    *   **Distributed Lock Visibility:** Real-time monitoring of active Inode leases and lock ownership to diagnose contention.
    *   **System Metrics:** Visualize cluster performance, including Raft commit latency, I/O throughput, and disk utilization across nodes.
    *   **Blind Lookup:** Resolve a plaintext email to its HMAC Hash to locate specific user records.
*   **Deployment:** The admin console communicates with the standard API port. Because it relies on Layer 7 E2EE and PQC signatures, it does not require mTLS for client access.

### 7.5 Request Forwarding
*   Write requests sent to Follower nodes are automatically forwarded to the Leader via the Internal Cluster API.
*   Read requests can be served locally by Followers (using Read-Index for consistency).

### 7.6 Cluster Bootstrapping and Snapshot Transfer
DistFS utilizes a two-tiered trust model to resolve the circular dependency between FSM encryption and node bootstrapping.

1.  **Tier 1: Local Node Vault:**
    *   On initial bootstrap, the Leader generates a high-entropy **ClusterSecret** and stores it in its local node-local encrypted vault (protected by the node's unique `MasterKey`).
    *   During the `Join` handshake, the Leader retrieves the `ClusterSecret` and encapsulates it for the joining node's Public Encryption Key.
    *   The joining node decrypts and persists the `ClusterSecret` in its own local Tier 1 vault.
2.  **Tier 2: Cluster Root of Trust (FSM):**
    *   The BoltDB `system` bucket contains the cluster-wide root metadata, including the **FSM KeyRing**.
    *   Values in the `system` bucket are encrypted using a key derived from the `ClusterSecret`.
    *   All other buckets (Inodes, Users, Groups) are encrypted using the rotating `FSM KeyRing`.
3.  **Snapshot Portability:**
    *   When a Raft snapshot is transferred to a Follower, the `system` bucket remains encrypted with the `ClusterSecret`.
    *   Since every authorized Follower has the `ClusterSecret` in its local Tier 1 vault, it can immediately decrypt the root anchors and bootstrap its local FSM state.
