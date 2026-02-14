# DistFS: Secure Distributed File System
**High-Level Design Document**

## 1. Overview
DistFS is a distributed, end-to-end encrypted file system designed for zero-knowledge privacy. It separates metadata management (strongly consistent via Raft) from data storage (scalable via chunked distribution). The system is designed to provide `fs.FS` compatibility for Go clients while ensuring that the storage providers (nodes) cannot read the user's data or metadata.

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
    *   **Isolation:** Encryption keys are node-local and never shared across the network.
*   **Key Rotation:** The encryption key for Raft logs MUST be rotated after every snapshot.

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

### 3.5 Multi-Device Key Synchronization (Zero-Knowledge Sync)
To support seamless multi-device usage without compromising the "Trust No One" model, DistFS allows users to store a recovery blob on the server.
1.  **Client-Side Preparation:** The client encrypts its `config.json` (containing the PQC Identity and Encryption keys) using a user-provided passphrase and **Argon2id** KDF.
2.  **Passphrase-Encrypted Blob:** The server only ever sees the opaque ciphertext (`KeySyncBlob`).
3.  **Synchronization Protocol:**
    *   **Retrieval (New Device):** The user authenticates via OIDC (JWT). The server returns the blob. The user enters their passphrase locally to decrypt and install their keys.
    *   **Storage/Update (Existing Device):** To prevent unauthorized overwrites, the client must provide a valid `Session-Token` and use **Layer 7 E2EE (Sealing)**. This proves the user already knows the current key before they can change the sync blob.

### 3.6 Secure Passphrase Entry (Pinentry)
To enhance security during passphrase entry, DistFS supports the **Assuan protocol** via the `pinentry` suite of tools.
1.  **Standard Protocol:** The client communicates with `pinentry` binaries (e.g., `pinentry-curses`, `pinentry-qt`, `pinentry-mac`) to securely capture user passphrases.
2.  **Environment Integration:** Supports `GPG_TTY` for terminal-based entry and respects `~/.gnupg/gpg-agent.conf` configurations.
3.  **Opt-in Usage:** Enabled via the `--use-pinentry` flag in CLI and FUSE tools.
4.  **Hardened Implementation:** Validates input environments and avoids insecure logging of captured passphrases.

---

## 4. Metadata Layer (MetaNodes)

This layer reuses the distributed consensus architecture from `skorekeeper`.

### 4.1 State Machine (FSM)
The Raft FSM stores the "Inode" table and Directory Structure.
*   **User Structure:**
    *   `ID` (HMAC Hash)
    *   `UID` (POSIX UID)
    *   `Keys` (Sign/Enc)
    *   `Usage` (Struct: `TotalBytes`, `InodeCount`)
    *   `Quota` (Struct: `MaxBytes`, `MaxInodes`)
*   **Inode Structure:**
    *   `ID` (UUID)
    *   `Type` (File | Directory)
    *   `ParentID` (UUID)
    *   `OwnerID` (HMAC Hash)
    *   `GroupID` (UUID)
    *   `Mode` (Unix Permission Bits, e.g., 0755)
    *   `Size` (File size in bytes)
    *   `EncryptedName` ([]byte)
    *   `Lockbox` (Map[ID] -> EncryptedKey)
    *   `Version` (Lamport Clock / Raft Index)
*   **Directory Structure:** The Metadata Layer MUST know the file system hierarchy to enforce permissions and perform Garbage Collection.
    *   **Directory Inodes:** Store a list of children: `EncryptedName -> InodeID`. This allows traversal and GC traversing without knowing plaintext names.
    *   **File Inodes:** Store `ChunkManifest` (List of Chunk IDs + DataNode locations).
    *   **Garbage Collection:** Orphaned Inodes and Chunks (not referenced by any live Inode) are garbage collected.

### 4.2 Persistence & Snapshots
*   **Engine:** Hashicorp Raft with BoltDB (reusing `skorekeeper` config).
*   **Snapshot Strategy:** Use `MetadataSnapshot` (Streaming BoltDB).
    *   **Fast Startup:** `NoSnapshotRestoreOnStart = true`. MetaNodes rely on disk persistence and only replay trailing logs on startup to ensure fast recovery.

### 4.3 Consistency
*   All metadata changes (Create, Delete, Share, Append) go through the Raft Leader.
*   Reads can be served by Followers with `Index` verification (Read-Index) for scalability.

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
*   **File Level:** File updates are transactional via Raft. The client uploads new chunks first, then sends a single `UpdateManifest` command to the MetaNode. This atomically swaps the old chunk list for the new one, ensuring readers never see a partial update.

### 5.6 Access Control (Capability Tokens)
Data Nodes enforce permissions using **Capability Tokens** issued by the Metadata Leader.
*   **Flow:**
    1.  Client requests access to File X from Metadata Leader.
    2.  Leader checks permissions (ACL/Group).
    3.  Leader issues a time-bound **Signed Token** granting READ/WRITE access to the specific Chunk IDs associated with File X.
    4.  Client presents Token to Data Node.
    5.  Data Node verifies signature and expiry before serving data.

---

## 6. Client Library & API

### 6.1 Go Client (`fs.FS`)
The client library implements `io.fs.FS` and `io.fs.File`.

*   `Open(name string)`:
    1.  Resolve path by traversing Directory Inodes (fetching `Children`).
    2.  Decrypt directory names locally to find path components.
    3.  Fetch file metadata (Lockbox + Manifest).
    4.  Decrypt File Key.
    5.  Return a `File` handle.
*   `Read(b []byte)`:
    1.  Calculate which Chunk(s) correspond to the requested byte range.
    2.  Fetch chunk(s) from nearest DataNode (HTTP GET).
    3.  Decrypt chunk in memory.
    4.  Copy to `b`.

### 6.2 REST API
Communication uses JSON over HTTP/2 (or gRPC).

*   **Meta API:**
    *   `POST /v1/meta/inode` (Create/Update Inode)
    *   `GET /v1/meta/inode/{id}` (Read Metadata)
    *   `PUT /v1/meta/directory/{id}/entry` (Add/Remove Child)
    *   `POST /v1/meta/allocate` (Allocate Chunk Targets)
*   **Data API:**
    *   `PUT /v1/data/{chunk_id}` (Write Chunk)
    *   `GET /v1/data/{chunk_id}` (Read Chunk)

### 6.3 Identity & Authentication
*   **Identity Registry:**
    *   **Users:** `HMAC(Email) -> Public Keys`. No PII (names/emails) stored.
    *   **Groups:** `UUID -> Public Keys`.
*   **User Registration:**
    *   **Federated Identity:** Users must register via `POST /v1/user/register` providing a valid OIDC ID Token (JWT). The server calculates `HMAC(email)` using the internal Cluster Secret and registers the keys against this hash. The email is discarded immediately.
*   **Authentication:**
    *   **Client Auth:** Client authenticates with Metadata Server via Sealed Tokens (signed/encrypted) proving identity.
    *   **Chunk Access:** Client authenticates with Data Nodes via Signed Capability Tokens issued by Metadata Server.

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

### 7.4 Cluster Management Dashboard
The `/api/cluster` endpoint provides a web-based dashboard for operators, built with **Vanilla JS and CSS** (no external frontend dependencies) to ensure lightweight, secure deployment.

*   **Access Control:** Protected by the `X-Raft-Secret` header.
*   **User Management (Shadow Dashboard):**
    *   **Accounting:** Real-time view of storage usage (`TotalBytes`, `InodeCount`) per anonymized User ID.
    *   **Blind Lookup:** An admin tool to resolve a plaintext email to its HMAC Hash (using the server's internal secret) to locate specific user records for support.
    *   **Quota Management:**
        *   **Templates:** Operators can define "Quota Templates" (e.g., "Basic", "Pro") with default limits.
        *   **Enforcement:** The Metadata Layer rejects writes that exceed the user's assigned quota.
*   **Cluster Health:** View Leader status, peer connectivity, and version information.
*   **Node Operations:** Add/Remove nodes (Join/Drain).

### 7.5 Request Forwarding
*   Write requests sent to Follower nodes are automatically forwarded to the Leader via the Internal Cluster API.
*   Read requests can be served locally by Followers (using Read-Index for consistency).