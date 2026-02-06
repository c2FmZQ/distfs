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
*   **Node Security:** Leveraging lessons from `skorekeeper`, all data stored on MetaNodes and DataNodes (Raft logs, snapshots, chunk files) is encrypted *at rest* using a **Node-Local Master Key** (AES-GCM). This protects against physical disk theft but does not grant the node access to the E2EE user data.

### 3.2 Key Hierarchy & Cryptography
Users control their identity via an asymmetric key pair using **Post-Quantum Cryptography (PQC)** algorithms (e.g., CRYSTALS-Kyber for encapsulation, CRYSTALS-Dilithium for signatures) to future-proof against quantum threats.

1.  **User Identity Key:** Public key maps to the User ID. Private key signs requests.
    *   **User ID:** A random UUID assigned by the Cluster Leader upon first registration. This decouples the permanent User ID from the rotateable cryptographic keys.
2.  **Group Identity Key:** A persistent Public/Private key pair representing a Group. The Group Private Key is shared among group members via the Group Lockbox.
3.  **File Key (FK):** A random symmetric key generated for *each* file. Encrypts the file content.
4.  **Lockbox:**
    *   **File Lockbox:** Stores the `File Key` encrypted for the Owner and/or the assigned Group.
    *   **Group Lockbox:** Stores the `Group Private Key` encrypted for each member's Public Key.

---

## 4. Metadata Layer (MetaNodes)

This layer reuses the distributed consensus architecture from `skorekeeper`.

### 4.1 State Machine (FSM)
The Raft FSM stores the "Inode" table.
*   **Inode Structure:**
    *   `ID` (UUID)
    *   `Type` (File | Directory)
    *   `ParentID` (UUID)
    *   `OwnerID` (UUID)
    *   `GroupID` (UUID)
    *   `Mode` (Unix Permission Bits, e.g., 0755)
    *   `EncryptedName` ([]byte)
    *   `ChunkManifest` (List of Chunk IDs + DataNode locations)
    *   `Lockbox` (Map[ID] -> EncryptedKey)
    *   `Version` (Lamport Clock / Raft Index)

### 4.2 Persistence & Snapshots
*   **Engine:** Hashicorp Raft with BoltDB (reusing `skorekeeper` config).
*   **Snapshot Strategy:** Use the `LinkSnapshotStore` pattern implemented in `skorekeeper`.
    *   **O(1) Snapshots:** The FSM creates hardlinks of the underlying BoltDB or JSON structures instead of copying data.
    *   **Startup:** `NoSnapshotRestoreOnStart = true`. MetaNodes rely on disk persistence and only replay trailing logs on startup to ensure fast recovery.

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
2.  **Allocate:** Client requests allocation for `ChunkID`. The Leader selects 3 target nodes.
3.  **Push:** Client pushes the *Encrypted* chunk to the **Primary Node**.
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
*   Nodes store chunks as flat files: `data/chunks/{chunk_id}`.
*   **Self-Validation:** Chunks are content-addressed (Hash of encrypted content).

### 5.5 Atomicity & Consistency
*   **Chunk Level:** Writes to DataNodes are atomic. A chunk is either fully written and validated or rejected. Replacements use new Chunk IDs or versioned writes; existing chunks are immutable.
*   **File Level:** File updates are transactional via Raft. The client uploads new chunks first, then sends a single `UpdateManifest` command to the MetaNode. This atomically swaps the old chunk list for the new one, ensuring readers never see a partial update.

---

## 6. Client Library & API

### 6.1 Go Client (`fs.FS`)
The client library implements `io.fs.FS` and `io.fs.File`.

*   `Open(name string)`:
    1.  Traverse directory tree (fetching metadata).
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
    *   `POST /v1/meta/inode` (Create)
    *   `GET /v1/meta/inode/{id}` (Read Metadata)
    *   `PUT /v1/meta/lockbox` (Share/Revoke)
*   **Data API:**
    *   `PUT /v1/data/{chunk_id}` (Write Chunk)
    *   `GET /v1/data/{chunk_id}` (Read Chunk)

### 6.3 Identity & Authentication
*   **Identity Registry:**
    *   **Users:** `UUID -> Public Key`. Email addresses are mapped to UUIDs via a secondary index. User IDs are immutable random UUIDs generated by the Leader on creation.
    *   **Groups:** `UUID -> Public Key`. Group IDs are random UUIDs generated on creation.
*   **Group Management API:**
    *   `POST /v1/group` (Create Group)
    *   `POST /v1/group/{id}/member` (Add Member)
        *   *Payload:* The **Group Private Key** encrypted with the new member's Public Key. This requires the caller (Admin) to perform decryption/re-encryption client-side.
    *   `DELETE /v1/group/{id}/member` (Remove Member)
*   **Authentication Flow (Challenge-Response):**
    1.  **Login:** Client requests a challenge for their email.
    2.  **Sign:** Server sends a random nonce. Client signs it with their Private Key.
    3.  **Verify:** Client sends the signed nonce. Server verifies it against the registered Public Key.
    4.  **Token:** Server issues a **JWT** (JSON Web Token) for the session.
*   **API Access:** Clients include the JWT in the `Authorization: Bearer` header for all subsequent API calls.

### 6.4 POSIX Compliance & FUSE (Nice-to-Have)
To enable mounting DistFS as a local drive, a FUSE (Filesystem in Userspace) adapter will be developed.

*   **Command:** `distfs mount /mnt/my-secure-drive`
*   **Architecture:** The FUSE client acts as a translation layer, converting POSIX syscalls (`open`, `read`, `write`, `getattr`) into DistFS API calls.
*   **Challenges & Compromises:**
    *   **Latency:** Random writes to large files will require download-decrypt-modify-encrypt-upload cycles for the affected chunk(s). The client will implement aggressive write-back caching to mitigate this.
    *   **Semantics:** DistFS is eventually consistent for data replication but strongly consistent for metadata. POSIX apps expecting instant data visibility across nodes might need adaptation.
    *   **Permissions:** DistFS uses cryptographic ACLs, which map imperfectly to UNIX `rwx` bits. The FUSE layer will enforce DistFS permissions logic while presenting a simplified view to the OS.

---

## 7. Reused Components from Skorekeeper

We will directly port the following tested sub-systems:

1.  **Raft Lifecycle:** The `RaftManager` struct, including bootstrap, join, and shutdown logic.
2.  **Encrypted Log Store:** `EncryptedLogStore` decorator for BoltDB to ensure Raft logs are encrypted on disk.
3.  **Encrypted Stable Store:** `EncryptedStableStore` for metadata encryption.
4.  **Key Ring:** The `KeyRing` mechanism for rotating server-side persistence keys.
5.  **LinkSnapshotStore:** The O(1) snapshotting implementation for handling FSM snapshots efficiently.
6.  **mTLS Config:** The internal cluster communication setup for secure node-to-node talk.

## 8. Sharing Model (POSIX + Groups)

Access control aligns with the Unix permission model, enforcing security via both Raft logic (Metadata) and Cryptography (Data).

### 8.1 Permissions (Metadata)
Every Inode has an `OwnerID`, `GroupID`, and `Mode` (e.g., `rwxr-x---`).
*   **Authorization Check:** The MetaNode enforces standard Unix logic:
    1.  If User == Owner, use User Bits.
    2.  Else if User in Group, use Group Bits.
    3.  Else use Other Bits.

### 8.2 Cryptographic Access (Data)
To read the file content, the user must be able to decrypt the `File Key`.
1.  **File Lockbox:** Contains the `File Key` encrypted for the **Owner's Public Key** and the **Group's Public Key**.
2.  **Group Lockbox:** If accessing via Group, the user retrieves the `Group Private Key` from the Group Lockbox (where it is encrypted for the user's personal Public Key).
3.  **Decryption Chain:**
    *   *Owner:* `Private Key` -> Decrypt `File Key`.
    *   *Group Member:* `Private Key` -> Decrypt `Group Private Key` -> Decrypt `File Key`.

### 8.3 Revocation
*   **Remove Member:** The Group Admin removes the user's entry from the Group Lockbox.
    *   *Lazy:* The evicted user retains the old Group Private Key (and thus file access) until keys are rotated.
    *   *Strict:* Admin rotates the Group Key, re-encrypts it for remaining members, and re-encrypts file keys for sensitive files.

## 9. Failure Modes

*   **MetaNode Failure:** Leader election handles it (Raft).
*   **DataNode Failure:**
    *   MetaNode tracks "Heartbeats" from DataNodes.
    *   If a DataNode is dead, MetaNode identifies "Under-replicated Chunks".
    *   MetaNode instructs remaining replicas to copy chunks to a new DataNode.
