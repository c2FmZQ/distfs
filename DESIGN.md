# DistFS: Design Document

DistFS is a secure, distributed file system built on a zero-knowledge architectural model. It provides a strongly consistent metadata layer and a horizontally scalable data storage layer, ensuring that all user content and sensitive metadata remain opaque to the storage infrastructure.

## 1. Core Mandates

The design of DistFS is governed by four primary mandates:
1.  **Zero-Knowledge Privacy:** The server infrastructure never possesses plaintext user data or filenames. All encryption and decryption occur exclusively at the client.
2.  **Consensus-Driven Metadata:** File system state and namespace are managed by a Raft consensus cluster to ensure strong consistency and high availability.
3.  **Scalable Data Distribution:** Content is sharded into fixed-size, encrypted chunks distributed across "dumb" storage nodes.
4.  **POSIX Fidelity:** The system provides a high-fidelity POSIX interface via FUSE, supporting standard applications and workflows.

## 2. System Architecture

DistFS employs a unified node architecture where a single binary can perform both metadata and data storage roles.

```mermaid
graph TD
    Client[DistFS Client / FUSE] -- Sealed JSON/HTTP2 -- MetadataGroup[Metadata Cluster Raft Group]
    Client -- Encrypted Chunks/HTTP2 -- DataNodes[Data Nodes Pool]
    MetadataGroup -- mTLS/Internal -- DataNodes
    
    subgraph Metadata Role
        Raft[Raft Consensus]
        BoltDB[BoltDB FSM]
    end
    
    subgraph Data Role
        Store[Chunk Store]
        Scrubber[Integrity Scrubber]
    end
```

### 2.1 The Unified Node
While nodes are logically separated into roles, the `storage-node` binary implements both. In a typical deployment, 3-5 nodes participate in the Raft group (Metadata Role), while all nodes in the cluster participate in chunk storage (Data Role).

## 3. Security Model

### 3.1 Cryptographic Bedrock
DistFS utilizes Post-Quantum Cryptography (PQC) alongside established symmetric primitives:
*   **Asymmetric:** ML-KEM-768 (Crystals-Kyber) for key encapsulation and Ed25519 for digital signatures.
*   **Symmetric:** AES-256-GCM for data encryption (DEM).
*   **KDF:** Argon2id for local configuration protection.

### 3.2 Key Hierarchy
1.  **User Identity Key:** A PQC pair registered during onboarding. The public key derives the User ID.
2.  **Epoch Keys (Cluster Identity):** Periodically rotating PQC KEM keys shared across the metadata cluster. Used for Layer 7 E2EE.
3.  **File Key (FK):** A unique symmetric AES-256 key generated for *every* file.
4.  **Lockbox:** A multi-recipient metadata field within each Inode containing the File Key encrypted for the owner, assigned group, or "world" recipients.

### 3.3 Layer 7 End-to-End Encryption (Sealing)
Beyond transport-layer TLS, all metadata mutations and sensitive queries are "sealed":
*   **SealedRequest:** Client encrypts the payload for the cluster's active Epoch Key and signs it with their Identity Key.
*   **SealedResponse:** Server encrypts the response for the client's registered public key.
This ensures that intermediate proxies (Load Balancers, WAFs) cannot observe or manipulate the file system structure.

## 4. Metadata Layer

### 4.1 Finite State Machine (FSM)
The metadata state is stored in a BoltDB-backed FSM, replicated via Raft. The schema includes:
*   **Inodes:** Representing files, directories, and symlinks.
*   **Dark Registry:** User and Group records. IDs are `HMAC-SHA256(Email, ClusterSecret)` to prevent PII exposure.
*   **Keysync:** Encrypted backups of client configurations.

### 4.2 Namespace Management
Directories are stored as Inodes containing a map of `HMAC(Name, ParentKey) -> InodeID`. This allows the server to manage the directory tree and perform garbage collection without knowing the plaintext names of files or folders.

### 4.3 Distributed Locking (Leases)
DistFS implements a lease-based locking mechanism to prevent concurrent write conflicts.
*   Clients acquire a time-bound lease on an Inode ID or path.
*   The FSM atomically grants leases within Raft transactions, providing deadlock prevention.
*   Leases are automatically released upon session heartbeat timeout or explicit client release.

## 5. Data Layer

### 5.1 Chunking and Inlining
*   **Small File Inlining:** Files smaller than 4KB are encrypted and stored directly within the Inode's `InlineData` field, eliminating storage node round-trips.
*   **Chunking:** Larger files are split into fixed 1MB chunks. Chunks are content-addressed by the hash of their *encrypted* content.

### 5.2 Replication Pipeline
DistFS uses a parallel fan-out replication model. When a client uploads a chunk:
1.  The client requests allocation from the Metadata Leader.
2.  The Leader selects $N$ nodes (default 3) based on consistent hashing and disk space.
3.  The client pushes the chunk to the primary node, which concurrently replicates the data to all secondary nodes.
4.  Success is only returned to the client once all $N$ replicas are acknowledged.

### 5.3 Reliability
*   **Integrity Scrubber:** A background process on each node verifies the checksums of local chunks. Corrupted chunks are quarantined (renamed to `.corrupted`) and marked for repair.
*   **Replication Monitor:** The Metadata Leader periodically scans Inodes to identify under-replicated chunks and triggers restorative replication.

## 6. Client Logic and POSIX Compliance

### 6.1 Path Resolution and Caching
Path resolution is $O(	ext{depth})$ as the client must traverse and decrypt each directory component. To mitigate this, the client implements a thread-safe `PathCache` that maps absolute paths to `(InodeID, FileKey)`. Cache entries are strictly validated against the server's Inode state (ParentID/NameHMAC) before use.

### 6.2 Differential Synchronization (Fsync)
To provide efficient `fsync` support without full file re-uploads, the client tracks modified 1MB pages in memory.
1.  **Write:** The client performs read-modify-write on 1MB pages in RAM.
2.  **Flush/Fsync:** Only the "dirty" pages are re-encrypted and uploaded. The Inode's manifest is then atomically updated on the Raft leader to point to the new chunk IDs for those regions while retaining references to unchanged chunks.

### 6.3 Tail Latency Mitigation (Hedged Reads)
The client implements **Hedged Requests** for data retrieval. It initiates a fetch from the primary replica and, if it fails to return within a 1-second threshold, starts staggered parallel fetches from remaining replicas. The first successful response cancels all pending requests.

## 7. Operational Design

### 7.1 Unified Onboarding
Onboarding is handled via an OIDC Device Flow. The client authenticates with a federated provider, initializes its PQC keys, and performs a zero-knowledge backup of its configuration to the metadata cluster, enabling seamless multi-device usage.

### 7.2 Cluster Management
A web-based dashboard, built with vanilla JavaScript and protected by mTLS and a cluster secret, provides real-time visibility into:
*   Raft cluster health and leadership.
*   Node capacity and usage.
*   Anonymized user accounting and quota enforcement.
*   Lease state.

---
*This document reflects the implementation as of Phase 29. For upcoming features and the long-term roadmap, see [DISTFS-PLAN.md](DISTFS-PLAN.md).*
