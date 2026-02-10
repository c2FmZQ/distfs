# DistFS Implementation Plan

This document outlines the comprehensive, step-by-step plan to build **DistFS**, a secure, distributed, end-to-end encrypted file system.

**Quality Standards:**
*   **Test Coverage:** Minimum 80% for every package.
*   **Testing Strategy:** Strict TDD (Test-Driven Development) workflow. No code is committed without a failing test first.
*   **Linting:** `golangci-lint` with strict settings enabled from Day 1.
*   **Documentation:** All public APIs must have GoDoc.

---

## Phase 1: Cryptographic Primitives (The "Zero-Knowledge" Bedrock)
**Goal:** Implement the client-side cryptographic layer. The server will never see these keys in plaintext.

*   **Step 1.1: Post-Quantum Identity Keys**
    *   **Action:** Implement wrappers for **CRYSTALS-Dilithium** (Digital Signatures). Define `UserIdentity` struct (Private Key + Public Key ID).
*   **Step 1.2: Hybrid Encryption Scheme (KEM+DEM)**
    *   **Action:** Implement wrappers for **CRYSTALS-Kyber** (Key Encapsulation) combined with **AES-256-GCM**.
*   **Step 1.3: The Lockbox**
    *   **Action:** Implement the `Lockbox` struct: `map[UserID]EncryptedFileKey`.
*   **Step 1.4: Chunk Encryption (Content-Addressable)**
    *   **Action:** Implement `ChunkCrypter`.

---

## Phase 2: The Storage Node (Unified)
**Goal:** Create the unified "dumb" storage layer that stores encrypted blobs.

*   **Step 2.1: Storage Engine**
    *   **Action:** Implement `Store` interface backed by the local filesystem (`data/chunks/`).
*   **Step 2.2: Integrity Scrubber**
    *   **Action:** Implement a background worker that walks the chunk directory.
*   **Step 2.3: Data API (HTTP/2)**
    *   **Action:** Implement `PUT /v1/data/{chunk_id}` and `GET /v1/data/{chunk_id}`.

---

## Phase 3: The Metadata Role (Raft Core)
**Goal:** Port and adapt the distributed consensus engine.

*   **Step 3.1: Raft Infrastructure**
    *   **Action:** Port `RaftManager`, `EncryptedLogStore`.
*   **Step 3.2: FSM & Inode Model**
    *   **Action:** Define `Inode` struct.
    *   **Update:** Implement Directory Structure (`Children` map) in FSM.
*   **Step 3.3: LinkSnapshotStore**
    *   **Action:** Port/Adapt Snapshot logic (`MetadataSnapshot`).
*   **Step 3.4: Metadata API**
    *   **Action:** Implement `POST /v1/meta/inode` and `GET /v1/meta/inode/{id}`.
    *   **Action:** Implement Directory API (`Add/Remove Entry`).

---

## Phase 4: Client Library (The Integrator)
**Goal:** Bind Crypto, Networking, and Metadata into a usable Go library.

*   **Step 4.1: Client Connectivity**
    *   **Action:** Implement `Client` struct with mTLS/JWT management.
*   **Step 4.2: File Write Logic**
    *   **Action:** Implement `WriteFile` pipeline (Chunk -> Encrypt -> Upload -> Inode).
*   **Step 4.3: File Read Logic**
    *   **Action:** Implement `NewReader` (Streaming).
*   **Step 4.4: fs.FS Implementation**
    *   **Action:** Implement `Open`, `Stat`, `ReadDir`.
    *   **Update:** Implement `ResolvePath` using Metadata Directory API.

---

## Phase 5: Replication & Distributed Reliability
**Goal:** Turn the single-node logic into a resilient cluster.

*   **Step 5.1: Write Pipeline (Replication)**
    *   **Action:** Update Data Node `PUT` handler to forward data.
*   **Step 5.2: Node Registry**
    *   **Action:** MetaNode tracks DataNode heartbeats.
*   **Step 5.3: Replication Repair**
    *   **Action:** Implement "Under-replicated Chunk" detection.
*   **Step 5.4: Access Control (Capability Tokens)**
    *   **Action:** Implement `IssueToken` (Metadata) and `VerifyToken` (Data).
    *   **Action:** Update Client to request/use Tokens.

---

## Phase 6: Identity & Sharing
**Goal:** Implement the Group and User management logic.

*   **Step 6.1: Identity Registry**
    *   **Action:** Implement `User` and `Group` in the Raft FSM.
*   **Step 6.2: Authentication**
    *   **Action:** Implement Client-Side Auth (Sealed Tokens) middleware.

---

## Phase 7: Polish & Interfaces
**Goal:** Make it usable for humans and OSs.

*   **Step 7.1: CLI Tool**
    *   **Action:** Build `distfs` binary.
*   **Step 7.2: FUSE Adapter**
    *   **Action:** Implement `fuse.FileSystem` interface.

---

## Phase 8: POSIX Compliance (NFS-style)
**Goal:** Achieve high-fidelity POSIX compliance to support standard applications.

*   **Step 8.1: Metadata Schema Upgrade**
    *   **Action:** Replace `OwnerID`/`GroupID` strings with `uint32` UID/GID.
    *   **Action:** Add `MTime`, `CTime` (excluding `ATime`), `NLink` to `Inode`.
    *   **Action:** Implement automatic random UID/GID assignment for new users/groups.
*   **Step 8.2: FUSE Operations Upgrade**
    *   **Action:** Implement `Rename` (Atomic move).
    *   **Action:** Implement `Unlink` / `Rmdir` (Deletion).
    *   **Action:** Implement `Symlink` / `Readlink`.
    *   **Action:** Implement `Setattr` (`chmod`, `chown`, `truncate`, `utimes`).
    *   **Action:** Implement `Link` (Hard Links).

---

## Phase 9: Cluster Management & Maintenance
**Goal:** Advanced operations.

*   **Step 9.1: Cluster API**
    *   **Action:** `GET /v1/cluster/status`.
    *   **Action:** `POST /v1/cluster/join` (Add Voter/NonVoter).
*   **Step 9.2: Key Rotation**
    *   **Action:** Implement Log Key Rotation on Snapshot.
*   **Step 9.3: Request Forwarding**
    *   **Action:** Forward write requests from Follower to Leader.

---

## Phase 10: Performance & Lifecycle Management
**Goal:** Optimize scalability and reclaim storage.

*   **Step 10.1: Chunk Manifest Pagination**
    *   **Action:** [Done] Refactor `Inode` to store `ChunkManifest` as a list of reference IDs.
    *   **Action:** [Done] Implement `ChunkPage` storage in FSM to support 100GB+ files.
*   **Step 10.2: Parallel Read-Ahead**
    *   **Action:** [Done] Implement a background worker in `FileReader` to pre-fetch upcoming chunks.
*   **Step 10.3: Data Garbage Collection (GC)**
    *   **Action:** [Done] Add `DELETE /v1/data/{chunk_id}` to the Data Node API.
    *   **Action:** [Done] Implement a metadata-driven GC worker that identifies and deletes unreferenced chunks from Data Nodes.