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
    *   **Tests:** Key generation, Signing, Verification, Serialization/Deserialization.
*   **Step 1.2: Hybrid Encryption Scheme (KEM+DEM)**
    *   **Action:** Implement wrappers for **CRYSTALS-Kyber** (Key Encapsulation) combined with **AES-256-GCM**. This allows encrypting small symmetric keys (File Keys) for specific users.
    *   **Tests:** Encrypt for Public Key, Decrypt with Private Key, fuzz testing with invalid ciphertexts.
*   **Step 1.3: The Lockbox**
    *   **Action:** Implement the `Lockbox` struct: `map[UserID]EncryptedFileKey`. Implement `AddRecipient(pubKey)` and `GetFileKey(privKey)`.
    *   **Tests:** Multi-recipient scenarios, ensuring User A cannot decrypt User B's entry.
*   **Step 1.4: Chunk Encryption (Content-Addressable)**
    *   **Action:** Implement `ChunkCrypter`.
        *   Input: Plaintext `[]byte`, `FileKey`.
        *   Output: `EncryptedChunk`, `ChunkID` (Hash of EncryptedChunk).
        *   Padding: Implement PKCS#7 or similar padding to obscure exact chunk sizes up to the 1MB boundary (or fixed block alignment).
    *   **Tests:** Round-trip encryption, ensuring deterministic `ChunkID` for identical content + key, padding verification.

---

## Phase 2: The Storage Node (Unified)
**Goal:** Create the unified "dumb" storage layer that stores encrypted blobs.

*   **Step 2.1: Storage Engine**
    *   **Action:** Implement `Store` interface backed by the local filesystem (`data/chunks/`).
    *   **Feature:** Atomic writes (write to temp, fsync, rename).
    *   **Tests:** Concurrent writes, disk full simulation, atomic overwrite guarantees.
*   **Step 2.2: Integrity Scrubber**
    *   **Action:** Implement a background worker that walks the chunk directory, calculates SHA-256 of files, and compares them to the filename (`ChunkID`).
    *   **Tests:** Corrupt a file on disk, ensure Scrubber detects and flags it.
*   **Step 2.3: Data API (HTTP/2)**
    *   **Action:** Implement `PUT /v1/data/{chunk_id}` and `GET /v1/data/{chunk_id}`.
    *   **Logic:** Implement "Consistent Hashing" placement check (reject write if not responsible node)?? No, client determines placement. Node accepts if authorized.
    *   **Security:** Verify mTLS Client Certificate (for node-to-node replication) or User JWT (for client uploads).
    *   **Tests:** HTTP integration tests, verifying Content-Length limits and streaming behavior.

---

## Phase 3: The Metadata Role (Raft Core)
**Goal:** Port and adapt the distributed consensus engine.

*   **Step 3.1: Raft Infrastructure**
    *   **Action:** Port `RaftManager`, `EncryptedLogStore`, `EncryptedStableStore` from `skorekeeper`.
    *   **Adaptation:** Remove game-specific logic. Make it generic.
    *   **Tests:** Raft lifecycle tests (Bootstrap, Restart, Leader Election).
*   **Step 3.2: FSM & Inode Model**
    *   **Action:** Define `Inode` struct (ID, ParentID, Lockbox, ChunkManifest). Implement the BoltDB-backed FSM.
    *   **Tests:** Unit tests for FSM `Apply` (Create, Update, Delete). Verify data persistence.
*   **Step 3.3: LinkSnapshotStore**
    *   **Action:** Port `LinkSnapshotStore` for O(1) snapshots.
    *   **Tests:** Verify hardlinks are created, Verify `NoSnapshotRestoreOnStart` behavior (persistence check).
*   **Step 3.4: Metadata API**
    *   **Action:** Implement `POST /v1/meta/inode` and `GET /v1/meta/inode/{id}`.
    *   **Consistency:** Ensure Read-Index or Leader-Only reads for strong consistency.
    *   **Tests:** API tests ensuring metadata persistence across cluster restarts.

---

## Phase 4: Client Library (The Integrator)
**Goal:** Bind Crypto, Networking, and Metadata into a usable Go library.

*   **Step 4.1: Client Connectivity**
    *   **Action:** Implement `Client` struct with mTLS/JWT management.
    *   **Action:** Implement `ConnectionPool` for managing HTTP/2 connections to DataNodes.
*   **Step 4.2: File Write Logic (The Pipeline)**
    *   **Action:** Implement `Alloc -> Encrypt -> Push -> Commit` flow.
    *   **Logic:** Implement padding, chunking (1MB), and parallel uploads.
    *   **Tests:** Mocked DataNodes/MetaNodes. Verify correct sequence of calls.
*   **Step 4.3: File Read Logic**
    *   **Action:** Implement `Read(p []byte)`. Logic to calculate chunk offsets, fetch concurrent chunks, decrypt, and assemble.
    *   **Tests:** Read various file sizes (1KB, 1MB, 100MB). Seek tests.
*   **Step 4.4: fs.FS Implementation**
    *   **Action:** Implement `Open`, `Stat`, `ReadDir`.
    *   **Tests:** Run `testing/fstest` (Go's standard filesystem conformance test suite) against DistFS.

---

## Phase 5: Replication & Distributed Reliability
**Goal:** Turn the single-node logic into a resilient cluster.

*   **Step 5.1: Write Pipeline (Replication)**
    *   **Action:** Update Data Node `PUT` handler to forward data to Secondary/Tertiary nodes if specified in the allocation request.
    *   **Tests:** Setup 3 DataNodes. Write to Primary. Verify file exists on all 3.
*   **Step 5.2: Node Registry & Health**
    *   **Action:** MetaNode tracks DataNode heartbeats.
    *   **Action:** Expose "Cluster Map" to Clients (so they know where to write).
    *   **Tests:** Simulate node death, verify heartbeat timeout logic.
*   **Step 5.3: Replication Repair**
    *   **Action:** Implement "Under-replicated Chunk" detection scanner on Leader.
    *   **Action:** Implement "ReplicateChunk" command sent to DataNodes.
    *   **Tests:** Kill one node. Wait `TBD` minutes. Verify cluster restores redundancy to 3x.
*   **Step 5.4: Node Draining**
    *   **Action:** Implement `POST /v1/node/{id}/drain`.
    *   **Logic:** Iterate all chunks owned by Node X, replicate them to other nodes, then update Manifests.
    *   **Tests:** Write data to Node A. Drain Node A. Verify data exists on Nodes B/C and Metadata points to B/C.

---

## Phase 6: Identity & Sharing (The Social Layer)
**Goal:** Implement the Group and User management logic.

*   **Step 6.1: Identity Registry**
    *   **Action:** Implement `User` and `Group` in the Raft FSM.
    *   **Action:** Implement JWT issuance endpoint (Challenge-Response).
    *   **Tests:** Authentication flows, signature verification.
*   **Step 6.2: Group Management**
    *   **Action:** Implement `CreateGroup`, `AddMember` (requires client-side crypto).
    *   **Logic:** Implement Group Lockbox in FSM (Map[MemberID] -> EncryptedGroupKey).
    *   **Tests:** Verify Group Lockbox updates.
*   **Step 6.3: Enforcement**
    *   **Action:** Update FSM to enforce POSIX-style permission bits (`OwnerID`, `GroupID`, `Mode`) on all Inode operations.
    *   **Tests:** Verify "Permission Denied" errors for unauthorized users.

---

## Phase 7: Polish & Interfaces
**Goal:** Make it usable for humans and OSs.

*   **Step 7.1: CLI Tool**
    *   **Action:** Build `distfs` binary. Commands: `login`, `ls`, `mkdir`, `cp`, `cat`, `share`.
    *   **Tests:** E2E CLI script tests.
*   **Step 7.2: FUSE Adapter**
    *   **Action:** Implement `fuse.FileSystem` interface using the Client Library.
    *   **Tests:** Mount filesystem, run standard linux tools (`grep`, `vim`) on mounted dir.

---

## Phase 8: Scalability Validation
**Goal:** Prove the "100GB / 1M Files" constraints.

*   **Step 8.1: Metadata Scaling**
    *   **Action:** Implement pagination for `ChunkManifests` if they grow too large for a single Raft log.
    *   **Tests:** Create a file with 200,000 chunks (200GB). Verify Commit succeeds.
*   **Step 8.2: Directory Scaling**
    *   **Action:** Ensure `ReadDir` supports pagination.
    *   **Tests:** Create directory with 100,000 files. Benchmark `ls`.
