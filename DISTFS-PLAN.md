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
    *   **Action:** Implement `Store` interface backed by `github.com/c2FmZQ/storage` (`OpenBlobWrite`/`OpenBlobRead`).
    *   **Action:** Ensure `DISTFS_MASTER_KEY` env var is used to derive the local Master Key.
*   **Step 2.2: Integrity Scrubber**
    *   **Action:** Implement a background worker that walks the chunk directory.
*   **Step 2.3: Data API (HTTP/2)**
    *   **Action:** Implement `PUT /v1/data/{chunk_id}` and `GET /v1/data/{chunk_id}`.

---

## Phase 3: The Metadata Role (Raft Core)
**Goal:** Port and adapt the distributed consensus engine.

*   **Step 3.1: Raft Infrastructure**
    *   **Action:** Port `RaftManager`, `EncryptedLogStore` using `github.com/c2FmZQ/storage` crypto primitives.
    *   **Action:** Ensure Raft logs and snapshots are encrypted at rest using the derived Master Key.
*   **Step 3.2: FSM & Inode Model**
    *   **Action:** Define `Inode` struct.
    *   **Action:** Implement `ClusterSecret` generation (Bootstrap) and storage in FSM.
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
    *   **Action:** Implement `POST /v1/user/register` (OIDC) and remove `POST /v1/user` (Raw) to enforce federated identity.
    *   **Action:** Implement "Dark Registry": remove `Name` field from `User` struct and use `HMAC(email)` as User ID. Implement `ClusterSecret` logic in API handler.
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
**Goal:** Implement advanced operations, security, and the management dashboard.

*   **Step 9.1: Network Configuration**
    *   **Action:** Implement flags for `--cluster-addr`, `--raft-bind`, `--cluster-advertise`, and `--raft-advertise`.
    *   **Action:** Configure separate listeners for Public and Internal APIs.
*   **Step 9.2: Node Identity & mTLS**
    *   **Action:** Implement `NodeKey` generation (Ed25519) and persistence (`node.key`).
    *   **Action:** Implement dynamic self-signed certificate generation using `NodeKey`.
    *   **Action:** Implement `RaftTransport` using mTLS.
*   **Step 9.3: Trust Bootstrapping (TOFU)**
    *   **Action:** Implement `NodeMeta` storage in FSM (list of trusted keys).
    *   **Action:** Implement TOFU logic for fresh nodes to accept initial connection from Leader.
*   **Step 9.4: Cluster Management API & Dashboard**
    *   **Action:** Implement `RaftSecret` middleware protection.
    *   **Action:** Implement `POST /api/cluster/join` (Add Node) and `POST /api/cluster/remove`.
    *   **Action:** Implement `GET /api/cluster` (Dashboard HTML/JSON) using Vanilla JS/CSS for the frontend.
    *   **Action:** Implement "Blind Lookup" API to resolve Emails to User Hashes.
*   **Step 9.5: Request Forwarding**
    *   **Action:** Forward write requests from Follower to Leader via Internal Cluster API.
*   **Step 9.6: Key Rotation**
    *   **Action:** Implement Log Key Rotation on Snapshot.
*   **Step 9.7: Accounting Engine**
    *   **Action:** Update FSM `User` struct with `Usage` stats (Atomic Counters).
    *   **Action:** Add hooks to Inode/Chunk ops to update usage stats in real-time.
*   **Step 9.8: Quota Enforcement**
    *   **Action:** Implement `Quota` struct in User model.
    *   **Action:** Implement Quota Templates (default limits).
    *   **Action:** Enforce quotas in `CreateInode` and `AllocateChunk` handlers.
*   **Step 9.9: Cluster Identity (Epoch Keys)**
    *   **Action:** Implement `CmdRotateKey` in FSM.
    *   **Action:** Implement `KeyRotationWorker` (Leader only).
    *   **Action:** Update `/v1/meta/key` to return active Epoch Key.
    *   **Action:** Update Auth Middleware to use shared Epoch Keys instead of Node Keys.

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

---

## Phase 11: E2E & Reliability
**Goal:** Harden the system against failures and verify correctness at scale.

*   **Step 11.1: High-Availability (HA) Failure Simulation**
    *   **Action:** Implement E2E tests that kill storage nodes during active operations.
*   **Step 11.2: Concurrency & Stress Testing**
    *   **Action:** Implement multi-client write/read stress tests.
*   **Step 11.3: Data Integrity E2E**
    *   **Action:** Verify that the Integrity Scrubber and Replication Repair work together to recover from chunk corruption.
*   **Step 11.4: Garbage Collection Verification**
    *   **Action:** End-to-end verification that deleting a file eventually reclaims disk space on data nodes.

---

## Phase 12: World-Readable Support
**Goal:** Enable "public" files within the cluster while maintaining E2EE.

*   **Step 12.1: World Identity Management**
    *   **Action:** Generate `WorldIdentity` (ML-KEM pair) in FSM if missing.
    *   **Action:** Implement `GET /v1/meta/key/world` to distribute the Public Key.
*   **Step 12.2: Private Key Distribution**
    *   **Action:** Implement `GET /v1/meta/key/world/private` (Authenticated).
    *   **Action:** Encapsulate World Private Key using requester's `EncKey` before transmission.
*   **Step 12.3: Client Fallback Logic**
    *   **Action:** Update `ResolvePath` and `ReadFile` to check for `world` recipient if personal access fails.
    *   **Action:** Implement memory caching for decrypted World Private Key.
*   **Step 12.4: FUSE & CLI Publishing**
    *   **Action:** Update `chmod` handler to automatically add/remove `world` recipient in Lockbox based on permission bits.
*   **Step 12.5: World-Writable Server Auth**
    *   **Action:** Update MetaNode to allow non-owners to write to Inodes if world-write bit (`0002`) is set.
*   **Step 12.6: World-Writable Client Logic**
    *   **Action:** Ensure Client can use World Private Key to unlock File Keys for write operations.

---

## Phase 13: Group-Based Sharing
**Goal:** Implement cryptographic group sharing.

*   **Step 13.1: Group Authorization**
    *   **Action:** Update `handleIssueToken` and `checkWritePermission` in MetaNode to verify user membership in `inode.GroupID`.
*   **Step 13.2: Group Key Retrieval**
    *   **Action:** Implement `GET /v1/group/{id}/private` to retrieve the Group Private Key (encapsulated for the requester).
*   **Step 13.3: Client Group Logic**
    *   **Action:** Update `UnlockInode` to attempt group-based decryption if personal access fails.
    *   **Action:** Implement memory caching for Group Private Keys.
*   **Step 13.4: Group Management CLI**
    *   **Action:** Implement `chgrp` and `group-create`/`group-add` commands.

---

## Phase 14: Layer 7 End-to-End Encryption (Metadata Privacy) [COMPLETED]
**Goal:** Encrypt all client-to-server request payloads using the server's public key.

*   **Step 14.1: Sealed Request Primitives**
    *   **Action:** [Done] Implement `SealRequest` and `OpenRequest` in `pkg/crypto`.
    *   **Action:** [Done] Inner payload: `[Timestamp][Signature][JSON]`.
*   **Step 14.2: Server Unsealing Middleware**
    *   **Action:** [Done] Implement a request interceptor in `MetadataServer` that transparently unseals bodies.
    *   **Action:** [Done] Enforce timestamp-based replay protection.
*   **Step 14.3: Client Sealing Integration**
    *   **Action:** [Done] Update `Client.sendRequest` (or equivalent) to wrap all outgoing payloads.
    *   **Action:** [Done] Transition all handlers to strictly expect sealed requests.

---

## Phase 15: Bidirectional Layer 7 E2EE (Response Privacy) [COMPLETED]
**Goal:** Encrypt all server-to-client responses using the client's registered public key.

*   **Step 15.1: Response Sealing Primitives**
    *   **Action:** [Done] Implement `SealResponse` and `OpenResponse` in `pkg/crypto`.
*   **Step 15.2: Server Response Interceptor**
    *   **Action:** [Done] Implement a response wrapper in `MetadataServer` that seals outgoing JSON.
    *   **Action:** [Done] Use the registered `User.EncKey` for encryption.
*   **Step 15.3: Client Transparent Unsealing**
    *   **Action:** [Done] Update Client HTTP helpers to automatically unseal responses when the sealed header is present.

---

## Phase 17: Multi-Device Key Synchronization [COMPLETED]
**Goal:** Allow users to sync their cryptographic keys across devices securely.

*   **Step 17.1: Metadata FSM Support**
    *   **Action:** [Done] Add `keysync` bucket to BoltDB.
    *   **Action:** [Done] Implement `CmdStoreKeySync` command.
*   **Step 17.2: Server Endpoints**
    *   **Action:** [Done] `GET /v1/user/keysync`: Authenticate via OIDC JWT, return blob.
    *   **Action:** [Done] `POST /v1/user/keysync`: Authenticate via `Session-Token` + Mandatory Sealing, store blob.
*   **Step 17.3: Client Integration**
    *   **Action:** [Done] Implement `PushKeySync` and `PullKeySync` in `pkg/client`.
    *   **Action:** [Done] Use existing `pkg/config` encryption logic (Argon2id).
*   **Step 17.4: CLI Commands**
    *   **Action:** [Done] Add `distfs keysync push`.
    *   **Action:** [Done] Add `distfs keysync pull` (or integrate into `init`).
    
    ---
    
    ## Phase 18: Secure Passphrase Entry (Pinentry)
    **Goal:** Integrate `pinentry` support for secure passphrase input.
    
    *   **Step 18.1: Library Integration**
        *   **Action:** Add `github.com/twpayne/go-pinentry` as a dependency.
    *   **Step 18.2: Secure Pinentry Wrapper**
        *   **Action:** Implement `GetPasswordSecure` in `pkg/config` that uses `go-pinentry`.
        *   **Action:** Validate `GPG_TTY` to prevent command injection.
        *   **Action:** Use conditional compilation with `nopinentry` build tag.
    *   **Step 18.3: CLI & FUSE Integration**
        *   **Action:** Add `--use-pinentry` flag to `distfs` and `distfs-fuse`.
        *   **Action:** Update `config.GetPassword` to use the secure wrapper if enabled.

---

## Phase 19: Unified Onboarding Flow
**Goal:** Simplify client setup by combining init, register, and keysync into a single command.

*   **Step 19.1: Unified Init Logic (CLI)**
    *   **Action:** Refactor `distfs init` to support `--new` and existing account flows.
    *   **Action:** Integrate OIDC Device Flow, Registration, and KeySync (Push/Pull) into `init`.
    *   **Action:** Deprecate or internalize standalone `register` and `keysync` commands.
*   **Step 19.2: Unified Onboarding (FUSE)**
    *   **Action:** Update `distfs-fuse` to utilize the unified onboarding logic if configuration is missing.
*   **Step 19.3: Documentation & E2E**
    *   **Action:** Update `README.md` and project scripts to use the streamlined flow.
    