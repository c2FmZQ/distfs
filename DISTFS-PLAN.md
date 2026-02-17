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

---

## Phase 20: Automated OIDC Discovery
**Goal:** Eliminate manual OIDC endpoint configuration for clients.

*   **Step 20.1: OIDC Discovery (Server)**
    *   **Action:** Update `storage-node` to fetch OIDC configuration from a discovery URL.
    *   **Action:** Implement `GET /v1/auth/config` to expose OIDC endpoints to clients.
*   **Step 20.2: Dynamic Configuration (Client)**
    *   **Action:** Update `pkg/client` to automatically fetch OIDC endpoints from the metadata server.
*   **Step 20.3: Mock & E2E Updates**
    *   **Action:** Update `test-auth` mock server to serve an OIDC discovery document.
    *   **Action:** Simplify E2E scripts by removing manual endpoint flags.

---

## Phase 21: Hedged Data Access
**Goal:** Optimize data latency and reliability using direct metadata URLs and parallel staggered fetches.

*   **Step 21.1: Authoritative URL Injection (Server)**
    *   **Action:** Update `ChunkEntry` to include `URLs []string`.
    *   **Action:** Update Metadata Server to resolve Node IDs to authoritative Public URLs during Inode retrieval.
*   **Step 21.2: Hedged Request Implementation (Client)**
    *   **Action:** Refactor `downloadChunk` to implement staggered parallel fetches (1s delay).
    *   **Action:** Implement immediate cancellation of pending replicas upon first success.
    *   **Action:** Remove client-side node cache and registry refresh logic.

---

## Phase 22: Performance Benchmarking
**Goal:** Measure and optimize system throughput, latency, and resiliency under load.

*   **Step 22.1: Benchmarking Tool (`distfs-bench`)**
    *   **Action:** Implement a dedicated benchmarking binary in `cmd/distfs-bench`.
    *   **Action:** Support metadata-only modes (mkdir/ls/rm) to stress the Raft consensus layer.
    *   **Action:** Support data modes (put/get) with configurable file sizes (1KB to 1GB).
    *   **Action:** Implement concurrent workers with latency histogram reporting (P50, P95, P99).
*   **Step 22.2: Large Scale Cluster Simulation**
    *   **Action:** Create `docker-compose.bench.yml` for a 3-node cluster with resource limits.
    *   **Action:** Use a dedicated benchmark runner container to isolate client-side crypto CPU usage.
*   **Step 22.3: "Grey Failure" Latency Analysis**
    *   **Action:** Benchmark read performance while injecting network latency (e.g., 2s) into a single node.
    *   **Action:** Quantify the efficiency of Phase 21 hedged requests in masking tail latency.
*   **Step 22.4: FUSE Performance Profiling**
    *   **Action:** Run `fio` against a `distfs-fuse` mount point to measure POSIX overhead.
    
---

## Phase 23: Client-Side Path Caching
**Goal:** Reduce path resolution latency from O(Depth) to O(1) for repeated access.

*   **Step 23.1: Path Hint Store**
    *   **Action:** Implement a thread-safe `PathCache` in `pkg/client` mapping absolute paths to `(InodeID, SymmetricKey)`.
*   **Step 23.2: Resolution Shortcut**
    *   **Action:** Update `ResolvePath` to check the cache before initiating directory traversal.
*   **Step 23.3: Cache Validation (Integrity)**
    *   **Action:** Store parent ID and name HMAC in the `Inode` struct.
    *   **Action:** Implement mandatory validation when using a cache hint: verify the target Inode still has the expected parent and name.
    *   **Action:** Automatically invalidate cache entries on validation failure.

---

## Phase 24: Small File Inlining
**Goal:** Eliminate storage node round-trips for small files by embedding data in the metadata layer.

*   **Step 24.1: Inode Schema Expansion**
    *   **Action:** Add `InlineData []byte` field to the `Inode` struct.
*   **Step 24.2: Inline Write Path**
    *   **Action:** Update `Client.WriteFile` to store encrypted content directly in `Inode.InlineData` if size is below threshold (e.g., 4KB).
*   **Step 24.3: Inline Read Path**
    *   **Action:** Update `Client.ReadFile` to return a buffer from `InlineData` if present, skipping chunk allocation.
*   **Step 24.4: Eviction Logic**
    *   **Action:** Implement atomic transition in `MetadataFSM`: when a file grows beyond the inline limit, move data to Data Nodes and clear `InlineData` in a single Raft transaction.

---

## Phase 25: Node-Driven Parallel Replication
**Goal:** Reduce write latency by parallelizing chunk replication at the primary storage node.

*   **Step 25.1: Parallel Replication Worker**
    *   **Action:** Update `DataNode` chunk upload handler to initiate replication to all peers in parallel via goroutines.
*   **Step 25.2: Strict Success Coupling**
    *   **Action:** Ensure the primary node waits for confirmation from ALL required replicas before returning `201 Created` to the client.
*   **Step 25.3: Error Propagation**
    *   **Action:** Return a composite error to the client if any parallel replication leg fails, triggering a standard client retry.

---

## Phase 26: Session Key Memoization
**Goal:** Reduce cryptographic overhead by reusing established ML-KEM shared secrets.

*   **Step 26.1: Security Context Cache**
    *   **Action:** Implement a server-side session cache mapping `SessionToken` to the derived symmetric `RequestKey`.
*   **Step 26.2: Optimized Unsealing**
    *   **Action:** Update `unsealRequest` middleware to skip ML-KEM decapsulation if a valid session context exists, using cached AES-GCM keys directly.
*   **Step 26.3: Client-Side Session State**
    *   **Action:** Update `pkg/client` to cache derived secrets and only perform KEM encapsulation when the session expires or is rejected.

---

## Phase 27: Metadata Request Batching
**Goal:** Increase metadata throughput by amortizing Raft fsync costs.

*   **Step 27.1: Request Aggregator**
    *   **Action:** Implement a buffering queue in the `MetadataServer` for incoming Raft mutation requests.
*   **Step 27.2: Group Commit Logic**
    *   **Action:** Implement a timed trigger (e.g., 2ms) to collect all pending requests into a single `CmdBatch` Raft log entry.
*   **Step 27.3: Batch FSM Processing**
    *   **Action:** Update `MetadataFSM` to iterate through batches and return an array of individual execution results.

---

## Phase 28: Advanced POSIX & Efficiency
**Goal:** Achieve high-fidelity POSIX behavior and optimize metadata streaming.

*   **Step 28.1: Implementation of Statfs**
    *   **Action:** Implement `GET /v1/cluster/stats` to aggregate disk usage across all registered nodes.
    *   **Action:** Implement `Statfs` in FUSE to report cluster capacity and user remaining quota.
*   **Step 28.2: Explicit Fsync Support**
    *   **Action:** Implement `Fsync` in the FUSE client to trigger an immediate chunk commit and metadata update for active file handles.
*   **Step 28.3: Incremental ReadDir**
    *   **Action:** Implement `fs.HandleReadDirer` to stream directory entries.
    *   **Action:** Optimize `GetInodes` batch calls to be used incrementally during traversal.
*   **Step 28.4: Node Eviction (Forget)**
    *   **Action:** Implement `fs.NodeForgetter` to properly release internal client-side tracking data when the kernel evicts an inode from its cache.

---

## Phase 29: Storage API & Distributed Locking
**Goal:** Implement a subset of the `storage.Storage` interface to support transactional multi-file updates and high-level E2EE data management.

*   **Step 29.1: Metadata Schema & FSM Expansion**
    *   **Action:** Add `LeaseOwner string` and `LeaseExpiry int64` to the `Inode` struct in `pkg/metadata/types.go`.
    *   **Action:** Implement `CmdAcquireLeases` and `CmdReleaseLeases` in `pkg/metadata/fsm.go`.
    *   **Action:** Add FSM logic to atomically validate and grant leases for multiple Inodes in a single Raft transaction (Deadlock Prevention).
*   **Step 29.2: Client Locking Primitives**
    *   **Action:** Implement `AcquireLeases(ctx, ids)` and `ReleaseLeases(ctx, ids)` in `pkg/client/client.go`.
    *   **Action:** Ensure leases are associated with the `Session-Token`.
*   **Step 29.3: High-Level Blob API (`OpenBlobRead` / `OpenBlobWrite`)**
    *   **Action:** Implement `OpenBlobRead(id)` as a wrapper around `NewReader`.
    *   **Action:** Implement `OpenBlobWrite(id)` by creating a new `FileWriter` that handles streaming chunked encryption and pipelined uploads.
*   **Step 29.4: Data File API (`ReadDataFile` / `SaveDataFile`)**
    *   **Action:** Implement E2EE serialization (JSON/Gob) wrappers.
    *   **Action:** Integrate with Step 24.2 (Small File Inlining) to store these files directly in the Metadata Layer for low latency.
*   **Step 29.5: Transactional Updates (`OpenForUpdate` / `OpenManyForUpdate`)**
    *   **Action:** Implement the transactional lifecycle:
        1.  Acquire exclusive leases for all requested Inodes.
        2.  Read current data and decrypt.
        3.  Provide data to user callback.
        4.  Re-encrypt and perform atomic `UpdateInode` + `ReleaseLease` Raft command.
    *   **Action:** Implement automatic lease renewal based on client heartbeat to handle long-running transactions.
*   **Step 29.6: Lease Reaper**
    *   **Action:** Add a background worker to the `MetadataServer` that monitors session heartbeats.
    *   **Action:** Automatically release all leases owned by a session if its heartbeat times out or the session is revoked.
    *   **Action:** Add a "Lease" view to the operator dashboard.

---

## Phase 30: Admin CUI & Individual Authorization
**Goal:** Transition cluster management to an individually authorized, PQC-powered Command-line User Interface (CUI).

*   **Step 30.1: Admin Bucket & Authorization**
    *   **Action:** Add `admins` bucket to BoltDB FSM.
    *   **Action:** Implement `CmdPromoteAdmin` Raft command.
    *   **Action:** Update `CmdCreateUser` logic to automatically add the first-ever registered user to the `admins` bucket (Bootstrap).
    *   **Action:** Implement `isAdmin(userID)` check in the Metadata Server.
*   **Step 30.2: Sealed Admin API**
    *   **Action:** Implement `/v1/admin/*` endpoint prefix.
    *   **Action:** Enforce mandatory **SealedRequests** and verify admin status for all endpoints in this group.
    *   **Action:** Port existing dashboard functions (Users, Nodes, Stats, Lookup, Join/Remove) to this new authenticated API.
*   **Step 30.3: Admin CUI (`distfs admin`)**
    *   **Action:** Implement the Elm-style CUI loop using **Charmbracelet Bubble Tea**.
    *   **Action:** Create a multi-tab interface (Overview, Users, Nodes, Tools).
    *   **Action:** Use **Lip Gloss** for a polished, modern terminal aesthetic.
    *   **Action:** Implement real-time polling for cluster status and usage metrics.
*   **Step 30.4: Legacy Cleanup**
    *   **Action:** Remove `dashboard.go` and the `ui/` directory.
    *   **Action:** Deprecate the shared `X-Raft-Secret` auth mechanism in favor of individual PQC signatures.
*   **Step 30.5: Metadata Overrides (chown/chmod)**
    *   **Action:** Implement `CmdAdminChown` and `CmdAdminChmod` Raft commands in the FSM.
    *   **Action:** Add `/v1/admin/chown` and `/v1/admin/chmod` endpoints to the Metadata Server.
    *   **Action:** Implement `distfs admin-chown <email> <path>` and `distfs admin-chmod <mode> <path>` commands.
    *   **Action:** Ensure the CLI prints explicit warnings regarding Zero-Knowledge data access limitations.

---

## Phase 31: Manifest Signing & Integrity
**Goal:** Implement cryptographic attribution and authorization for file metadata.

*   **Step 31.1: Group ML-DSA Keys**
    *   **Action:** Update `Group` struct to include `SignKey` (Public) and `EncryptedSignKey` (Wrapped Private).
    *   **Action:** Update `CreateGroup` to generate ML-DSA signing pair.
    *   **Action:** Update `AddUserToGroup` to wrap the group signing key for the new member.
*   **Step 31.2: Inode Signature Fields**
    *   **Action:** Add `SignerID`, `UserSig`, and `GroupSig` to the `Inode` struct.
    *   **Action:** Add `AuthorizedSigners` list to Inodes (Owner by default).
*   **Step 31.3: Client-side Dual Signing**
    *   **Action:** Implement `ChunkManifest` hashing.
    *   **Action:** Update `UpdateInode` to sign the hash with the User's Identity Key.
    *   **Action:** If in a group context, also sign with the Group Signing Key.
*   **Step 31.4: Client-side Verification**
    *   **Action:** Update `UnlockInode` or `Open` to verify both signatures against the manifest.
    *   **Action:** Reject files with mismatched or unauthorized signatures.
*   **Step 31.5: Prohibition of World-Writable**
    *   **Action:** [Done] Update `MetadataServer` to explicitly reject any mutation that attempts to set the `Other-Write` bit (0002).
    *   **Action:** [Done] Update `FSM` validation logic to ignore world-write bits during apply.
*   **Step 31.6: Root Anchor Persistence**
    *   **Action:** Update client configuration to store the Root Inode ID, Owner, and last seen Version.
    *   **Action:** Implement a safety check during initialization: warn or abort if the Root Owner changes or the Version decreases (Rollback Protection).


