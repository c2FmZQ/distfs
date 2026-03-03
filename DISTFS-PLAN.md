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

## Phase 13: Group-Based Sharing & Management [COMPLETED]
**Goal:** Implement cryptographic group sharing and secure, owner-delegated management.

*   **Step 13.1: Group Authorization & Signatures**
    *   **Action:** [Done] Update `Group` struct with `Version`, `SignerID`, and `Signature` in `pkg/metadata/types.go`.
    *   **Action:** [Done] Implement `Group.Hash()` for metadata integrity verification.
    *   **Action:** [Done] Update `handleUpdateGroup` in `MetadataServer` to enforce **Signature Verification** and **Version Matching**.
*   **Step 13.2: Delegated & Self-Managed Groups**
    *   **Action:** [Done] Update `checkGroupWritePermission` in `MetadataServer` to support `OwnerID` being a User or Group ID.
    *   **Action:** [Done] Implement non-recursive group-membership check for group-owned groups.
*   **Step 13.3: Client Group Management Signing**
    *   **Action:** [Done] Update `Client.AddUserToGroup` to sign the updated group metadata using the user's ML-DSA identity key.
    *   **Action:** [Done] Implement `Client.UpdateGroup` to handle optimistic concurrency retries (fetch-modify-retry).
*   **Step 13.4: Group Management CLI (Advanced)**
    *   **Action:** [Done] Implement `group-chown` to transfer group ownership to another User or Group.
    *   **Action:** [Done] Implement `group-list-members` and `group-info` to display ownership and management status.
*   **Step 13.5: Testing & Verification**
    *   **Action:** [Done] **Unit Test:** FSM `executeUpdateGroup` correctly verifies signatures and increments versions.
    *   **Action:** [Done] **Security Test:** Verify that a non-member is rejected when attempting to update a group.
    *   **Action:** [Done] **Security Test:** Verify that a member can update a self-managed group but a non-member cannot.
    *   **Action:** [Done] **Integration Test:** Demonstrate "Group A owned by Group B" where a member of B successfully adds a user to A.
*   **Step 13.6: PII Isolation (Encrypted Member Registry)**
    *   **Action:** [Done] Add `RegistryLockbox` and `EncryptedRegistry` fields to `Group` struct.
    *   **Action:** [Done] Implement client-side logic to generate a symmetric **Registry Key** during group creation.
    *   **Action:** [Done] Implement `RegistryLockbox.AddRecipient` to share the Registry Key with authorized managers (`OwnerID`).
    *   **Action:** [Done] Update `group-add` to update the `EncryptedRegistry` blob (containing member emails) whenever a user is added.
    *   **Action:** [Done] Update `group-info` to attempt Registry Key decryption and display member emails only if authorized.
*   **Step 13.7: Group Discovery (Membership Indexing)**
    *   **Action:** [Done] Add `user_memberships` and `owner_groups` buckets to BoltDB FSM.
    *   **Action:** [Done] Implement indexing logic in `executeCreateGroup` and `executeUpdateGroup` to maintain consistency between group state and membership indices.
    *   **Action:** [Done] Implement `GET /v1/user/groups` endpoint in `MetadataServer` to return groups associated with the authenticated user.
    *   **Action:** [Done] Implement role resolution logic (Owner, Manager, Member) on the server.
    *   **Action:** [Done] Add `distfs group-list` command to CLI with local decryption of group names.
*   **Step 13.8: Group Resource Quotas [REFACTORED]**
    *   **Action:** [Done] Add `Usage`, `Quota`, and `QuotaEnabled` fields to `Group` struct.
    *   **Action:** [Done] Implement "Static Quota Mode": groups with `QuotaEnabled: true` are charged exclusively; others fall back to the owner.
    *   **Action:** [Done] Remove complex dynamic migration logic in favor of immutable creation-time accounting mode.
    *   **Action:** [Done] Implement `CmdSetGroupQuota` and restrict it to quota-enabled groups.
    *   **Action:** [Done] Update CLI and E2E tests to align with the new mode-based enforcement.

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

## Phase 29: Storage API & Path-Based Atomic Writes
**Goal:** Implement atomic path-based updates and distributed filename locking.

*   **Step 29.1: Multi-Bucket Leasing (FSM)**
    *   **Action:** Refactor `executeAcquireLeases` to support two target types:
        *   **Inode IDs**: Used by POSIX/Readers (Shared/Exclusive). Stored in `inodes` bucket.
        *   **Filenames/Paths**: Used by Atomic Writes (Exclusive). Stored in a new `filename_leases` bucket.
    *   **Action:** Update `LeaseInfo` to include the target type.
*   **Step 29.2: Atomic Swap Protocol (Client)**
    *   **Action:** Refactor `FileWriter` to support "Atomic Swap" mode.
    *   **Action:** On `Close()`, if in swap mode:
        1.  Create a **new InodeID**.
        2.  Propose a batch: `CreateInode(New)` + `UpdateInode(Parent, Link=New)` + `UpdateInode(Old, NLink--)`.
*   **Step 29.3: Standardized High-Level API**
    *   **Action:** Update `OpenBlobWrite` and `SaveDataFile` to:
        1.  Acquire an **Exclusive Filename Lease** on the path.
        2.  Initialize `FileWriter` in Atomic Swap mode.
*   **Step 29.4: Transactional Updates (`OpenManyForUpdate`)**
    *   **Action:** Update to use path-based locking for all targets.
    *   **Action:** Perform atomic commit of all modified files using the batch swap protocol.
*   **Step 29.5: POSIX Compatibility (FUSE)**
    *   **Action:** Ensure FUSE continues to use Inode-ID based leasing for POSIX compliance.
    *   **Action:** Verify that unlinked files remain readable even after an atomic swap has replaced their name in the directory.

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
    *   **Action:** [Done] Implement `Client.UpdateInode` and `Client.UpdateGroup` using the atomic mutation callback pattern.
    *   **Action:** [Done] Migrate `AddEntry`, `RemoveEntry`, and `Link` to use client-side signed versioning with server-side sequence validation.
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

---

## Phase 32: Scalability & Performance Optimization
**Goal:** Address identified bottlenecks in metadata, storage, and client interaction to support high throughput and large datasets.

*   **Step 32.1: Parallel Metadata Batching**
    *   **Action:** Refactor \`batchProcessor\` in \`MetadataServer\` to support parallel request preparation (decoding, signature verification) before serialization into the Raft log.
    *   **Test:** Benchmark metadata write throughput with high concurrent client load.
    *   **Success Criteria:** Increased throughput for \`CreateInode\`/\`UpdateInode\` operations compared to single-channel baseline.

*   **Step 32.2: FSM Transaction Optimization**
    *   **Action:** Optimize \`executeCommand\` logic to minimize time spent inside the global BoltDB write lock.
    *   **Action:** Investigate and implement sharding strategies for metadata (e.g., separate buckets or DB instances) if necessary for write concurrency.
    *   **Test:** Measure FSM apply latency under heavy write load.
    *   **Success Criteria:** Reduced Raft commit latency and improved responsiveness during heavy write bursts.

*   **Step 32.3: Optimized DiskStore Operations**
    *   **Action:** Refactor \`DeleteChunk\` and \`ListChunks\` in \`DiskStore\` to avoid \`filepath.WalkDir\` (O(N) scan).
    *   **Action:** Implement a deterministic directory sharding scheme (e.g., \`ab/cd/chunk_id\`) for the underlying \`storage\` backend to ensure O(1) access.
    *   **Test:** Benchmark \`DeleteChunk\` and \`ListChunks\` with >100k chunks.
    *   **Success Criteria:** \`DeleteChunk\` latency remains constant regardless of total chunk count.

*   **Step 32.4: Client Concurrency Management**
    *   **Action:** Split the global \`concurrencySem\` in \`Client\` into separate semaphores for Control Plane (Metadata) and Data Plane (Chunk I/O).
    *   **Test:** Simulate heavy data I/O and measure latency of concurrent metadata operations.
    *   **Success Criteria:** Metadata operations remain responsive even when data throughput is saturated.

*   **Step 32.5: FUSE Initialization Optimization**
    *   **Action:** Replace the blocking recursive retry loop in \`FS.Root()\` with a non-blocking or lazy initialization mechanism.
    *   **Test:** Verify FUSE mount returns immediately and handles subsequent access gracefully if the cluster is initially unavailable.
    *   **Success Criteria:** \`distfs-fuse\` command returns successfully without hanging, even if the server is offline.

---

## Phase 33: Secure Contact Exchange [COMPLETED]
**Goal:** Enable users to securely share their identity for group membership and collaboration via out-of-band communication.

*   **Step 33.1: Contact String Specification**
    *   **Action:** [Done] Define the `distfs-contact` URI scheme.
    *   **Action:** [Done] Include UserID, Public Encryption Key (ML-KEM), and Public Signing Key (ML-DSA) in the payload.
    *   **Action:** [Done] Implement signing logic where the user signs their contact data to prevent tampering during OOB transit.
*   **Step 33.2: Contact Generation & Verification**
    *   **Action:** [Done] Implement `GenerateContactString()` in `pkg/client`.
    *   **Action:** [Done] Implement `VerifyContactString(uri)` in `pkg/client` to parse and validate signatures.
*   **Step 33.3: CLI Integration**
    *   **Action:** [Done] Add `distfs contact-info` command to display the user's signed URI.
    *   **Action:** [Done] Update `distfs group-add` to accept a contact URI, automatically verifying and extracting the UserID.
*   **Step 33.4: Testing**
    *   **Action:** [Done] Verify that tampered contact strings (e.g., modified UserID) are rejected during verification.

---

## Phase 34: Admin Console Enhancements
**Goal:** Expand the interactive management interface with deep cluster visibility and streamlined operations.

*   **Step 34.1: Groups Tab**
    *   **Action:** Implement a "Groups" tab in the `distfs admin` CUI.
    *   **Action:** Display group IDs, usage (inodes/bytes), and current quotas.
*   **Step 34.2: Leases & Lock Monitoring**
    *   **Action:** Implement a "Leases" tab to monitor active Inode leases and lock durations.
    *   **Action:** Add server-side API to list all active leases.
*   **Step 34.3: Action Modals & In-Console Management**
    *   **Action:** Implement pop-up input modals for administrative actions (Set Quota, Promote User, Join Node).
    *   **Action:** Eliminate the need to exit the console for common management tasks.
*   **Step 34.4: Health Indicators & Metrics**
    *   **Action:** Enhance the Overview tab with visual health indicators (Color-coded Raft status).
    *   **Action:** Implement a Metrics tab to visualize Raft commit latency and storage node utilization.

---

## Phase 35: Enhanced "ls" Command
**Goal:** Implement a feature-rich `ls` command that supports standard POSIX flags for metadata visibility, sorting, and recursion.

*   **Step 35.1: Client Library API Enhancement**
    *   **Action:** Refactor `Client.ReadDir` (or add `ReadDirExtended`) to optionally fetch full `Inode` metadata for each entry in a single batch.
    *   **Action:** Implement `ReadDirRecursive` using a depth-first or breadth-first traversal with efficient concurrency limiting.
*   **Step 35.2: Metadata Formatting & Humanization**
    *   **Action:** Implement a formatting package to handle human-readable sizes (`-h`), file modes, and time formatting.
    *   **Action:** Add `-F` classification logic (e.g., appending `/` for directories).
*   **Step 35.3: Sorting and Filtering**
    *   **Action:** Implement client-side sorting logic for Alphabetical (default), Time (`-t`), and Size (`-S`).
    *   **Action:** Implement reverse sorting (`-r`) and hidden file filtering (`-a` logic).
*   **Step 35.4: CLI Flag Integration**
    *   **Action:** Update `cmd/distfs/main.go` to support flags: `-l`, `-a`, `-h`, `-i`, `-R`, `-d`, `-t`, `-S`, `-r`, `-1`, `-F`.
    *   **Action:** Implement long-format (`-l`) column alignment and colorized output support.
*   **Step 35.5: Testing & Verification**
    *   **Action:** **Unit Test:** Verify sorting logic with various metadata combinations.
    *   **Action:** **Unit Test:** Verify human-readable formatting across different scales (B, KB, MB, GB).
    *   **Action:** **Integration Test:** Perform a recursive `ls -R` on a complex directory tree and verify total entry count and metadata accuracy.
    *   **Action:** **Integration Test:** Verify that `-a` correctly toggles visibility of hidden files.

---

## Phase 36: Opaque Client Metadata (ClientBlob)
**Goal:** Consolidate non-enforcement metadata into a single encrypted blob to maximize zero-knowledge privacy.

*   **Step 36.1: ClientBlob Specification**
    *   **Action:** Define `InodeClientBlob` and `GroupClientBlob` structs in `pkg/metadata`.
    *   **Inode Fields:** `Name`, `SymlinkTarget`, `InlineData`, `MTime`, `UID`, `GID`, `SignerID`, `AuthorizedSigners`.
    *   **Group Fields:** `Name`.
*   **Step 36.2: Metadata Schema Migration**
    *   **Action:** Add `ClientBlob []byte` to `Inode` and `Group` structs in `pkg/metadata/types.go`.
    *   **Action:** Update `ManifestHash()` and `Group.Hash()` to include `ClientBlob` and exclude moved fields.
*   **Step 36.3: Client-Side Implementation**
    *   **Action:** Update `signInode` and `signGroup` to serialize and encrypt the `ClientBlob`.
    *   **Action:** Update `VerifyInode` and `GetGroup` to decrypt and unpack the `ClientBlob` into transient memory fields.
*   **Step 36.4: Cleanup & Enforcement**
    *   **Action:** Remove legacy fields from `Inode` and `Group` structs.
    *   **Action:** Update `FSM` and `Server` to strictly ignore or reject legacy fields.
*   **Step 36.5: Testing & Verification**
    *   **Action:** Add E2E tests to verify that common operations (ls, stat, read) work correctly with the blob-based architecture.
    *   **Action:** Verify via raw DB inspection that sensitive fields are no longer stored in plaintext (or even separate ciphertext fields).

---

## Phase 37: FSM Key Rotation & KeyRing Implementation
**Goal:** Implement cryptographic agility and forward secrecy for the metadata layer by introducing a rotating FSM key ring.

*   **Step 37.1: KeyRing Integration in FSM**
    *   **Action:** Refactor `MetadataFSM` struct in `pkg/metadata/fsm.go` to use `crypto.KeyRing` instead of a static `[]byte` for `fsmKey`.
    *   **Action:** Update `NewMetadataFSM` to initialize/load the `KeyRing` from `fsm.key`.
*   **Step 37.2: Prefixed Ciphertext Format**
    *   **Action:** Update `EncryptValue` to prepend the 4-byte Key Generation ID to the ciphertext.
    *   **Action:** Update `DecryptValue` to read the ID and use the corresponding key from the `KeyRing`.
*   **Step 37.3: Synchronized Key Rotation**
    *   **Action:** Implement `CmdRotateFSMKey` Raft command.
    *   **Action:** When applied, all nodes call `fsm.keyRing.Rotate()` and persist the updated ring to their local `fsm.key` via `fsm.st`.
*   **Step 37.4: Background Re-encryption Worker**
    *   **Action:** Implement `KeyRotationWorker` in `pkg/metadata/key_rotation.go` (Leader-only).
    *   **Action:** The worker slowly scans BoltDB buckets (Inodes, Users, Groups, etc.).
    *   **Action:** For values not encrypted with the *active* key, it re-encrypts them and proposes an update via Raft (e.g., `CmdUpdateInode`).
    *   **Action:** Implement throttling to ensure minimal impact on cluster performance.
*   **Step 37.5: Snapshot & Restore Evolution**
    *   **Action:** Update `MetadataSnapshot.Persist` to write the full serialized `KeyRing` to the snapshot stream.
    *   **Action:** Update `MetadataFSM.Restore` to read and initialize the `KeyRing` from the stream.
*   **Step 37.6: Testing & Verification**
    *   **Action:** **Unit Test:** Verify that `DecryptValue` correctly handles multiple key generations.
    *   **Action:** **Integration Test:** Perform a key rotation and verify that the background worker successfully updates all values to the new key without downtime.
    *   **Action:** **Reliability Test:** Verify that a node can join the cluster and correctly sync the full `KeyRing` from a snapshot.

---

## Phase 38: Comprehensive Test Coverage (Target 90%)
**Goal:** Achieve and maintain a minimum of 90% statement coverage across all core packages to ensure long-term stability and prevent regressions.

*   **Step 38.1: Crypto Package Hardening (Target: 90%)**
    *   **Action:** Add exhaustive unit tests for `pkg/crypto/sealed.go` covering all error paths (too short payloads, invalid signatures, expired timestamps).
    *   **Action:** Implement property-based tests for `KeyRing` serialization and `Lockbox` recipient management.
*   **Step 38.2: Metadata FSM Branch Coverage (Target: 90%)**
    *   **Action:** Meticulously test every error path in `fsm.go` by injecting corrupted data into BoltDB buckets or simulating unmarshal failures.
    *   **Action:** Add tests for `KeyRotationWorker` edge cases, such as multiple concurrent rotations or bucket exhaustion during scans.
*   **Step 38.3: Client Library Resilience (Target: 90%)**
    *   **Action:** Use an HTTP mock transport to simulate varied failure modes: network timeouts, 500-series server errors, and malformed sealed responses.
    *   **Action:** Verify the efficiency of the hedged read cancellation logic by instrumenting the mock nodes to return data at precise intervals.
*   **Step 38.4: Data Layer and Scrubber Stress (Target: 90%)**
    *   **Action:** Simulate disk I/O errors and "disk full" scenarios in `pkg/data/disk_store.go`.
    *   **Action:** Enhance Scrubber tests to verify the exact quarantine and reporting lifecycle for varied corruption types (truncated files, random bit flips).
*   **Step 38.5: FUSE Protocol Fidelity (Target: 90%)**
    *   **Action:** Implement unit tests for individual FUSE operations (Stat, ReadDir, Chmod) that bypass the kernel using mock request objects.
    *   **Action:** Verify node eviction (`Forget`) and memory management logic under heavy inode pressure.
*   **Step 38.6: CLI Command Coverage (Target: 90%)**
    *   **Action:** Implement a test suite for `cmd/distfs` that captures stdout/stderr and verifies exit codes for all valid and invalid flag combinations.
    *   **Action:** Test the interactive Admin CUI components using Bubble Tea's testing framework.

---

## Phase 39: POSIX-Compliant Deletion (Deferred GC)
**Goal:** Ensure that unlinked files remain accessible to clients with open handles, as required by POSIX.

*   **Step 39.1: Shared Lease Support (FSM)**
    *   **Action:** Update `LeaseRequest` to include `Type` (SHARED, EXCLUSIVE).
    *   **Action:** Update `Inode` to store a map of `OwnerID -> Expiry` for SHARED leases.
    *   **Action:** Refactor `executeAcquireLeases` to allow multiple concurrent SHARED leases.
*   **Step 39.2: Deferred Deletion Logic (FSM)**
    *   **Action:** Add `Unlinked bool` field to the `Inode` struct.
    *   **Action:** Update `executeDeleteInode`: if active leases exist, set `Unlinked = true` and keep the inode in the DB, but remove it from parent directories.
    *   **Action:** Update `executeReleaseLeases`: if the last lease is released and `Unlinked == true`, trigger the final deletion (quota update + GC enqueue).
*   **Step 39.3: Client-Side Handle Management**
    *   **Action:** Update `Client.NewReader` and `Client.OpenBlobWrite` to acquire a SHARED lease.
    *   **Action:** Implement a background "Lease Renewer" in `FileReader` and `FileWriter`.
    *   **Action:** Ensure `Close()` explicitly releases the lease.
*   **Step 39.4: Metadata Reaper Enhancement (Indexed)**
    *   **Action:** Add `unlinked_inodes` bucket to the FSM to track inodes pending deletion.
    *   **Action:** Update the leader-only `GCWorker` to scan the `unlinked_inodes` bucket (instead of all inodes) to finalize deletions for crashed clients.
*   **Step 39.5: Comprehensive Testing Strategy**
    *   **Action:** **Unit Test (FSM):** Verify that `executeDeleteInode` correctly transitions to the `Unlinked` state when leases are active.
    *   **Action:** **Unit Test (FSM):** Verify that releasing the last lease on an `Unlinked` inode triggers GC enqueuing.
    *   **Action:** **Integration Test (Client):** Open a file, delete it via another client, and verify the first client can still read its content.
    *   **Action:** **E2E Test (FUSE):** Perform a "delete-while-open" test using standard shell commands (`cat & sleep`, `rm`, then finish `cat`).
    *   **Action:** **Resiliency Test:** Kill a client with an open unlinked file and verify that the `GCWorker` eventually reclaims the space after the lease expires.
    *   **Action:** **Stress Test:** Rapidly open/delete/close thousands of files to ensure no leaks in the `garbage_collection` bucket or the `leases` bucket.

---

## Phase 40: Atomic Multi-File Reads
**Goal:** Implement consistent multi-file reads by combining path-based namespace stability with inode-based data protection.

*   **Step 40.1: Shared Filename Leases (FSM)**
    *   **Action:** Refactor `executeAcquireLeases` in `pkg/metadata/fsm.go` to support multiple concurrent `LeaseShared` entries for the same path in `filename_leases`.
    *   **Action:** Implement conflict logic: `Shared` conflicts only with `Exclusive`; `Exclusive` conflicts with all types. Stored as a map of `Nonce -> LeaseInfo` in `filename_leases`.
*   **Step 40.2: Multi-Reader API (Client)**
    *   **Action:** Implement `NewReaders(ctx, paths []string) ([]*FileReader, error)` in `pkg/client/client.go`.
    *   **Action:** Implement the "Snapshot Protocol":
        1.  Acquire **Shared Filename Leases** for all paths in a single batch. This "freezes" the paths so they can't be swapped out by concurrent atomic writes.
        2.  Resolve all paths to Inode IDs and Keys.
        3.  Initialize `FileReader` for each (each will acquire its own **Inode-based lease**).
        4.  Release the **Filename Leases** (data protection is now handled by Inode leases).
*   **Step 40.3: High-Level Atomic Read (Client)**
    *   **Action:** Implement `ReadDataFiles(ctx, paths []string, targets []any) error`.
    *   **Action:** Coordinate reading and unmarshaling all requested files within the snapshot window.
*   **Step 40.4: Consistency Verification**
    *   **Action:** **Unit Test:** Verify that `ReadDataFiles` successfully blocks a concurrent `SaveDataFile` (atomic swap) on the same path until the path-resolution phase is complete.
    *   **Action:** **Concurrency Test:** Rapidly swap multiple files (e.g., config and key) and verify that the reader always sees a matched pair (never old config with new key).

---

## Phase 41: SERVER-API.md Alignment & Protocol Hardening [COMPLETED]
**Goal:** Align the implementation with the definitive "Source of Truth" specification to ensure cross-language compatibility and protocol stability.

*   **Step 41.1: Cryptographic Wire Format Alignment**
    *   **Action:** [Done] Update `pkg/crypto/sealed.go` to use **Big-Endian** for the 8-byte `Timestamp` in the Sealing protocol.
    *   **Action:** [Done] Align the `ManifestHash` and `Group.Hash` implementations in `pkg/metadata/types.go` to use **Big-Endian** for all binary fields.
    *   **Action:** [Done] Verify byte-perfect segment literals and separators in hashing algorithms against the spec.
*   **Step 41.2: Structured Error Response Implementation**
    *   **Action:** [Done] Create `APIErrorResponse` struct in `pkg/metadata/types.go`.
    *   **Action:** [Done] Implement `writeError(w, code, message, httpStatus)` helper in `MetadataServer`.
    *   **Action:** [Done] Map all internal errors (Conflict, Exists, NotFound, etc.) to their specific `DISTFS_*` string constants defined in Section 8 of `SERVER-API.md`.
*   **Step 41.3: Unified Mutation API Consolidation**
    *   **Action:** [Done] Refactor `LogCommand` in `pkg/metadata/fsm.go` to use `json.RawMessage` for the `Data` field to support structured nested JSON.
    *   **Action:** [Done] Update `handleBatch` in `MetadataServer` to parse structured JSON data without base64 decoding.
    *   **Action:** [Done] Remove all standalone mutation endpoints (`POST /v1/meta/inode`, `PUT /v1/group`, `PUT /v1/meta/inode/{id}`, `DELETE /v1/meta/inode/{id}`, `PUT /v1/meta/directory/{id}/entry`, `POST /v1/meta/setattr`).
    *   **Action:** [Done] Refactor the Go client library and the entire test suite to strictly use the `/v1/meta/batch` API for all state-changing operations.
*   **Step 41.4: Server-Side Lease Enforcement**
    *   **Action:** [Done] Implement mandatory lease verification in the FSM during `executeUpdateInode`, `executeUpdateGroup`, and `applyBatch`.
    *   **Action:** [Done] Reject any mutation if an Exclusive Lease is held by a different `SessionID`.
*   **Step 41.5: Final Protocol Validation**
    *   **Action:** [Done] Add cross-package unit tests that verify hashing and sealing parity between the Go client and a "blind" implementation based strictly on the spec.
    *   **Action:** [Done] Verify that all E2EE-sealed requests and responses adhere to the exact byte offsets defined in the spec.
*   **Step 41.6: CLIENT-API.md Alignment (Go Library)**
    *   **Action:** [Done] Refactor `AcquireLeases` to use `LeaseOptions` struct, including the `OnExpired` callback logic in the background renewal loop.
    *   **Action:** [Done] Implement Go 1.23 Iterators (`iter.Seq` and `iter.Seq2`) for all administrative and group listing functions (`AdminListUsers`, `ListGroups`, etc.).
    *   **Action:** [Done] Standardize the POSIX-like interface in `pkg/client` to use standard Go signatures `(ctx, path, ...)` and return concrete exported types (`*DistFile`, `*DistFileInfo`, `[]*DistDirEntry`).
    *   **Action:** [Done] Ensure all iterator implementations respect `context.Context` cancellation and terminate immediately on the first error.
*   **Step 41.7: Atomic Multi-File Read Implementation**
    *   **Action:** [Done] Implement `NewReaders(ctx, paths []string) ([]*FileReader, error)` in `pkg/client/client.go` using the "Snapshot Protocol" (Shared Filename Leases -> Batch Inode Fetch -> Inode Leases).
    *   **Action:** [Done] Implement `ReadDataFiles(ctx, paths []string, targets []any) error` to provide consistent point-in-time reads across multiple files.
    *   **Action:** [Done] Add integration tests verifying that `ReadDataFiles` provides a consistent view even when files are being swapped by concurrent `SaveDataFile` operations.

---

## Phase 42: ClusterSecret Root of Trust Implementation
**Goal:** Implement a two-tiered trust model to resolve bootstrapping deadlocks and ensure Raft snapshot portability.

*   **Step 42.1: Tier 1 Vault Implementation**
    *   **Action:** Implement `NodeVault` logic in `pkg/metadata/vault.go` to manage local storage of `ClusterSecret` via `st.ReadDataFile`/`st.SaveDataFile`.
*   **Step 42.2: FSM Encryption Refactoring**
    *   **Action:** Update `NewMetadataFSM` to accept `ClusterSecret` and remove legacy `fsm.key` loading.
    *   **Action:** Refactor `fsm.Get` and `fsm.Put` to use `ClusterSecret` for the `system` bucket.
    *   **Action:** Update `syncKeyRing` and `executeRotateFSMKey` to use the new tiered encryption model.
*   **Step 42.3: Join Handshake Evolution**
    *   **Action:** Update `handleClusterJoin` to encapsulate the `ClusterSecret` for the joining node.
    *   **Action:** Update `AdminJoinNode` or the corresponding internal logic to handle secret retrieval and persistence.
*   **Step 42.4: storage-node Alignment**
    *   **Action:** Update `main.go` to load/generate `ClusterSecret` before FSM initialization.
    *   **Action:** Simplify `verifyJWT` to use the memory-resident `ClusterSecret`.
*   **Step 42.5: Verification & Cleanup**
    *   **Action:** Verify that joining nodes can successfully restore snapshots and bootstrap their KeyRings.
    *   **Action:** Remove all remaining plaintext `cluster_secret` logic from the FSM.

---

## Phase 43: Metadata Structural Integrity & Atomic Mutations
**Goal:** Enforce filesystem-level structural consistency in the Metadata Layer and implement truly atomic directory mutations.

*   **Step 43.1: FSM Structural Validation Logic**
    *   **Action:** Implement `validateStructuralConsistency` in `pkg/metadata/fsm.go`.
    *   **Consistency Rules:**
        1.  **NLink Delta:** `NLink` changes must match `Dir.Children` additions/removals in the batch.
        2.  **Bidirectionality:** New directory entries must have reciprocal `Inode.Links` entries.
        3.  **Type Constraints:** Directories must have `NLink <= 1` (no hard links). Non-directories must have `len(Children) == 0`.
        4.  **Root Protection:** Prohibit `NLink=0` or `DeleteInode` for any Inode where `len(Links) == 0` (Roots).
    *   **Enforcement:** Reject batches that would result in inconsistent link counts or orphaned entries.
*   **Step 43.2: Non-Empty Directory Protection**
    *   **Action:** Update `executeDeleteInode` to reject deletion if `len(inode.Children) > 0`.
*   **Step 43.3: Client-Side Atomic AddEntry**
    *   **Action:** Refactor `AddEntry` in `pkg/client/directory.go` to bundle `CmdCreateInode` (child) and `CmdUpdateInode` (parent) into a single atomic `LogCommand` batch.
*   **Step 43.4: Client-Side Atomic RemoveEntry**
    *   **Action:** Refactor `RemoveEntryRaw` to bundle parent update and child `NLink` decrement into one atomic batch.
*   **Step 43.5: Client-Side Atomic Rename**
    *   **Action:** Refactor `RenameRaw` to bundle all involved inode updates (source parent, target parent, moved child) into one atomic batch.
*   **Step 43.6: Testing & Verification**
    *   **Action:** Add FSM unit tests for structural inconsistency rejection.
    *   **Action:** Rerun `TestAddEntryRegression` and `TestFUSE_POSIXCompliance` to verify metadata stability.

### Phase 43 Testing Strategy:
1.  **Inconsistent Batch Test:** Attempt to add a file to a directory without incrementing the file's `NLink` in the same batch; verify the server rejects the batch.
2.  **Orphaned Entry Test:** Attempt to create an Inode without linking it in any parent; verify rejection (except for Root).
3.  **Non-Empty Rmdir Test:** Verify `os.Remove` fails on a directory containing files.

---

## Phase 44: Hardware Security (TPM Integration)
**Goal:** Implement optional Trusted Platform Module (TPM) support to bind node identity and master secrets to physical hardware.

*   **Step 44.1: Abstract Identity Interfaces**
    *   **Action:** Refactor `pkg/metadata/node_identity.go` so `NodeKey` utilizes the `crypto.Signer` interface rather than concrete `ed25519` types.
    *   **Action:** Update `GenerateSelfSignedCert` in `pkg/metadata/raft_manager.go` to accept the generic interface.
*   **Step 44.2: TPM-Backed Node Identity (mTLS)**
    *   **Action:** Modify `LoadOrGenerateNodeKey` to optionally accept a `*tpm.TPM` instance. When provided, generate an ECC P-256 key within the TPM and persist its serialized handle instead of raw private key bytes.
*   **Step 44.3: Hardware-Bound Master Key**
    *   **Action:** Add `-use-tpm` flag to `cmd/storage-node`.
    *   **Action:** Implement logic to derive a hardware-bound `HardwareHash` by performing an HMAC over the `DISTFS_MASTER_KEY` environment variable using a TPM-managed key. Use this hash to initialize the local `storage_crypto` layer.
*   **Step 44.4: Client-Side Integration**
    *   **Action:** Add `-use-tpm` to `cmd/distfs` and `cmd/distfs-fuse`. Replicate the TPM HMAC wrapping logic for `DISTFS_PASSWORD`.
*   **Step 44.5: Testing & Verification**
    *   **Action:** Verify the standard (non-TPM) build path works unmodified.
    *   **Action:** Manually test node bootstrap and client mounting on a TPM-enabled instance.

### Phase 44 Testing Strategy:
1.  **Backward Compatibility:** Run all existing E2E tests without `-use-tpm` to ensure `ed25519` defaults remain fully functional.
2.  **TPM Interface Integrity:** Ensure unit tests for `node_identity.go` pass when providing a mock or interface-compliant TPM key struct.

---

## Phase 45: Privacy & ECH Integration
**Goal:** Integrate `github.com/c2FmZQ/ech` into all client-initiated HTTP clients to encrypt SNI (Encrypted Client Hello) and secure DNS queries (DNS-over-HTTPS).

*   **Step 45.1: Client Library Update**
    *   **Action:** Modify `pkg/client/client.go` to use `ech.NewTransport()` for the primary `httpClient`.
    *   **Action:** Add `WithDisableDoH(disable bool)` to allow fallback to the standard system resolver for internal/testing environments.
*   **Step 45.2: Server Internal Clients Update**
    *   **Action:** Modify `pkg/metadata/server.go` to accept a `disableDoH` parameter in `NewServer`.
    *   **Action:** Instantiate `ech.NewTransport()` for `s.httpClient` and `s.discoveryHTTPClient`, applying the appropriate TLS configurations.
*   **Step 45.3: CLI Flags & Configuration**
    *   **Action:** Add the `-disable-doh` flag to `cmd/distfs`, `cmd/distfs-fuse`, and `cmd/storage-node`.
    *   **Action:** Plumb this flag through to the respective client builders and server initializers.
*   **Step 45.4: Test Infrastructure Adaptation**
    *   **Action:** Update `docker-compose.yml` to pass `-disable-doh` to all `storage-node` instances.
    *   **Action:** Update all `scripts/test-*.sh` scripts to pass `-disable-doh` to `distfs` and `distfs-fuse` commands, as the local Docker network relies on standard DNS, not public DoH resolvers.
*   **Step 45.5: Verification**
    *   **Action:** Run `go test -failfast ./...` and `./scripts/run-tests.sh --skip-unit` to ensure the fallback resolver works correctly in the test environment while the code is wired for ECH by default.
