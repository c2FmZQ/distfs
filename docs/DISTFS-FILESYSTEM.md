# DistFS Filesystem Operations & Cryptography

This document provides an analysis of the DistFS filesystem architecture. It details the strict separation of responsibilities between the untrusted server and the cryptographic client, the establishment of trust, and the execution of cryptographic protocols.

## 1. Separation of Responsibilities

DistFS operates under a strict "Trust No One" model. The server infrastructure is treated as an untrusted persistence and coordination layer.

### 1.1 Server Responsibilities
*   **Metadata Enforcement:** The server maintains the file system graph via Raft, enforcing referential integrity.
*   **Concurrency Control:** The server utilizes Optimistic Concurrency Control (OCC) and Server-Side Leases for POSIX compliance.
*   **Resource Management:** The server enforces multi-tenant quotas at the User and Group levels.

### 1.2 Client Responsibilities
*   **Data Encryption:** All file content and sensitive metadata are encrypted by the client before transmission.
*   **Data Chunking:** The client splits file data into uniform 1MB chunks.
*   **Authorization:** Access control is entirely cryptographic using ML-KEM and ML-DSA.

## 2. Filesystem Identity

Identity in DistFS is decentralized and cryptographically enforced.

### 2.1 User Identity
A user's identity is defined by a pair of PQC keys:
*   **SignKey (ML-DSA):** Proves **Attribution**.
*   **EncKey (ML-KEM):** Proves **Authorization**.

### 2.2 Server and Cluster Identity
*   **ClusterSignKey (ML-DSA):** Used by the cluster to notarize the metadata timeline (`ClusterSig`).
*   **Epoch Keys:** Rotating symmetric keys used to protect Layer 7 traffic.

### 2.3 Strict Hierarchical Ownership
Access to manage sensitive metadata (Groups and Inodes) is governed by a strict hierarchy. A resource $R$ can only be modified by:
1.  The **Direct Owner** of $R$.
2.  An **Ancestor Owner** (if $R$ is owned by a group, the group's owner or parents can manage it).
3.  A verified **Administrator** (subject to specific provisioning constraints).
This hierarchy is enforced by the Raft FSM during log application, ensuring that cryptographic authority cannot be bypassed even if the server is compromised.

## 3. Establishing Trust

Trust is established using a self-sovereign, recursive verification model.

### 3.1 Sovereign Bootstrap
The cluster is anchored by the first registered user ("Alice").

### 3.2 Aggregate Optimistic Verification
To maintain high performance without compromising security, DistFS uses **Aggregate Optimistic Verification**.
1.  **Optimistic Phase:** Clients fetch Inodes and Groups from the server and provisionally use the provided keys to reduce latency.
2.  **Confirmation Phase:** All fetched IDs are added to a verification queue. The client asynchronously resolves the recursive registry attestations back to a trusted anchor (Alice) in the `/registry`.
3.  **Blocking Safety:** Any "high-trust" operation (e.g., decapsulating a file key or verifying a mutation) blocks until the corresponding identities are formally verified.

## 4. Cryptographic Operations

### 4.1 Layer 7 End-to-End Encryption (E2EE)
Requests are packaged as `SealedRequest` envelopes (see `DISTFS-RAFT.md`).

### 4.2 Data Encryption (Chunks and ClientBlobs)
*   **AES-256-GCM:** Used for all symmetric encryption.
*   **ClientBlobs:** Sensitive Inode metadata (filenames, symlink targets) is encrypted into an opaque `ClientBlob` using the **File Key**.
*   **Chunks:** File data encrypted with the File Key and a unique nonce.
*   **Opaque Paths (Dark Forest):** To hide the directory hierarchy from the server, filenames are indexed using keyed HMACs: `nameHMAC = Hex(HMAC(Parent_FileKey, plaintext_filename))`. The server only sees these opaque hmacs as map keys in the `Children` and `Links` maps.

### 4.3 Lockboxes and Trial Decryption
Access to the **File Key** is obtained via decapsulation of a `Lockbox` entry using ML-KEM.

### 4.4 Group Forward Secrecy & Epoch Ratcheting
Groups manage access via a rotating **Epoch Seed**.
1.  **Epoch Advancement:** When a member is removed, the Group Manager rotates the Epoch Seed.
2.  **Ratcheting:** Each Epoch Seed $S_t$ can be used to derive the previous seed $S_{t-1}$ via a one-way hash-based ratchet: $S_{t-1} = H(S_t)$. This allows current members to access legacy files.
3.  **Forward Secrecy:** Because the ratchet is a one-way function, a removed member possessing $S_{t-1}$ cannot derive $S_t$.

### 4.5 Zero-Knowledge Key Synchronization (Recovery)
To allow cross-device recovery, DistFS supports **Key Synchronization**.
1.  **Key Derivation:** The client derives a high-entropy **Wrapping Key** ($K_w$) from the user's password using the Argon2id memory-hard function.
2.  **Sealing:** The user's private identity keys and configuration are encrypted (sealed) with $K_w$ using AES-GCM and stored as a `KeySyncBlob` on the server.
3.  **Zero-Knowledge:** The server only sees the opaque ciphertext. Without the password, the server cannot derive $K_w$ or access the private keys.

### 4.6 Secure Capability Delegation (Storage Access)
Storage nodes (DataNodes) only accept requests authorized by a cryptographically signed **Capability Token**.
1.  **Issuance:** The MetaNode Leader issues a token containing specific `ChunkIDs`, an access mode ("R" or "W"), and an expiry time.
2.  **Signature:** The token is signed using the cluster's **ClusterSignKey** (ML-DSA).
3.  **Verification:** The DataNode verifies the signature before processing the request, ensuring that only metadata-authorized clients can access raw blocks.

## 5. Formal Cryptography Proofs

### 5.1 Definitions
Let $\mathcal{U}$ be the set of all identities.
Let $PK_u, SK_u$ be the keypair for user $u$.
Let $\mathcal{T}$ be the set of trusted users.

### 5.2 Theorem 1: Trust Model Security (Identity Spoofing)
**Theorem:** If ML-DSA is Existentially Unforgeable under Chosen Message Attack (EUF-CMA), the DistFS trust model is secure against unauthorized identity spoofing.

**Proof Sketch:**
Assume there exists an adversary $\mathcal{A}$ that can output a forged attestation $A^*(Alice, w)$ for some user $w$. We construct a reduction $\mathcal{B}$ that uses $\mathcal{A}$ to break the EUF-CMA security of ML-DSA.
1.  $\mathcal{B}$ receives a public key $PK^*$ from the ML-DSA challenger.
2.  $\mathcal{B}$ sets $PK_{Alice} = PK^*$ and starts $\mathcal{A}$.
3.  $\mathcal{B}$ answers $\mathcal{A}$'s registration and attestation queries by acting as a proxy to its own signing oracle.
4.  Eventually, $\mathcal{A}$ outputs a forged attestation $A^*(Alice, w) = \sigma^*$.
Since $\mathcal{A}$ wins, $\sigma^*$ is a valid signature on $PK_w$ under $PK_{Alice}$. Thus, $\mathcal{B}$ outputs $(PK_w, \sigma^*)$, breaking the EUF-CMA security of ML-DSA. Since ML-DSA is assumed secure, the probability of $\mathcal{A}$ succeeding is negligible.

### 5.3 Theorem 2: Data Integrity
**Theorem:** If AES-GCM is unforgeable (AEAD), the hash function provides Second Preimage Resistance (SPR), and ML-DSA is EUF-CMA secure, then the integrity of DistFS file data is preserved.

**Proof Sketch:**
Let a file $F$ consist of chunks $c_1, \dots, c_n$. Encryption is $E_k(N_i, c_i) = (C_i, T_i)$ and ChunkID is $ID_i = H(N_i || C_i || T_i)$. The Inode manifest $M = [ID_1, \dots, ID_n]$ is signed as $\sigma_M = Sign(SK_{owner}, M)$.
An adversary $\mathcal{A}$ attempting to modify a chunk without detection has three avenues:
1.  **AEAD:** Modifying $(C_i, T_i)$ without $k$ is prevented by AEAD unforgeability. Even with $k$, the new $ID_i^*$ won't match the signed manifest.
2.  **SPR:** Finding a different chunk that hashes to the same $ID_i$ is prevented by the Second Preimage Resistance of the hash function.
3.  **EUF-CMA:** Modifying the manifest $M$ requires forging the owner's signature $\sigma_M$, which is prohibited by Theorem 1.
Thus, tampering is detected with overwhelming probability.

### 5.4 Theorem 3: Metadata Attribution & Delegation
**Theorem:** An adversary cannot modify an Inode or forge a file without being identified.

**Proof Sketch:**
Every `Inode` contains a `UserSig` ($\sigma_I = Sign(SK_{signer}, Hash(Inode))$).
1.  **Verification:** The client verifies $\sigma_I$ against the `SignKey` bound to `SignerID` in the `/registry`.
2.  **Delegation:** If `SignerID != OwnerID`, the client additionally requires and verifies an `OwnerDelegationSig` ($\sigma_D = Sign(SK_{owner}, Hash(ID || GroupID))$), proving the owner authorized the group/ACL containing the signer.
3.  **Admin Bypass:** For initial provisioning, an authenticated Admin is permitted to sign **empty directories** for other users without an `OwnerDelegationSig`. This is a controlled exception for administrative setup and does not compromise data integrity, as the directory contains no children or file keys.
4.  **Reduction:** Forging either $\sigma_I$ or $\sigma_D$ requires breaking the EUF-CMA security of ML-DSA. Therefore, all metadata mutations are cryptographically attributable and verifiable.

### 5.5 Theorem 4: Zero-Knowledge Confidentiality
**Theorem:** The storage nodes (server) cannot access plaintext user data.

**Proof Sketch:**
1.  **Encryption:** Data is encrypted via AES-GCM with a random File Key $k$.
2.  **Lockbox:** $k$ is stored in the `Lockbox`, encrypted *only* for authorized recipients using ML-KEM.
3.  **Privacy:** The server only sees encrypted chunks $C$ and the opaque `Lockbox` entries.
4.  **Reduction:** To obtain the plaintext, the server must either break AES-GCM IND-CPA security or decapsulate an ML-KEM entry without the recipient's private key. Both are assumed computationally infeasible. Thus, the server possesses zero knowledge of the data content.

### 5.6 Theorem 12: Group Forward Secrecy
**Theorem:** A removed group member cannot access file data created after their removal.

**Proof Sketch:**
Let $S_t$ be the epoch seed for epoch $t$. Let a user $u$ be removed at epoch $t$.
1.  **Authorization:** At epoch $t$, $S_t$ is encapsulated only for users in the current membership list $\mathcal{M}_t$. Since $u \notin \mathcal{M}_t$, $u$ cannot obtain $S_t$ via decapsulation.
2.  **One-way Ratchet:** The relationship between seeds is $S_{i-1} = H(S_i)$. By the pre-image resistance of the hash function, it is computationally infeasible to derive $S_i$ from $S_{i-1}$.
3.  **Conclusion:** Even if $u$ possesses $S_{t-1}$ (the seed from before their removal), they cannot derive $S_t$ or any subsequent seed. Therefore, they cannot decapsulate the File Keys for any new files protected by the new epoch, satisfying Forward Secrecy.

### 5.7 Theorem 15: Opaque Path Analysis (Path Privacy)
**Theorem:** An adversary (server) with access to the metadata database cannot determine the plaintext filenames or reconstruct the directory hierarchy.

**Proof Sketch:**
1.  **Identifier Blinding:** Filenames are stored as $nameHMAC = HMAC(Parent\_FileKey, plaintext\_filename)$.
2.  **Dark Forest:** Since $HMAC$ is a **Pseudorandom Function (PRF)** and $Parent\_FileKey$ is high-entropy and only known to authorized clients, the resulting values are indistinguishable from random bitstrings to the server.
3.  **Independence:** The server cannot link a $nameHMAC$ in a directory's `Children` map to the child Inode's `ID` without the cryptographic keys, as the `ID` is itself an unrelated random UUID. Therefore, the server cannot reconstruct the file tree or organizational structure.

### 5.8 Theorem 16: Secure Key Synchronization (Recovery)
**Theorem:** The `KeySync` recovery mechanism does not compromise the Zero-Knowledge mandate.

**Proof Sketch:**
1.  **KDF Security:** The wrapping key $K_w$ is derived using Argon2id, which is resistant to GPU-accelerated dictionary attacks.
2.  **Symmetric Security:** The keys are sealed using AES-GCM (IND-CPA). 
3.  **Privacy:** To access the private keys, an adversary must either break the IND-CPA security of AES-GCM or perform a successful dictionary attack against Argon2id. Provided the user selects a high-entropy password, this is computationally infeasible. Since $K_w$ never leaves the client, the server remains in a Zero-Knowledge state regarding the user's identity keys.

### 5.9 Theorem 20: Strict Hierarchical Ownership
**Theorem:** Resource management permissions correctly propagate through the ownership hierarchy.

**Proof Sketch:**
Let $O(R)$ denote the owner of resource $R$.
1.  **Direct Ownership:** If $O(R) = u$, then $u$ has full management authority.
2.  **Hierarchical Ownership:** If $O(R) = G$ (a Group), the FSM resolves authority by recursively checking $O(G)$. If any ancestor in the ownership chain is the authenticated `signerID`, the mutation is permitted.
3.  **Immutability:** Critical ownership fields (e.g., `Group.OwnerID`) are immutable after creation.
Since the FSM enforces these checks within a deterministic Raft log, the hierarchical chain of trust is strictly maintained.

### 5.10 Theorem 21: Context-Bound Attribution (Move-Resistance)
**Theorem:** An Inode cannot be moved between groups or re-parented without the owner's explicit re-authorization.

**Proof Sketch:**
The `OwnerDelegationSig` ($\sigma_D$) is calculated over the `DelegationHash`, which includes the `Inode.ID` and the `Inode.GroupID`.
1.  **Context Binding:** By including the `GroupID` in the signed hash, the owner cryptographically binds their delegation to a specific group context.
2.  **Mutation Check:** If a user attempts to move an Inode to a different group, the `GroupID` changes.
3.  **Verification Failure:** The existing $\sigma_D$ will fail verification against the new `GroupID`.
Therefore, a non-owner cannot move a file to a group they control to bypass access rules without obtaining a new signature from the owner.

### 5.11 Theorem 22: Cryptographic ACL Enforcement
**Theorem:** Filesystem permissions (ACLs) are immutable to the metadata server and bound to the owner's cryptographic signature.

**Proof Sketch:**
Both the `ManifestHash` (for the owner) and the `DelegationHash` (for delegated signers) include the deterministically sorted representation of the `AccessACL` and `DefaultACL`.
1.  **Integrity Binding:** Any modification to the ACLs by the server will result in a mismatch with the cryptographic hashes.
2.  **Signature Requirement:** To commit a valid ACL change, the server must provide a new `UserSig` or `OwnerDelegationSig`.
By the EUF-CMA security of ML-DSA, the server cannot produce these signatures. Thus, permissions are cryptographically anchored to the owner's intent.

### 5.12 Theorem 23: Storage Isolation (Chunk Unlinkability)
**Theorem:** The storage nodes (DataNodes) cannot determine which chunks belong to the same file or which user owns them.

**Proof Sketch:**
1.  **Flat Namespace:** Chunks are stored in a flat namespace indexed by their `ChunkID` (a hash of ciphertext).
2.  **Fixed Size:** All chunks are uniform 1MB blocks, preventing size-based correlation.
3.  **Token Blindness:** The `CapabilityToken` used to authorize DataNode access contains only the `ChunkIDs` and the requested mode. It does not contain `FileIDs`, `UserIDs`, or parent directory information.
Since the mapping between files and chunks (the `Manifest`) is encrypted and stored only on MetaNodes, the DataNode possesses no metadata linking isolated blocks together.

### 5.13 Theorem 24: Multi-Level Cache Integrity (Optimistic Safety)
**Theorem:** Aggregate Optimistic Verification ensures that client-side caches do not weaken the security model.

**Proof Sketch:**
1.  **Verification Queue:** All fetched IDs are added to a background verification queue.
2.  **Atomic Confirmation:** Any operation requiring a "high-trust" key (e.g., decapsulating a file key or verifying a mutation) blocks until the corresponding identity attestation has been recursively verified back to a trusted anchor (Alice) in the `/registry`.
3.  **Cache Invalidation:** If a registry check reveals a key mismatch or revoked attestation, the cache is invalidated and the operation is aborted.
Therefore, while the client *fetches* data optimistically, it only *trusts* data that has passed formal cryptographic verification, maintaining the "Trust No One" model.

### 5.14 Theorem 26: Secure Capability Delegation
**Theorem:** DataNodes only accept storage requests authorized by the MetaNode cluster.

**Proof Sketch:**
DataNode access requires a `CapabilityToken` signed by the cluster's `ClusterSignKey` (ML-DSA).
1.  **Short-lived:** Tokens have a short expiry time (TTL).
2.  **Attestation:** The DataNode verifies the cluster's signature before serving any block.
3.  **Session Binding:** Tokens can be cryptographically bound to the client's session identifier.
By the EUF-CMA security of the cluster key, an adversary cannot self-issue access tokens. Access is strictly delegated by the metadata layer, enforcing global consistency and permissions at the storage layer.

**Known Weakness: Replay / Rollback Attacks (Stale Manifests)**
*TODO: The DistFS implementation must be updated to incorporate a monotonic version number within the Inode signature that the client verifies against a strictly linearizable registry.*
