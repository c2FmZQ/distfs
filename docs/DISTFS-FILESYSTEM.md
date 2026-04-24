# DistFS Filesystem Operations & Cryptography

This document provides an analysis of the DistFS filesystem architecture. It details the strict separation of responsibilities between the untrusted server and the cryptographic client, the establishment of trust, and the execution of cryptographic protocols.

## 1. Separation of Responsibilities

DistFS operates under a strict "Trust No One" model. The server infrastructure is treated as an untrusted persistence and coordination layer.

### 1.1 Server Responsibilities
*   **Metadata Enforcement:** The server maintains the file system graph via Raft, enforcing referential integrity (e.g., preventing directory loops, ensuring correct link counts).
*   **Concurrency Control:** The server utilizes Optimistic Concurrency Control (OCC) via incremental versioning and provides strict linearizability through lease management.
*   **Resource Management:** The server enforces multi-tenant quotas (Inodes and Bytes) at the User and Group levels, dynamically resolving the primary debtor based on the `QuotaEnabled` flag.
*   **POSIX Semantics:** The server manages open file handles, usage leases, and deferred deletions to ensure high-fidelity POSIX compliance (e.g., unlinked files remain on disk until all handles are closed).

### 1.2 Client Responsibilities
*   **Data Encryption:** All file content and sensitive metadata (filenames, symlink targets) are encrypted by the client before transmission.
*   **Data Chunking:** The client splits file data into uniform 1MB chunks, handling necessary padding to obfuscate exact file sizes.
*   **Authorization:** Access control is entirely cryptographic. The client encapsulates symmetric keys using Post-Quantum asymmetric algorithms (ML-KEM) and signs metadata mutations (ML-DSA) to prove authorization.

## 2. Filesystem Identity

Identity in DistFS is decentralized and cryptographically enforced, removing the need for a central Certificate Authority.

### 2.1 User Identity
A user's identity is defined by a pair of Post-Quantum Cryptography (PQC) keys:
*   **SignKey (ML-DSA):** Used to sign Inode mutations and attestations. This proves **Attribution**.
*   **EncKey (ML-KEM):** Used to decapsulate symmetric file keys from the Inode Lockbox. This proves **Authorization**.

The unique `UserID` is not the user's public key, but an opaque identifier derived from their OIDC subject claim and the cluster's `ClusterSecret` (see `DISTFS-RAFT.md`).

### 2.2 Server and Cluster Identity
*   **ClusterSignKey (ML-DSA):** An asymmetric key pair owned by the cluster quorum. It is used to notarize the metadata timeline (`ClusterSig`) and sign registry attestations for system-level groups and users.
*   **Epoch Keys:** Rotating symmetric keys used to protect Layer 7 traffic (`SealedEnvelope`).

### 2.3 The Sovereign Anchor
The cluster is anchored by the first registered user ("Alice"). Alice initializes the filesystem root (`/`) and establishes the root of the **Sovereign Chain of Trust** by self-signing her own attestation file in the registry.

## 3. Establishing Trust

Trust is established using a self-sovereign, recursive verification model.

### 3.1 Sovereign Bootstrap
1.  Alice generates her PQC identity.
2.  Alice registers and initializes the system namespaces (`/registry`, `/users`).
3.  Alice creates a self-signed attestation (`/registry/alice.user`), binding her `UserID` to her public keys.

### 3.2 Optimistic Verification
To prevent blocking I/O operations while verifying identity attestations in the distributed `/registry`, DistFS uses Aggregate Optimistic Verification.

1.  **Optimistic Phase:** The client traverses the file system, fetching Inodes and verifying their signatures using keys provided by the server. It proceeds optimistically, queuing the `SignerID` and `OwnerID` for later verification.
2.  **Confirmation Phase:** The client asynchronously fetches the registry attestations (e.g., `/registry/<ID>.user`) for all queued IDs and verifies them against the trusted anchor (Alice) or verified intermediaries.
3.  **Cross-Check:** The client ensures the keys used in the Optimistic Phase match the verified registry attestations. Failure immediately aborts the operation.

## 4. Cryptographic Operations

DistFS employs a defense-in-depth cryptographic strategy protecting data in transit, at rest, and against metadata tampering.

### 4.1 Layer 7 End-to-End Encryption (E2EE)
Requests are packaged as `SealedRequest` envelopes, encrypted using an ephemeral symmetric key encapsulated for the cluster's active, rotating **Epoch Key** (ML-KEM). Responses are symmetrically encrypted for the client. This prevents network infrastructure from analyzing traffic patterns.

### 4.2 Data Encryption (Chunks and ClientBlobs)
*   **AES-256-GCM:** Used for all symmetric encryption.
*   **ClientBlobs:** Sensitive Inode metadata (filenames, ACLs) is encrypted into an opaque `ClientBlob` using a unique **File Key**.
*   **Chunks:** File data is chunked into 1MB blocks, encrypted with the File Key and a unique nonce, and hashed to produce the `ChunkID`.

### 4.3 Lockboxes and Trial Decryption
When a client access a file, it derives the File Key from the Inode's `Lockbox`. The Lockbox contains the File Key encrypted for authorized recipients (Users or Groups) using ML-KEM.

## 5. Formal Cryptography Proofs

### 5.1 Definitions
Let $\mathcal{U}$ be the set of all identities in the system.
Let $PK_u$ and $SK_u$ denote the public and private keypair (ML-DSA) for user $u$.
Let $A(u, v) = Sign(SK_u, PK_v)$ denote an attestation.
Let $\mathcal{T}$ be the set of trusted users, initially $\mathcal{T} = \{Alice\}$.

### 5.2 Theorem 1: Trust Model Security (Identity Spoofing)
**Theorem:** If ML-DSA is Existentially Unforgeable under Chosen Message Attack (EUF-CMA), the DistFS trust model is secure against unauthorized identity spoofing.

**Proof Sketch:** An adversary $\mathcal{A}$ attempting to win a Trust Game must output a forged attestation $A^*(Alice, w)$ for a user $w$. We can reduce this to breaking the EUF-CMA security of ML-DSA. If $\mathcal{A}$ can forge a valid signature $\sigma^*$ for $PK_w$ under Alice's public key $PK_{Alice}$ without the private key $SK_{Alice}$, then $\mathcal{A}$ has broken the underlying signature scheme. Since ML-DSA is assumed EUF-CMA secure, the probability of this is negligible.

### 5.3 Theorem 2: Data Integrity
**Theorem:** If AES-GCM is unforgeable (AEAD), the hash function provides Second Preimage Resistance (SPR), and ML-DSA is EUF-CMA secure, then the integrity of DistFS file data is preserved.

**Proof Sketch:** An adversary $\mathcal{A}$ must present a modified chunk $(N_i^*, C_i^*, T_i^*)$ that is accepted as valid.
1.  **AEAD:** Modifying $C_i$ or $T_i$ without the key $k$ is prevented by AEAD unforgeability.
2.  **SPR:** Finding a different chunk that hashes to the same $ID_i$ is prevented by the Second Preimage Resistance of the hash function.
3.  **EUF-CMA:** Modifying the manifest $M$ in the Inode requires forging the owner's ML-DSA signature $\sigma_M$, which is prohibited by Theorem 1.
Thus, tampering is detected with overwhelming probability.

### 5.4 Theorem 3: Metadata Attribution & Delegation
**Theorem:** An adversary cannot modify an Inode or forge a file without being identified.

**Proof Sketch:** Every `Inode` contains a `UserSig` ($\sigma_I = Sign(SK_{signer}, Hash(Inode))$). If the signer is not the owner, the client requires an `OwnerDelegationSig` ($\sigma_D = Sign(SK_{owner}, Hash(ID || GroupID))$). Forging either $\sigma_I$ or $\sigma_D$ requires breaking the EUF-CMA security of ML-DSA. Therefore, all metadata mutations are cryptographically attributable and verifiable.

### 5.5 Theorem 4: Zero-Knowledge Confidentiality
**Theorem:** The storage nodes (server) cannot access plaintext user data.

**Proof Sketch:** Data is encrypted via AES-GCM with a File Key $k$. $k$ is stored in the `Lockbox`, encrypted *only* for authorized recipients using ML-KEM. The server only sees encrypted chunks and the opaque Lockbox. To obtain the plaintext, the server must either break AES-GCM IND-CPA security or decapsulate an ML-KEM entry without the recipient's private key. Both are assumed computationally infeasible.

**Known Weakness: Replay / Rollback Attacks (Stale Manifests)**
This proof does not prevent an adversary from replacing the current Inode with an older, validly signed version.
*TODO: The DistFS implementation must be updated to incorporate a monotonic version number within the Inode signature that the client verifies against a strictly linearizable registry to explicitly prevent rollback attacks.*
