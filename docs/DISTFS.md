# DistFS: Secure Distributed File System

DistFS is a high-performance, distributed file system built on a **Zero-Knowledge** foundation. It prioritizes data privacy, end-to-end encryption, and post-quantum security.

## Known Issues and Work in Progress

*   **Verifiable Timeline (Fork-Resistance):** The system currently requires a decentralized transparency log or client gossip mechanism to detect server equivocation and history forking (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Replay / Rollback Attacks (Stale Manifests):** The DistFS implementation must be updated to incorporate a monotonic version number within the Inode signature that the client verifies against a strictly linearizable registry (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).

## 1. Architectural Pillars

*   **Zero-Knowledge:** The server never possesses plaintext data or encryption keys.
*   **Decentralized Trust:** Trust is anchored by a Sovereign User and propagated via a recursive, verifiable registry.
*   **Strong Consistency:** Metadata is managed by a linearizable Raft cluster with server-side leases.
*   **Horizontal Scalability:** Data is sharded into 1MB encrypted chunks distributed across untrusted storage nodes.
*   **Post-Quantum Security:** All asymmetric operations (signing and encapsulation) utilize NIST-standardized PQC primitives.

## 2. Post-Quantum Security & Hybrid Resilience

DistFS is designed for long-term data durability in a post-quantum world. 

### 2.1 PQC Primitives
DistFS utilizes the following NIST Post-Quantum Cryptography (PQC) standards:
*   **ML-DSA (Dilithium):** Used for all digital signatures (Identity, Metadata, Attestations).
*   **ML-KEM (Kyber):** Used for all key encapsulation (Lockboxes, Layer 7 E2EE).

### 2.2 Hybrid Resilience
While DistFS prioritizes PQC, it is architected for **Hybrid Resilience**. Identity keys can be composed of both a PQC component and a classical component (e.g., Ed25519 or ECC). This ensures that the system remains secure if either the PQC primitive is found to have a mathematical weakness or the classical primitive is broken by a quantum computer.

## 3. Formal Cryptography Proofs

The DistFS security model is defined by a series of formal theorems and proofs distributed across the technical documentation.

### 3.1 Trust & Identity
*   **Theorem 1 (Identity Spoofing):** Secure against unauthorized identity injection (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 3 (Metadata Attribution):** All mutations are cryptographically attributable (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 5 (TOFU Join):** Cluster join protocol is MITM-resistant (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 7 (Identity Privacy):** User PII is protected via a Dark Registry (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 11 (Anonymous Membership):** AnonymousLockbox members are mathematically hidden from the server (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 14 (Verifiable Timeline):** Server cannot fork history without detection (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 20 (Hierarchical Ownership):** Authority propagates correctly (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 21 (Move-Resistance):** Bind delegation to group context (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 24 (Optimistic Safety):** Caches do not weaken security (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 25 (Identity Possession):** Login requires private key proof (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 27 (Byzantine Registry):** Registry is immune to server manipulation (see [`DISTFS.md`](DISTFS.md)).

### 3.2 Data Confidentiality & Integrity
*   **Theorem 2 (Data Integrity):** Detection of malicious tampering (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 4 (Zero-Knowledge):** Server cannot access plaintext data (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 6 (FSM Confidentiality):** Metadata is encrypted at rest (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 12 (Forward Secrecy):** Revoked users cannot access new data (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 15 (Path Privacy):** Directory hierarchy is hidden from the server (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 16 (Secure KeySync):** Device recovery is zero-knowledge (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 18 (Byzantine-Resistant Metadata):** Server cannot modify file content (see [`DISTFS.md`](DISTFS.md)).
*   **Theorem 22 (Cryptographic ACLs):** Permissions are bound to owner signature (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).
*   **Theorem 23 (Chunk Unlinkability):** Isolated storage blocks (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).

### 3.3 Network & Resource Security
*   **Theorem 8 (Layer 7 E2EE):** Traffic is protected against analysis (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 9 (Linearizability):** POSIX atomicity is guaranteed (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 10 (Quota Safety):** Multi-tenant resource protection (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 17 (Session PFS):** Ephemeral keys protect past traffic (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 19 (Batch Atomicity):** Multi-inode updates are all-or-nothing (see [`DISTFS-RAFT.md`](DISTFS-RAFT.md)).
*   **Theorem 26 (Capability Delegation):** Storage access is cluster-authorized (see [`DISTFS-FILESYSTEM.md`](DISTFS-FILESYSTEM.md)).

### 3.4 Theorem 13: Quantum-Resistant Hybrid Resilience
**Theorem:** The core security properties of DistFS (Confidentiality and Integrity) are preserved against a Quantum Adversary $\mathcal{A}_Q$.

**Proof Sketch:**
A Quantum Adversary $\mathcal{A}_Q$ can solve the Discrete Logarithm and Integer Factorization problems in polynomial time (Shor's Algorithm), effectively breaking RSA, ECC, and Ed25519.
1.  **Signatures:** All signatures in DistFS use ML-DSA, which is based on the hardness of the Module Learning With Errors (M-LWE) problem. No quantum algorithm is known to solve M-LWE in polynomial time.
2.  **Encapsulation:** All key encapsulation (used for File Keys and E2EE) uses ML-KEM, which is also based on M-LWE.
3.  **Symmetric Primitives:** AES-256-GCM and SHA-256 are used for data encryption and hashing. While Grover's Algorithm provides a square-root speedup, the 256-bit key length and digest size maintain a 128-bit security margin against quantum search.
Therefore, since all critical asymmetric and symmetric operations in DistFS are protected by quantum-resistant primitives, the overall security model is preserved against $\mathcal{A}_Q$.

### 3.5 Theorem 18: Byzantine-Resistant Metadata (Auditability)
**Theorem:** The metadata server is restricted to a Byzantine-Fail-Stop model regarding file content.

**Proof Sketch:**
Every `Inode` contains a `ManifestHash` ($H$) and a `UserSig` ($\sigma = Sign(SK_{owner}, H)$).
1.  **Binding:** $H$ cryptographically binds the chunk IDs, file keys, version, and ownership.
2.  **Immutability:** To modify any field within $H$, an adversary (server) must produce a new valid signature $\sigma'$.
3.  **Verification:** Clients verify $\sigma$ for every fetched Inode.
By the EUF-CMA security of ML-DSA, the server cannot produce a valid $\sigma'$ for a modified $H$. Therefore, the server's only "attack" is to stop serving the Inode (Fail-Stop) or serve a stale version (detected via Theorem 14). It cannot modify the file content or metadata without immediate detection by the client.

### 3.6 Theorem 27: Byzantine-Resistant Registry
**Theorem:** A compromised metadata server cannot silently inject or revoke user identities.

**Proof Sketch:**
The `/registry` is a self-sovereign chain of trust.
1.  **Anchoring:** Clients pin the public key of the Sovereign Anchor (Alice).
2.  **Attestation:** Every identity in the registry is an attestation signed by Alice or a verified administrator.
3.  **Recursive Verification:** Clients recursively verify the signature chain of any user or group back to Alice.
4.  **Immutability:** To inject a fake user or revoke a valid one, the server would need to forge an ML-DSA signature from an authorized anchor.
By the EUF-CMA security of ML-DSA, this is computationally infeasible. Therefore, the registry remains a "Single Source of Truth" that the server can store but never manipulate.
