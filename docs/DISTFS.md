# DistFS: Secure Distributed File System

DistFS is a high-performance, distributed file system built on a **Zero-Knowledge** foundation. It prioritizes data privacy, end-to-end encryption, and post-quantum security.

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
*   **Theorem 1 (Identity Spoofing):** Secure against unauthorized identity injection (see `DISTFS-FILESYSTEM.md`).
*   **Theorem 3 (Metadata Attribution):** All mutations are cryptographically attributable (see `DISTFS-FILESYSTEM.md`).
*   **Theorem 5 (TOFU Join):** Cluster join protocol is MITM-resistant (see `DISTFS-RAFT.md`).
*   **Theorem 7 (Identity Privacy):** User PII is protected via a Dark Registry (see `DISTFS-RAFT.md`).
*   **Theorem 11 (Anonymous Membership):** Group lists are hidden from the server (see `DISTFS-RAFT.md`).

### 3.2 Data Confidentiality & Integrity
*   **Theorem 2 (Data Integrity):** Detection of malicious tampering (see `DISTFS-FILESYSTEM.md`).
*   **Theorem 4 (Zero-Knowledge):** Server cannot access plaintext data (see `DISTFS-FILESYSTEM.md`).
*   **Theorem 6 (FSM Confidentiality):** Metadata is encrypted at rest (see `DISTFS-RAFT.md`).
*   **Theorem 12 (Forward Secrecy):** Revoked users cannot access new data (see `DISTFS-FILESYSTEM.md`).

### 3.3 Network & Resource Security
*   **Theorem 8 (Layer 7 E2EE):** Traffic is protected against analysis (see `DISTFS-RAFT.md`).
*   **Theorem 9 (Linearizability):** POSIX atomicity is guaranteed (see `DISTFS-RAFT.md`).
*   **Theorem 10 (Quota Safety):** Multi-tenant resource protection (see `DISTFS-RAFT.md`).

### 3.4 Theorem 13: Quantum-Resistant Hybrid Resilience
**Theorem:** The core security properties of DistFS (Confidentiality and Integrity) are preserved against a Quantum Adversary $\mathcal{A}_Q$.

**Proof Sketch:**
A Quantum Adversary $\mathcal{A}_Q$ can solve the Discrete Logarithm and Integer Factorization problems in polynomial time (Shor's Algorithm), effectively breaking RSA, ECC, and Ed25519.
1.  **Signatures:** All signatures in DistFS use ML-DSA, which is based on the hardness of the Module Learning With Errors (M-LWE) problem. No quantum algorithm is known to solve M-LWE in polynomial time.
2.  **Encapsulation:** All key encapsulation (used for File Keys and E2EE) uses ML-KEM, which is also based on M-LWE.
3.  **Symmetric Primitives:** AES-256-GCM and SHA-256 are used for data encryption and hashing. While Grover's Algorithm provides a square-root speedup, the 256-bit key length and digest size maintain a 128-bit security margin against quantum search.
Therefore, since all critical asymmetric and symmetric operations in DistFS are protected by quantum-resistant primitives, the overall security model is preserved against $\mathcal{A}_Q$.
