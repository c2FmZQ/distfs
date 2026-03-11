# DistFS: A Research File System for Zero-Knowledge, Post-Quantum Environments

DistFS is an experimental distributed, end-to-end encrypted (E2EE) file system designed to explore the boundaries of zero-knowledge privacy, strongly consistent metadata, and post-quantum cryptography (PQC) within a POSIX-compliant architecture.

This project serves as a research platform demonstrating how to map standard, highly-dynamic file system semantics—such as atomic renames, granular POSIX Access Control Lists (ACLs), and differential sync—into a completely opaque, untrusted distributed storage infrastructure without leaking structure or content.

---

## Core Research Pillars

DistFS is built upon three foundational technical principles:

1.  **Strict Zero-Knowledge Privacy:** The server infrastructure must never possess plaintext user data, filenames, or directory structures. All encryption, decryption, and access-control matrix expansions occur exclusively at the client boundary.
2.  **Consensus-Driven Metadata:** File system state, namespace consistency, and distributed locking are managed by a Raft consensus cluster to prevent split-brain scenarios and ensure a unified view across all distributed clients.
3.  **Post-Quantum Readiness:** All identity management, key encapsulation, and server-client communication are secured using National Institute of Standards and Technology (NIST) standardized Post-Quantum Cryptography (ML-KEM-768/Crystals-Kyber) to safeguard against future quantum-cryptanalytic threats.

---

## Key Security Features & Architectural Mechanisms

The following details the specific mechanisms DistFS uses to enforce its security guarantees while maintaining high-performance file system operations.

### 1. Cryptographic Provenance (The Immutable Owner)
In a zero-knowledge system, a compromised metadata server could theoretically alter the `OwnerID` of a file, allowing a malicious actor to rewrite the file and self-sign the payload. 
**The Mechanism:** DistFS solves this by mathematically binding the opaque `Inode ID` to the creator's identity via a cryptographic commitment (`ID = hex(SHA256(OwnerID || "|" || Nonce))[:32]`). 
**The Benefit:** The file's true ownership is immutable and verifiable by any client. The server cannot silently reassign ownership or spoof payloads, guaranteeing strict data provenance.

### 2. POSIX ACL Cryptographic Expansion (The Lockbox)
Implementing POSIX.1e Access Control Lists (ACLs) in an E2EE environment presents a unique challenge: the server can enforce access rules, but the client still needs the decryption key.
**The Mechanism:** DistFS implements a dynamic "Lockbox." When a FUSE client executes a `setfacl` command to grant a specific user read access, the client fetches that user's public key, encrypts the AES-256-GCM `File Key`, and appends this ciphertext to the Inode's metadata Lockbox. 
**The Benefit:** It provides high-fidelity POSIX ACL interoperability natively through FUSE xattrs (`system.posix_acl_access`), while preserving true mathematical end-to-end encryption. The server enforces the POSIX mask algorithm but remains blind to the data.

### 3. Layer 7 End-to-End Encryption (Sealing)
Standard TLS only protects data in transit to the edge proxy or load balancer. 
**The Mechanism:** DistFS implements "Sealed Requests." Every sensitive API mutation is encrypted against a rotating, post-quantum `Cluster Epoch Key` and cryptographically signed using the client's ML-DSA identity key.
**The Benefit:** Intermediate infrastructure (proxies, WAFs, load balancers) cannot observe, intercept, or manipulate the metadata layer. The file system topology remains completely opaque to network intermediaries.

### 4. The "Dark Registry" (Anonymized Identity)
Traditional systems leak PII (emails, usernames) in their internal databases.
**The Mechanism:** DistFS hashes all user and group identities using `HMAC-SHA256(Email, ClusterSecret)`.
**The Benefit:** The server operates on opaque cryptographic UUIDs. Even if the entire BoltDB database is exfiltrated, user emails and access patterns cannot be reverse-engineered without the heavily guarded `ClusterSecret`.

### 5. Out-Of-Band (OOB) Governed Identity Verification
To prevent Sybil attacks where an adversary registers thousands of identities, DistFS separates authentication from authorization.
**The Mechanism:** After authenticating via OpenID Connect (OIDC), the user's PQC identity is placed in a `Locked` state. The user exchanges a 6-digit cryptographic verification code Out-Of-Band with a cluster Administrator. The Admin then signs an attestation to unlock the account.
**The Benefit:** Enforces a Zero-Trust onboarding model where only explicitly verified physical devices are granted storage quotas and network access.

### 6. Hedged Reads & Differential Synchronization
Operating a file system over a network introduces significant latency hurdles.
**The Mechanism:** 
*   **Hedged Reads:** When fetching a 1MB encrypted chunk, the client queries the primary replica. If it does not respond within a strict sub-second threshold, the client fires parallel requests to secondary replicas. The first to return successfully cancels the others.
*   **Differential Sync (Fsync):** `fsync` operations do not re-upload the entire file. The client tracks dirty 1MB pages in memory and only encrypts and commits the specifically modified chunks, seamlessly updating the Raft metadata manifest.
**The Benefit:** Mitigates network tail latency and provides near-native file modification performance despite the heavy cryptographic overhead.

---

## System Architecture

DistFS employs a unified node architecture where a single binary (`storage-node`) performs both metadata and data storage roles. 

1.  **Metadata Role:** 3-5 nodes run a strongly consistent BoltDB-backed Raft FSM, managing Inodes, leases, and the Dark Registry.
2.  **Data Role:** All nodes in the cluster participate in an eventually consistent, parallel fan-out storage pool handling the 1MB encrypted data chunks.

```
Client (FUSE)  <-- Sealed JSON / PQC -->  Metadata Cluster (Raft)
      |                                        |
      +------- Encrypted Chunks -------------- + --> Data Node Pool
```

---

## Getting Started

### Prerequisites
*   Linux (kernel support for FUSE 3 required).
*   `fuse3` and `libfuse3-dev` installed locally.
*   Go 1.25 or higher.

### Installation
```bash
git clone https://github.com/c2FmZQ/distfs.git
cd distfs
go build ./cmd/distfs
go build ./cmd/distfs-fuse
go build ./cmd/storage-node
```

### Quick Local Cluster
```bash
export DISTFS_MASTER_KEY="local-dev-secret"
./storage-node --id local-1 --bootstrap --api-addr :8080 --raft-bind :8081
```

### Initializing a Client
```bash
./distfs init --new -server http://localhost:8080
./distfs-fuse -mount ~/my-distfs
```

---

## License
Copyright 2026 TTBT Enterprises LLC. Licensed under the Apache License, Version 2.0.
