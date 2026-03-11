# DistFS: Reconciling POSIX Semantics with Zero-Knowledge, Post-Quantum File Storage

DistFS is an experimental distributed, end-to-end encrypted (E2EE) file system. It is designed as a research platform to explore the boundaries of strict zero-knowledge privacy, strongly consistent metadata, and post-quantum cryptography (PQC) within a POSIX-compliant architecture.

The core tension DistFS resolves is the apparent incompatibility between high-fidelity POSIX environments (which require complex, dynamic metadata manipulation like granular ACLs and atomic renames) and a strict zero-knowledge model (where the server cannot read or verify metadata without exposing it). 

We invite researchers, cryptographers, and systems engineers to review, attack, and contribute to this architecture.

---

## 1. Threat Model & Security Assumptions

DistFS operates under an aggressive "Harvest Now, Decrypt Later" threat model where the entire network and storage infrastructure are assumed to be hostile.

*   **Malicious Infrastructure:** We assume the network is compromised, load balancers are tapped, and metadata servers are actively hostile (e.g., attempting to forge file ownership or roll back state).
*   **The Trusted Boundary:** The client machine (and its local memory/FUSE mount) is the *only* trusted boundary. All encryption, decryption, and access-control matrix expansions occur exclusively here.
*   **Out of Scope:** Endpoint compromise (malware on the user's laptop) and absolute denial of service (a server operator simply deleting all hard drives).

---

## 2. Key Cryptographic Mechanisms (Architectural Differentiators)

To survive in a hostile environment while providing a standard UNIX-like experience, DistFS introduces several novel architectural mechanisms.

### 2.1 Post-Quantum Cryptography (PQC) at Layer 7
While modern infrastructure often relies on terminating TLS at an ingress proxy (exposing plaintext metadata to the internal network), DistFS bakes NIST-standardized PQC directly into the application layer. Every Remote Procedure Call (RPC) mutation is a **Sealed Request** encrypted with ML-KEM-768 (Crystals-Kyber) against the cluster's active, rotating Epoch Key. This protects the namespace against future quantum-cryptanalytic attacks even if the internal data center network is fully compromised.

### 2.2 Zero-Knowledge POSIX ACLs (The Lockbox)
Providing granular POSIX.1e Access Control Lists (ACLs) in an E2EE file system requires mapping standard kernel permissions to complex cryptographic key distribution. DistFS maps standard Linux FUSE xattrs (`system.posix_acl_access`) directly into a dynamic cryptographic "Lockbox." 

When a user runs `setfacl -m u:alice:rwx file.txt`, the client intercepts the command, fetches Alice's public key, encrypts the file's symmetric AES-256-GCM key, appends it to the Lockbox, and generates a new ML-DSA signature over the state. The server strictly enforces the POSIX mask algorithm but remains mathematically blind to the actual file data.

### 2.3 Cryptographic Provenance vs. Server Authority
In traditional networked file systems (NFS, Ceph), the metadata server acts as the absolute authority; a compromised server can trivially reassign the `OwnerID` of a file and overwrite the data. DistFS treats its own metadata servers as untrusted. 

An Inode's ID is a mathematical commitment (`ID = hex(SHA256(OwnerID || "|" || Nonce))[:32]`). Furthermore, delegating write access requires a cryptographic `OwnerDelegationSig`. A compromised server literally *cannot* forge file ownership, reassign files, or spoof payloads without failing the client-side cryptographic verification engine.

### 2.4 The "Dark Registry" and OOB Governance
Enterprise file systems typically ingest plaintext Personally Identifiable Information (PII) like emails or usernames into their internal databases. DistFS utilizes a **Dark Registry** where user identities are derived from `HMAC-SHA256(Email, ClusterSecret)`. 

Furthermore, successfully authenticating via Single Sign-On (SSO/OIDC) does *not* immediately grant access. DistFS enforces a Zero-Trust onboarding model requiring an Out-Of-Band (OOB) cryptographic handshake: an Administrator must manually verify a device's 6-digit code and sign a blockchain-style attestation to unlock the account.

### 2.5 Unified Consensus-Driven Metadata + E2EE Sharding
Systems that distribute encrypted blocks over peer-to-peer pools often struggle to provide the strongly ordered, atomic consistency required for standard application workloads (e.g., rapid atomic renames, locking, strict directory DAGs). 

DistFS solves this by using a highly consistent Raft/BoltDB cluster purely to manage the encrypted namespace. This is married to a highly scalable, parallel fan-out storage pool for encrypted 1MB data chunks. It includes tail-latency mitigation (Hedged Reads) and differential syncing where `fsync` only encrypts and uploads dirty chunks rather than full files.

---

## 3. System Architecture

DistFS employs a unified node architecture where a single binary (`storage-node`) performs both metadata and data storage roles. 

1.  **Metadata Role:** 3-5 nodes run a strongly consistent BoltDB-backed Raft FSM, managing Inodes, distributed leases, and the Dark Registry.
2.  **Data Role:** All nodes in the cluster participate in an eventually consistent, parallel fan-out storage pool handling the 1MB encrypted data chunks.

```text
Client (FUSE)  <-- Sealed JSON / PQC -->  Metadata Cluster (Raft)
      |                                        |
      +------- Encrypted Chunks -------------- + --> Data Node Pool
```

---

## 4. Give It a Try (User Manual)

We encourage you to deploy a local test cluster and experiment with the system. 

### 4.1 Prerequisites
*   **Operating System:** Linux (kernel support for FUSE 3 required).
*   **Software:** `fuse3` and `libfuse3-dev` installed locally.
*   **Environment:** Go 1.25 or higher for building from source.

### 4.2 Installation
Clone the repository and build the core binaries:
```bash
git clone https://github.com/c2FmZQ/distfs.git
cd distfs
go build ./cmd/distfs
go build ./cmd/distfs-fuse
go build ./cmd/storage-node
```

### 4.3 Spin Up a Local Cluster
You can quickly bootstrap a single-node testing cluster:
```bash
export DISTFS_MASTER_KEY="local-dev-secret"
./storage-node --id local-1 --bootstrap --api-addr :8080 --raft-bind :8081
```

### 4.4 The Unified Onboarding Flow
DistFS streamlines client initialization by integrating identity generation, OIDC authentication, and secure configuration backup.

**Initialize a new account (This will prompt you for an OIDC token if configured):**
```bash
./distfs init --new -server http://localhost:8080
```

*Note: In a fully secured cluster, an Administrator must unlock your account before you can store data.*

### 4.5 CLI Command Reference
The `distfs` binary provides a set of tools for manual interaction with the encrypted file system.

*   **Namespace Operations:**
    *   `./distfs ls <path>`
    *   `./distfs mkdir <path>`
    *   `./distfs rm <path>`
    *   `./distfs mv <old_path> <new_path>`
*   **Data Operations:**
    *   `./distfs put <local_file> <remote_path>`
    *   `./distfs get <remote_path> <local_file>`

### 4.6 FUSE Integration (POSIX Testing)
Mount the encrypted filesystem directly to your local OS to test POSIX behavior, including ACLs and differential sync.

```bash
mkdir ~/my-distfs
./distfs-fuse -mount ~/my-distfs
```

Once mounted, you can test the Zero-Knowledge POSIX ACLs natively:
```bash
echo "Top secret" > ~/my-distfs/secret.txt
setfacl -m u:user-uuid-here:r-- ~/my-distfs/secret.txt
```
*The FUSE daemon intercepts the `setxattr` call, fetches the target user's public key, and instantly expands the cryptographic Lockbox.*

### 4.7 Cluster Administration
The cluster provides an interactive, PQC-powered administrative console:
```bash
./distfs admin
```
The console provides visibility into Raft replication state, anonymized user inventory, and storage accounting. It is also used to process OOB verifications and explicitly initialize storage roots.

---

## 5. Feedback and Contributions

DistFS is an active research project. We are constantly looking to improve the cryptographic models, performance heuristics, and architectural security. 

*   **Security Audits:** If you find a flaw in the cryptographic provenance, Lockbox expansion, or sealing algorithms, please open an issue.
*   **Performance:** Phase 52 introduced significant GC and latency optimizations (`sync.Pool`, O(1) indices). We welcome benchmarking data and PRs for further zero-copy network paths.
*   **Contributions:** Pull requests are highly encouraged. Please ensure all modifications pass the rigorous test suite: `./scripts/run-tests.sh`.

---

## License

Copyright 2026 TTBT Enterprises LLC. Licensed under the Apache License, Version 2.0.