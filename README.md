# DistFS: User Manual and Documentation

DistFS is a distributed, end-to-end encrypted (E2EE) file system designed for zero-knowledge privacy. It provides a strongly consistent namespace via Raft consensus and a horizontally scalable data layer for sharded chunk storage. 

This manual provides comprehensive documentation for deploying, using, and managing a DistFS cluster.

---

## 1. Core Pillars

DistFS is built upon three foundational technical principles:
*   **Zero-Knowledge Privacy:** File content, filenames, and directory structures are encrypted at the client. The storage infrastructure never possesses plaintext data or encryption keys.
*   **Strong Consistency:** Global namespace operations (creation, deletion, moves) are managed by a Raft consensus group, ensuring a unified view across all nodes and clients.
*   **Post-Quantum Readiness:** Identity management and key encapsulation utilize Post-Quantum Cryptography (PQC) algorithms (ML-KEM-768) to safeguard against future quantum threats.

---

## 2. Getting Started

### 2.1 Prerequisites
*   **Operating System:** Linux (kernel support for FUSE 3 required).
*   **Software:** `fuse3` and `libfuse3-dev` installed locally.
*   **Environment:** Go 1.25 or higher for building from source.

### 2.2 Installation
Clone the repository and build the core binaries:
```bash
git clone https://github.com/c2FmZQ/distfs.git
cd distfs
go build ./cmd/distfs
go build ./cmd/distfs-fuse
go build ./cmd/storage-node
```

---

## 3. The Unified Onboarding Flow

DistFS streamlines client initialization by integrating identity generation, OIDC authentication, and secure configuration backup.

### 3.1 Initializing a New Account
To create a new identity and register with a cluster:
```bash
./distfs init --new -server http://cluster-leader:8080
```
This command performs the following:
1.  Generates PQC identity keys locally.
2.  Executes an OAuth2 Device Flow for federated authentication (OIDC).
3.  Registers your public keys with the Metadata Server.
4.  Encrypts your local configuration with a passphrase using Argon2id.
5.  Pushes an encrypted recovery blob to the server for multi-device sync.

### 3.2 Restoring an Account (New Device)
To restore your identity on a secondary device:
```bash
./distfs init -server http://cluster-leader:8080
```
Provide your OIDC credentials and the original passphrase when prompted to retrieve and decrypt your keys.

---

## 4. CLI Command Reference

The `distfs` binary provides a set of tools for manual interaction with the file system.

### 4.1 Namespace Operations
*   `ls <path>`: List directory contents. Encrypted names are decrypted locally.
*   `mkdir <path>`: Create a new directory.
*   `rm <path>`: Remove a file or empty directory.
*   `mv <old_path> <new_path>`: Move or rename an entry (atomic metadata operation).

### 4.2 Data Operations
*   `put <local_file> <remote_path>`: Encrypt and upload a file. Files under 4KB are automatically inlined in the metadata layer for performance.
*   `get <remote_path> <local_file>`: Download and decrypt a file. Uses hedged reads to mitigate tail latency.

### 4.3 Sharing and Permissions
*   `chmod <mode> <path>`: Update permission bits.
    *   Adding world-read bit (`0004`) automatically adds the "world" recipient to the file's cryptographic lockbox.
*   `chgrp <group_id> <path>`: Assign a file to a group. Group members can unlock the file key using the Group Private Key.

---

## 5. FUSE Integration

Standard OS integration is provided via `distfs-fuse`.

### 5.1 Mounting
```bash
mkdir ~/my-files
./distfs-fuse -mount ~/my-files
```
If no configuration is found in the default location (`~/.distfs/config.json`), the FUSE tool will automatically initiate the onboarding flow.

### 5.2 POSIX Fidelity
DistFS supports a subset of POSIX operations optimized for distributed environments:
*   **Differential Synchronization (Fsync):** `fsync` only re-uploads modified 1MB pages rather than the entire file.
*   **Quota Reporting:** `df -h` on the mount point reflects the user's specific storage and inode quotas.
*   **Incremental ReadDir:** Supports large directories by streaming metadata in batches.

---

## 6. Server Administration

### 6.1 Configuring a Storage Node
Every node requires a master passphrase for its at-rest encryption layer:
```bash
export DISTFS_MASTER_KEY="your-node-passphrase"
```

### 6.2 Bootstrapping a Cluster
Start the primary node with the `--bootstrap` flag:
```bash
./storage-node --id node-1 --bootstrap \
  --api-addr :8080 \
  --raft-bind :8081 \
  --oidc-discovery-url https://auth.example.com/.well-known/openid-configuration
```

### 6.3 Joining Nodes
New nodes must be registered using their public identity key and the cluster secret.
```bash
./storage-node --id node-2 \
  --api-addr :8082 \
  --raft-bind :8083 \
  --raft-advertise node-2-ip:8083 \
  --raft-secret <cluster-secret>
```

### 6.4 Management Dashboard
The cluster provides a lightweight, dependency-free dashboard at `/api/cluster` (requires `X-Raft-Secret` header or session auth). It provides visibility into:
*   Raft replication state and leadership.
*   Cluster-wide storage utilization.
*   Anonymized user accounting and active leases.

---

## 7. Security Model Summary

DistFS employs a defense-in-depth architecture:
*   **Data at Rest:** All local storage (logs, snapshots, chunks) is encrypted using node-local master keys.
*   **Metadata Sealing:** All client-server communication is end-to-end encrypted at Layer 7 using rotating Cluster Epoch Keys.
*   **Anonymization:** Persistent User IDs are HMAC hashes of emails; the server never stores plaintext emails or names in its database.
*   **Secure Entry:** Support for `pinentry` ensures that passphrases never touch the terminal history or process environment.

---

## 8. Technical Specifications

*   **Chunk Size:** 1 MB (Fixed).
*   **Encryption:** AES-256-GCM (Data), ML-KEM-768 (Metadata).
*   **Max File Size:** 100 GB (Soft limit).
*   **Replication Factor:** Default 3 (Configurable).
*   **Consistency:** Strong (Metadata), Eventual/Pipelined (Data).

---

## License

Copyright 2026 TTBT Enterprises LLC. Licensed under the Apache License, Version 2.0.
For full architectural details, see [DESIGN.md](DESIGN.md).
