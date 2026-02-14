# DistFS

DistFS is a distributed, end-to-end encrypted file system designed with a "trust-no-one" security model. It provides a strongly consistent namespace via Raft consensus and a scalable data layer for sharded chunk storage. 

The primary goal of the project is to ensure that storage providers have zero knowledge of the user's data or the file system structure.

## Core Principles

*   **Privacy by Default:** All file content and metadata (including filenames and directory structures) are encrypted on the client side before being sent to the cluster.
*   **Zero-Knowledge:** The server never sees plaintext data or encryption keys. Access control is enforced cryptographically.
*   **Strong Consistency:** Metadata operations are managed by a Raft consensus group to ensure a global, consistent view of the file system.
*   **Availability:** Data is sharded into fixed-size chunks and replicated across multiple nodes to protect against hardware failures.
*   **Quantum Readiness:** Identity and key encapsulation rely on Post-Quantum Cryptography (PQC) algorithms.

## Architecture

DistFS utilizes a unified node architecture where each node can perform two roles:
1.  **Metadata Role:** Participates in the Raft group to manage inodes and directories.
2.  **Data Role:** Stores encrypted binary blobs (chunks). Chunks are content-addressed by the hash of their encrypted content.

For more technical details, refer to the [Design Document](DISTFS.md).

## Security Model

*   **Layer 7 E2EE (Sealing):** All metadata requests and responses are wrapped in encrypted envelopes, protecting against inspection by intermediate proxies or load balancers.
*   **Identity:** User identities are based on PQC sign/encrypt key pairs. User IDs are anonymized using a cluster-wide HMAC secret.
*   **At-Rest Encryption:** Nodes leverage `github.com/c2FmZQ/storage` to encrypt all local data (logs, snapshots, and chunks) using a node-local master key.
*   **Multi-Device Sync:** Users can securely synchronize their configuration across devices using a passphrase-encrypted recovery blob stored on the server.

## Getting Started

### Prerequisites

*   Linux environment
*   Go 1.25+
*   `fuse3` and `libfuse3-dev` (for FUSE support)
*   Docker and Docker Compose (for testing)

### Installation

```bash
git clone https://github.com/c2FmZQ/distfs.git
cd distfs
go build ./cmd/...
```

### Running a Cluster

1.  **Configure the Master Key:**
    Every node requires a master passphrase to manage its local encryption.
    ```bash
    export DISTFS_MASTER_KEY="your-node-secret"
    ```

2.  **Start the First Node (Bootstrap):**
    ```bash
    ./storage-node --data-dir ./data/n1 --api-addr :8080 --bootstrap
    ```

3.  **Join Additional Nodes:**
    ```bash
    ./storage-node --data-dir ./data/n2 --api-addr :8081 --raft-bind :8082 --cluster-addr :9091
    # Use the admin API or dashboard to join the node to the cluster.
    ```

## Usage

### 1. Initialize the Client
Generate your local identity and link to a metadata server.
```bash
./distfs init -meta http://localhost:8080
```

### 2. Register via OIDC
Authenticate with an OIDC provider to register your public keys with the cluster.
```bash
# Uses OAuth2 Device Flow by default
./distfs register -client-id <id> -auth-endpoint <url> -token-endpoint <url>
```
The client will automatically extract your email address from the OIDC token to derive your User ID.

### 3. File Operations
```bash
# Create a directory
./distfs mkdir /documents

# Upload a file
./distfs put local-file.txt /documents/remote-file.txt

# List files
./distfs ls /documents

# Download a file
./distfs get /documents/remote-file.txt restored.txt
```

### 4. FUSE Mounting
Standard OS integration is provided via FUSE.
```bash
mkdir ~/distfs-mount
./distfs-fuse -mount ~/distfs-mount
```

### 5. Multi-Device Key Sync
```bash
# On device 1: Push keys to the server
./distfs keysync push

# On device 2: Pull keys using OIDC identity
./distfs keysync pull -meta http://cluster-url:8080 -jwt <oidc-token>
```

## Development and Acknowledgments

DistFS is actively maintained and tested. The implementation relies on a robust CI suite covering unit tests and complex E2E failure simulations.

This project was built and is maintained with extensive use of the **Gemini CLI**, an AI-powered engineering tool. The AI assisted in architectural design, implementation of cryptographic logic, and the development of the comprehensive test suite.

## License

Copyright 2026 TTBT Enterprises LLC. Licensed under the Apache License, Version 2.0.
