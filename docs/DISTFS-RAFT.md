# DistFS Raft Consensus & Cluster Security

This document provides a rigorous, in-depth technical analysis of the DistFS metadata layer. It details the consensus mechanics, the security posture of the cluster, mutual TLS (mTLS) infrastructure, and the two-tiered trust model utilized for Finite State Machine (FSM) encryption.

## 1. Consensus Mechanics

DistFS relies on the Raft consensus algorithm to manage the global file system namespace and metadata. The implementation prioritizes strong consistency (linearizability) for metadata mutations.

### 1.1 Leader Election and Log Replication

The cluster consists of $N$ MetaNodes (typically $N \in \{3, 5\}$). All metadata mutations must be routed to the elected Leader.

1.  **Election:** Nodes utilize randomized election timeouts. If a Follower receives no heartbeats from the Leader within the timeout window, it transitions to the Candidate state and requests votes. A Candidate becomes the Leader upon receiving a quorum ($\lfloor N/2 \rfloor + 1$) of votes.
2.  **Replication:** A client submitting a metadata mutation (e.g., creating an Inode) sends a `SealedRequest` to the cluster. If received by a Follower, the request is internally forwarded to the Leader.
3.  **Commitment:** The Leader appends the mutation to its local Raft log and broadcasts `AppendEntries` RPCs to all Followers. Once a quorum of nodes acknowledges the append, the Leader applies the mutation to its FSM and returns a success response to the client.

```mermaid
sequenceDiagram
    participant Client
    participant Follower
    participant Leader
    participant FSM

    Client->>Follower: SealedRequest (Create Inode)
    Follower->>Leader: Forward Request
    Leader->>Leader: Append to Local Log
    Leader->>Follower: AppendEntries RPC
    Follower-->>Leader: Ack
    Note over Leader: Quorum Reached
    Leader->>FSM: Apply Log Entry
    Leader-->>Follower: Forward Response
    Follower-->>Client: SealedResponse
```

## 2. Cluster Security & mTLS

DistFS assumes the network is fundamentally hostile. All inter-node communication is secured via mutual TLS (mTLS), ensuring both confidentiality and strict peer authentication.

### 2.1 Node Identity

Each node possesses a unique, persistent identity rooted in an asymmetric key pair.
*   **Software Key:** By default, nodes generate an Ed25519 key pair (`node.key`).
*   **Hardware Key (TPM):** If instantiated with `--use-tpm`, the node generates an ECC P-256 key within a Trusted Platform Module. The private key material never leaves the TPM boundary.
*   **Node ID:** The Raft `NodeID` is derived deterministically from the public key, preventing ID spoofing.

### 2.2 Trust On First Use (TOFU) Bootstrapping

To bootstrap a secure cluster without a central Certificate Authority (CA), DistFS employs a strict Trust On First Use (TOFU) protocol.

1.  **Initial State:** A completely fresh node (no local Raft state) starts in TOFU mode.
2.  **Handshake:** The node connects to the cluster join address (the anticipated Leader). During the TLS handshake, it presents its self-signed certificate.
3.  **Trust Acquisition:** Because it is in TOFU mode, the joining node temporarily suspends peer certificate verification. Upon successful connection, it downloads the authoritative `NodeMeta` list—the set of trusted public keys for the entire cluster—from the Leader.
4.  **Strict Enforcement:** Once the `NodeMeta` is persisted locally, the node immediately and permanently transitions to **Strict Mode**. All future TLS connections require the peer to present a certificate matching a public key in the `NodeMeta` list.

```mermaid
stateDiagram-v2
    [*] --> TOFU: First Boot (No State)
    TOFU --> StrictMode: Download NodeMeta
    StrictMode --> StrictMode: Validate Peer against NodeMeta
    StrictMode --> [*]: Node Shutdown
```

## 3. Two-Tiered Trust Model for FSM Encryption

A critical challenge in encrypted distributed systems is resolving the circular dependency between Raft log application (which requires decryption keys) and cluster state (where the keys are stored). DistFS solves this using a two-tiered trust architecture.

### 3.1 Tier 1: Local Node Vault & ClusterSecret

At cluster initialization, the first node generates a high-entropy `ClusterSecret`. This secret is the root of trust for the cluster.
*   The `ClusterSecret` is encrypted using the node's local `MasterKey` (derived from `DISTFS_MASTER_KEY` or the TPM) and stored in a local, on-disk vault.
*   When a new node successfully completes the TOFU join process, the Leader securely transmits the `ClusterSecret` via the mTLS channel. The joining node persists this secret in its own local vault.

### 3.2 Tier 2: FSM KeyRing & The System Bucket

The Raft FSM is implemented using BoltDB. The FSM data is encrypted at rest, but the keys to decrypt it are stored *within* the FSM itself.
*   **The System Bucket:** The BoltDB `system` bucket contains the `FSM KeyRing` (a rotating set of AES-GCM keys) and the `ClusterSignKey`.
*   **Root Encryption:** Data within the `system` bucket is encrypted using a symmetric key deterministically derived from the **Tier 1 `ClusterSecret`**.
*   **Payload Encryption:** All other buckets (Inodes, Users, Groups) are encrypted using the active key from the **Tier 2 `FSM KeyRing`**.

This design ensures that a node can always decrypt the FSM root (using its local vault) to retrieve the active KeyRing required to process incoming Raft logs.

## 4. Snapshotting

To prevent unbounded Raft log growth, DistFS employs periodic snapshotting. DistFS utilizes a streaming BoltDB snapshot strategy (`MetadataSnapshot`).

### 4.1 Snapshot Portability

Because the FSM is fully encrypted, BoltDB snapshots can be safely transferred between nodes over the mTLS Raft transport.
*   When a Follower receives a snapshot, it replaces its local BoltDB file.
*   Because the Follower already possesses the `ClusterSecret` in its local Tier 1 vault, it can immediately decrypt the `system` bucket within the new snapshot, extract the current `FSM KeyRing`, and resume processing logs without requiring an out-of-band key exchange.