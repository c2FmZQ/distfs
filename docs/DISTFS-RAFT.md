# DistFS Raft Consensus & Cluster Security

This document provides an analysis of the DistFS metadata layer. It details the consensus mechanics, the security posture of the cluster, mutual TLS (mTLS) infrastructure, and the two-tiered trust model utilized for Finite State Machine (FSM) encryption.

## 1. Consensus Mechanics

DistFS relies on the Raft consensus algorithm to manage the global file system namespace and metadata. The implementation prioritizes strong consistency (linearizability) for metadata mutations.

### 1.1 Leader Election and Log Replication

The cluster consists of $N$ MetaNodes (typically $N \in \{3, 5\}$). All metadata mutations must be routed to the elected Leader.

1.  **Election:** Nodes utilize randomized election timeouts. If a Follower receives no heartbeats from the Leader within the timeout window, it transitions to the Candidate state and requests votes. A Candidate becomes the Leader upon receiving a quorum ($\lfloor N/2 \rfloor + 1$) of votes.
2.  **Replication:** A client submitting a metadata mutation sends a `SealedRequest` to the cluster. If received by a Follower, the request is internally forwarded to the Leader.
3.  **Commitment:** The Leader appends the mutation to its local Raft log and broadcasts `AppendEntries` RPCs. Once a quorum acknowledge the append, the Leader applies the mutation to its FSM and returns a success response.

## 2. Cluster Identity

Identity at the cluster level is divided between individual node identities and the shared root secret.

### 2.1 Node Identity
Each node possesses a unique, persistent identity rooted in an asymmetric key pair:
*   **Software Key:** Ed25519 key pair (`node.key`).
*   **Hardware Key (TPM):** ECC P-256 key within a Trusted Platform Module.
*   **NodeID:** Derived deterministically from the public key, preventing ID spoofing.

### 2.2 Cluster Identity (The ClusterSecret)
The **ClusterSecret** is a high-entropy symmetric secret that serves as the root of trust for the entire cluster. It is used to:
1.  Derive keys for FSM root encryption.
2.  Blind persistent User IDs to protect metadata privacy.

### 2.3 Identity Privacy (The Dark Registry)
The server only operates on opaque cryptographic identifiers. The persistent `UserID` is derived as $ID = HMAC(sub, ClusterSecret)$, where `sub` is the user's OIDC subject claim. This ensures that even if the metadata database is leaked, an adversary cannot deanonymize users without the `ClusterSecret`.

## 3. Cluster Security & mTLS

DistFS assumes the network is fundamentally hostile. All inter-node communication is secured via mutual TLS (mTLS).

### 3.1 Trust On First Use (TOFU) Bootstrapping
To bootstrap without a central CA, DistFS employs a strict TOFU protocol:
1.  **TOFU Phase:** A fresh node connects to the cluster Leader. It temporarily suspends certificate verification and downloads the authoritative `NodeMeta` list and the `ClusterSecret`.
2.  **Strict Mode:** Once the `NodeMeta` is persisted, the node permanently transitions to Strict Mode. All future TLS connections require the peer to present a certificate matching a public key in the `NodeMeta`.

## 4. Two-Tiered Trust Model for FSM Encryption

DistFS resolves the circular dependency of Raft log application using a two-tiered trust architecture.

### 4.1 Tier 1: Local Node Vault & ClusterSecret
The `ClusterSecret` is encrypted using the node's local `MasterKey` (derived from the TPM or an environment variable) and stored in a node-local vault.

### 4.2 Tier 2: FSM KeyRing & The System Bucket
*   **System Bucket:** Contains the `FSM KeyRing` and the `ClusterSignKey`. It is encrypted using a key derived from the **Tier 1 ClusterSecret**.
*   **Payload Encryption:** All other buckets (Inodes, Users, Groups) are encrypted using keys from the **Tier 2 FSM KeyRing**.

## 5. Formal Cryptography Proofs

### 5.1 Definitions
Let $\mathcal{N}$ be the set of nodes in the cluster.
Let $PK_n$ and $SK_n$ be the persistent keypair for node $n$.
Let $\mathcal{M}$ be the `NodeMeta` list of trusted public keys.
Let $S$ be the `ClusterSecret`.

### 5.2 Theorem 5: Security of the TOFU Join Protocol
**Theorem:** If ML-DSA is EUF-CMA secure, the TOFU protocol is secure against MITM attacks after the initial trust acquisition.

**Proof Sketch:** An adversary $\mathcal{A}$ attempting to impersonate a cluster member to a node in Strict Mode must present a certificate for some $PK_a \in \mathcal{M}$. This requires possession of $SK_a$. By the EUF-CMA security of the identity keys, the probability of $\mathcal{A}$ possessing $SK_a$ is negligible. Thus, after the first secure connection, the cluster forms a closed, authenticated network.

### 5.3 Theorem 6: Confidentiality of the FSM Root
**Theorem:** The contents of the FSM remain confidential even if the storage medium is exfiltrated, provided $S$ remains confidential.

**Proof Sketch:** FSM data $D$ is encrypted as $C = E_{K_{fsm}}(D)$. $K_{fsm}$ is stored in the `system` bucket, encrypted as $C_{sys} = E_{f(S)}(K_{fsm})$. $S$ is stored only in node-local vaults encrypted with hardware-bound keys. To obtain $D$, an adversary must obtain $S$ or break the IND-CPA security of AES-GCM. Both are assumed infeasible.

### 5.4 Theorem 7: Identity Privacy (Dark Registry)
**Theorem:** A metadata leak does not deanonymize users without the `ClusterSecret`.

**Proof Sketch:** The persistent `UserID` is $ID = HMAC(sub, S)$. Since $HMAC$ is a cryptographically secure hash function with Preimage Resistance, an adversary seeing $ID$ cannot derive $sub$ without $S$. As $S$ is protected by Theorem 6, user privacy is preserved against offline leakage.
