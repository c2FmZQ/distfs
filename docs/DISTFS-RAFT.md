# DistFS Raft Consensus & Cluster Security

This document provides an analysis of the DistFS metadata layer. It details the consensus mechanics, the security posture of the cluster, mutual TLS (mTLS) infrastructure, and the two-tiered trust model utilized for Finite State Machine (FSM) encryption.

## 1. Consensus Mechanics

DistFS relies on the Raft consensus algorithm to manage the global file system namespace and metadata. The implementation prioritizes strong consistency (linearizability) for metadata mutations.

### 1.1 Leader Election and Log Replication
The cluster consists of $N$ MetaNodes (typically $N \in \{3, 5\}$). All metadata mutations must be routed to the elected Leader.

1.  **Election:** Nodes utilize randomized election timeouts. A Candidate becomes the Leader upon receiving a quorum ($\lfloor N/2 \rfloor + 1$) of votes.
2.  **Replication:** Mutations are appended to the Raft log and broadcast via `AppendEntries`. Once a quorum acknowledges, the Leader applies the entry to the FSM.

### 1.2 Distributed Leases & Linearizability
To ensure strict POSIX linearizability for metadata (e.g., ensuring a `stat` reflects the most recent `write`), DistFS uses **Server-Side Leases**. 
*   When a client opens a file for writing, the Leader grants an exclusive **Usage Lease**.
*   Any concurrent attempt to modify the same Inode must wait for the lease to expire or be explicitly released.
*   The Leader preserves lease state across elections by replicating lease grants into the Raft log.

### 1.3 Multi-tenant Quota Resolution
The FSM enforces quotas for both Inodes and total Bytes.
*   **Primary Debtor:** For every write, the FSM resolves the primary debtor based on the `QuotaEnabled` flag of the Inode's parent directory.
*   **Atomic Rollback:** If a log entry would exceed a debtor's quota, the FSM triggers an atomic rollback, rejecting the mutation before it is permanently applied to the state.

### 1.4 Atomic State Transitions (Batching)
Multi-inode operations (e.g., `rename`, `symlink`, or atomic directory moves) are submitted as a single **Batch Command**. The FSM applies these commands within a single database transaction. If any sub-command fails or violates a security constraint, the entire batch is rolled back, ensuring the filesystem never enters an inconsistent state.

## 2. Cluster Identity

Identity at the cluster level is divided between individual node identities and the shared root secret.

### 2.1 Node Identity
Each node possesses a unique, persistent identity rooted in an asymmetric key pair:
*   **NodeID:** Derived deterministically from the public key, preventing ID spoofing.

### 2.2 Cluster Identity (The ClusterSecret)
The **ClusterSecret** is a high-entropy symmetric secret that serves as the root of trust. It is used to derive FSM encryption keys and blind User IDs.

### 2.3 Identity Privacy (The Dark Registry)
The server only operates on opaque identifiers. 
*   **Dark Users:** `UserID = HMAC(sub, ClusterSecret)`.
*   **Dark Groups:** To protect the social graph, group membership is managed via a **Dark Membership** model. A member's recipient ID in a Group Lockbox is not their `UserID`, but a salted HMAC: `RecipientID = HMAC(UserID, GroupID)`. This ensures that even if a server admin inspects the Lockbox, they cannot determine which users belong to the group without the `ClusterSecret`. HMAC acts as a **Pseudorandom Function (PRF)** in this context, ensuring that identifiers are indistinguishable from random noise to anyone without the secret key.

## 3. Cluster Security & mTLS

### 3.1 Layer 7 End-to-End Encryption (E2EE)
All client-cluster traffic is wrapped in a `SealedEnvelope`. 
*   **Confidentiality:** The envelope is encrypted using AES-256-GCM with a session key encapsulated via ML-KEM for the cluster's active **Epoch Key**.
*   **Replay Protection:** Every envelope contains a monotonic high-resolution timestamp and a unique 128-bit nonce. The Leader maintains a sliding-window cache of recent nonces and rejects any request with a timestamp older than $\Delta t$ or a previously seen nonce.

### 3.2 Cluster Notarization (ClusterSig)
To prevent a compromised cluster from presenting different versions of the history to different clients (Forking), DistFS utilizes **Verifiable Notarization**.
1.  **Server Signature:** The FSM signs the `ManifestHash` of every committed Inode using the cluster's **ClusterSignKey** (ML-DSA). This signature is stored as `ClusterSig`.
2.  **Anchored Verification:** Clients pin the `ID` and `Version` of known trusted Inodes (e.g., the root directory) as **Anchors**. When fetching an Inode, the client ensures the new version is monotonically greater than or equal to the anchored version and that the `ClusterSig` is valid.

### 3.3 Perfect Forward Secrecy (Session Establishment)
During login, the client and server perform an ephemeral PQC-KEM exchange. The server generates a unique **Session Key** encapsulated for the client's ephemeral public key. This key is used to protect all subsequent traffic in that session. Because the session key is ephemeral and never persisted in the Raft log or FSM, a future compromise of the cluster's long-term keys does not reveal the content of past sessions.

### 3.4 Proof of Identity Possession (Auth Challenges)
To prevent session hijacking or unauthorized login, the cluster enforces a **Challenge-Response** protocol. The server issues a random 32-byte challenge which the user must sign with their private `SignKey` (ML-DSA). Only users who can prove possession of the private key bound to their `UserID` can obtain a valid session token.

### 3.5 mTLS & TOFU Bootstrapping
Inter-node communication is secured via mutual TLS with a strict TOFU-to-Strict transition (see Section 5.2).

## 4. Two-Tiered Trust Model for FSM Encryption

DistFS resolves the circular dependency of Raft log application using a two-tiered trust architecture.

### 4.1 Tier 1: Local Node Vault & ClusterSecret
The `ClusterSecret` is encrypted using the node's local `MasterKey` (hardware-bound) and stored in a node-local vault.

### 4.2 Tier 2: FSM KeyRing & The System Bucket
The BoltDB `system` bucket (containing the KeyRing) is encrypted with a key derived from the Tier 1 `ClusterSecret`. All other data buckets use keys from the Tier 2 KeyRing.

## 5. Formal Cryptography Proofs

### 5.1 Definitions
Let $\mathcal{N}$ be the set of nodes.
Let $PK_n, SK_n$ be the node keypair.
Let $S$ be the `ClusterSecret`.
Let $E_t$ be the active cluster Epoch Key.

### 5.2 Theorem 5: Security of the TOFU Join Protocol
**Theorem:** If ML-DSA is EUF-CMA secure, the TOFU protocol is secure against MITM attacks after the initial trust acquisition.

**Proof Sketch:**
The TOFU protocol has two phases: **Phase A (Trust Acquisition)** and **Phase B (Strict Enforcement)**.
1.  **Phase A:** A joining node $n_{new}$ connects to an existing node $n_{leader}$ over TLS. During the initial handshake, $n_{new}$ has no prior knowledge of $\mathcal{M}$. However, $n_{leader}$ authenticates $n_{new}$ by checking its self-signed certificate against a pre-authorized join request or administrator approval.
2.  **Secret Transmission:** Once authenticated, $n_{leader}$ transmits $S$ and $\mathcal{M}$ to $n_{new}$ over the encrypted TLS channel.
3.  **Phase B:** Node $n_{new}$ transitions to **Strict Mode**. It now refuses any TLS handshake where the peer's public key $PK_{peer} \notin \mathcal{M}$.
**Integrity Argument:** An adversary $\mathcal{A}$ attempting to impersonate a cluster member to $n_{new}$ after Phase A must present a certificate for some $PK_a \in \mathcal{M}$. Since $PK_a$ corresponds to a legitimate node $n_a$, $\mathcal{A}$ must also possess $SK_a$ to complete the TLS handshake. By the EUF-CMA security of the underlying identity keys, the probability of $\mathcal{A}$ possessing $SK_a$ or forging a valid signature for $PK_a$ is negligible. Thus, after the first secure connection, the cluster forms a closed, authenticated network.

### 5.3 Theorem 6: Confidentiality of the FSM Root
**Theorem:** The contents of the FSM remain confidential even if the storage medium is exfiltrated, provided $S$ remains confidential.

**Proof Sketch:**
1.  **Encryption Hierarchy:** The FSM data $D$ is encrypted as $C = E_{K_{fsm}}(D)$, where $K_{fsm}$ is a key from the `FSM KeyRing`.
2.  **Root of Trust:** $K_{fsm}$ is stored in the `system` bucket, encrypted as $C_{sys} = E_{f(S)}(K_{fsm})$, where $f$ is a key derivation function and $S$ is the `ClusterSecret`.
3.  **Confidentiality Chain:** To obtain plaintext $D$, an adversary must first obtain $K_{fsm}$ from $C_{sys}$. To decrypt $C_{sys}$, the adversary must possess $S$.
4.  **Local Protection:** On each node $n$, $S$ is stored as $C_s = E_{K_{master}}(S)$. $K_{master}$ is bound to the node's local hardware (TPM) or a secure environment variable.
If $S$ is only transmitted over mTLS channels (protected by Theorem 5) and only stored in encrypted vaults, then an adversary who only possesses the FSM file $C$ cannot derive $K_{fsm}$ without breaking the IND-CPA security of AES-GCM or compromising a node's local vault. Therefore, FSM confidentiality is preserved.

### 5.4 Theorem 7: Identity Privacy (Dark Users)
**Theorem:** A metadata leak does not deanonymize users without the `ClusterSecret`.

**Proof Sketch:** The persistent `UserID` is $ID = HMAC(sub, S)$. Since $HMAC$ is a **Pseudorandom Function (PRF)**, an adversary seeing $ID$ cannot derive $sub$ without $S$, and the $ID$ itself is indistinguishable from a random bitstring. As $S$ is protected by Theorem 6, user privacy is preserved against offline leakage.

### 5.5 Theorem 8: Layer 7 E2EE & Replay Protection
**Theorem:** If the E2EE scheme is IND-CCA2 secure and the Leader enforces the sliding-window nonce protocol, then the cluster is secure against traffic analysis and replay attacks.

**Proof Sketch:**
1.  **Confidentiality:** All metadata is encapsulated in a `SealedEnvelope` encrypted with AES-GCM and ML-KEM. By the IND-CCA2 security of these primitives, an adversary $\mathcal{A}$ cannot distinguish between two requests or learn any bit of the payload.
2.  **Replay:** A request $R$ is uniquely identified by $(Nonce, Timestamp)$. If $\mathcal{A}$ resubmits $R$, the Leader checks its nonce cache. If the nonce is present, it is rejected. If the timestamp is outside the valid window $\Delta t$, it is rejected. Therefore, every request is processed at most once.

### 5.6 Theorem 9: Metadata Linearizability
**Theorem:** Any sequence of metadata operations in DistFS satisfies the Serializability property.

**Proof Sketch:** Metadata mutations are applied via a strictly linearizable Raft log. Read operations are either routed through the Raft log (as a `Query`) or verified against a Leader Lease. Since the Leader enforces exclusive Usage Leases for writers, no two writers can modify an Inode concurrently, and readers always observe the state committed by the most recent lease-holding writer. This ensures metadata linearizability.

### 5.7 Theorem 10: Multi-tenant Resource Safety
**Theorem:** A malicious user cannot exceed their assigned quota.

**Proof Sketch:** Quota enforcement happens within the Raft FSM during log application. Because the FSM is deterministic and applies entries atomically, the `PrimaryDebtor`'s current usage is checked against the limit $Q$ before the write is committed. If `usage + delta > Q`, the transaction is aborted and rolled back. Since the server is the authoritative source for quota state, the client cannot bypass this check.

### 5.8 Theorem 11: Anonymous Membership (Dark Groups)
**Theorem:** An adversary $\mathcal{A}$ with access to the Group Lockbox cannot determine group membership without $S$.

**Proof Sketch:** Recipient IDs in a group lockbox are derived as $R = HMAC(UserID, GroupID)$. Since $HMAC$ is a Pseudorandom Function (PRF), the values of $R$ appear indistinguishable from random noise to anyone without the salt ($S$, which is used to derive the `UserID`). Therefore, $\mathcal{A}$ cannot link a Lockbox entry back to a specific `UserID` in the Dark Registry.

### 5.9 Theorem 14: Verifiable Timeline (Fork-Resistance)
**Theorem:** A compromised metadata cluster cannot "fork" the history (presenting different consistent states to different clients) without being detected by an anchored client.

**Proof Sketch:**
Let a client $c$ have an anchored version $V_a$ of an Inode $I$.
1.  **Monotonicity:** The FSM only commits mutations where the new version $V_{new} > V_{old}$.
2.  **Notarization:** Every state update is signed as $Sign(SK_{cluster}, Hash(I || V_{new}))$.
3.  **Anchoring:** When $c$ fetches $I$, it verifies the signature and ensures $V \ge V_a$.
If the server attempts to present a forked history $H'$ to $c$, it must either produce a valid signature for a lower version number (which $c$ will reject via the anchor) or produce a forked history starting from $V_a$. However, since Raft ensures a single linearizable log, any two states at version $V > V_a$ that both possess valid cluster signatures must be identical (Collision Resistance of the signature/hash). Therefore, the server cannot present two different valid histories to different clients without breaking the underlying cryptographic primitives or Raft consensus.

### 5.10 Theorem 17: Perfect Forward Secrecy (Sessions)
**Theorem:** A compromise of the cluster's long-term identity keys does not allow an adversary to decrypt past client-server sessions.

**Proof Sketch:**
Session keys ($K_{sess}$) are established using an ephemeral PQC-KEM exchange during login.
1.  **Encapsulation:** The server generates $K_{sess}$ and encapsulates it ($C_{kem}$) for the client's ephemeral public key $PK_{eph}$.
2.  **Transience:** $K_{sess}$ and the corresponding private keys are stored only in volatile memory and are purged upon session expiry.
3.  **Forward Secrecy:** Since $K_{sess}$ is not derived from or encrypted by any long-term cluster secret (like $S$ or $SK_{cluster}$), an adversary $\mathcal{A}$ who obtains the long-term keys at time $T$ still lacks the ephemeral private keys required to decapsulate past $C_{kem}$ values. Therefore, past session confidentiality is preserved.

### 5.11 Theorem 19: Atomic State Transitions (Batch Consistency)
**Theorem:** multi-Inode mutations applied via a Batch Command satisfy the property of Atomicity.

**Proof Sketch:**
The Raft FSM processes a `Batch Command` within a single database transaction.
1.  **Isolation:** BoltDB provides ACID transactions. All sub-commands in the batch are applied to the same version of the state.
2.  **Consistency:** The FSM validates structural constraints (e.g., link counts, directory loops) after all sub-commands in the batch are simulated but before they are committed.
3.  **Rollback:** If any sub-command fails (due to quota, permissions, or structural error), the FSM triggers an explicit transaction rollback.
Therefore, the filesystem state transitions from one consistent state to another, with no intermediate or partial states ever becoming visible to readers, ensuring batch atomicity.

### 5.12 Theorem 25: Proof of Identity Possession (Auth Challenges)
**Theorem:** Session tokens are only issued to users who possess the corresponding private `SignKey`.

**Proof Sketch:**
During the `Login` flow, the server generates a random 256-bit challenge $C$.
1.  **Uniqueness:** $C$ is high-entropy and single-use, preventing replay.
2.  **Attribution:** The user must return $Sign(SK_{user}, C)$.
3.  **Verification:** The server verifies the signature against the user's `SignKey` in the registry.
By the EUF-CMA security of ML-DSA, an adversary $\mathcal{A}$ who does not possess $SK_{user}$ cannot produce a valid signature for a fresh challenge $C$. Therefore, the server ensures that the requester is the legitimate owner of the identity before issuing a session token.
