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

## 2. Establishing Trust

Trust in DistFS is established without reliance on centralized Certificate Authorities, using a self-sovereign, recursive model.

### 2.1 Sovereign Bootstrap
The cluster is anchored by the first registered user ("Alice").
1.  Alice generates a Post-Quantum Cryptography (PQC) identity (ML-KEM encapsulation keys and ML-DSA signing keys).
2.  Alice registers with the cluster and is automatically granted administrative rights.
3.  Alice initializes the filesystem root (`/`) and system namespaces (`/registry`, `/users`).
4.  She creates her own self-signed attestation file (`/registry/alice.user`), establishing the root of the Sovereign Chain of Trust.

### 2.2 Optimistic Verification
To prevent blocking I/O operations while verifying identity attestations in the distributed `/registry`, DistFS uses Aggregate Optimistic Verification.

1.  **Optimistic Phase:** As the client traverses the file system (e.g., during `Open`), it fetches Inodes and verifies their ML-DSA signatures using public keys provided by the server. It proceeds optimistically, queuing the `SignerID` and `OwnerID` for later verification.
2.  **Confirmation Phase:** Once the critical path is resolved, the client asynchronously fetches the registry attestations (e.g., `/registry/<ID>.user`) for all queued IDs. It verifies the attestation signatures against the trusted anchor (Alice) or previously verified intermediaries.
3.  **Cross-Check:** The client ensures the public keys used in the Optimistic Phase exactly match the keys bound in the verified registry attestations. Failure immediately aborts the operation and marks the data as tainted.

## 3. Cryptographic Operations

DistFS employs a defense-in-depth cryptographic strategy, protecting data in transit, at rest, and against metadata tampering.

### 3.1 Layer 7 End-to-End Encryption (E2EE)
To prevent network infrastructure (proxies, load balancers) from analyzing traffic patterns, all metadata mutations are encapsulated in Layer 7 E2EE.
*   Requests are packaged as a `SealedRequest`.
*   The payload is a `SealedEnvelope` encrypted using an ephemeral symmetric key, which is itself encapsulated for the cluster's active, rotating **Epoch Key** (ML-KEM).
*   Responses are `SealedResponse` envelopes, symmetrically encrypted for the client.
*   Replay attacks are mitigated via high-resolution timestamps and sliding-window nonces within the sealed envelopes.

### 3.2 Data Encryption (ClientBlobs and Chunks)
*   **AES-256-GCM:** The standard for symmetric encryption in DistFS.
*   **ClientBlobs:** Sensitive Inode metadata (filename, `MTime`, POSIX ACLs) is serialized and encrypted into an opaque `ClientBlob` using a unique **File Key**.
*   **Chunks:** File data is chunked and encrypted. The chunk ID is the cryptographic hash of the *encrypted* chunk, providing content-addressability.

### 3.3 Trial Decryption Algorithm
When a client needs to access a file, it must derive the File Key from the Inode's `Lockbox`. The Lockbox contains the File Key encrypted for various authorized recipients.

```mermaid
flowchart TD
    Start[Start Trial Decryption] --> Iterate[Iterate Lockbox Entries]
    Iterate --> CheckID{Recipient ID == Client ID?}
    CheckID -- Yes --> DecryptSelf[Decapsulate with Personal Key]
    CheckID -- No --> CheckWorld{Recipient ID == 'world'?}
    
    CheckWorld -- Yes --> FetchWorld[Fetch World Private Key]
    FetchWorld --> DecryptWorld[Decapsulate with World Key]
    
    CheckWorld -- No --> CheckGroup{Is Group ID?}
    CheckGroup -- Yes --> ResolveGroup[Resolve Group Membership]
    ResolveGroup --> DerivGroup[Derive Group Epoch Key]
    DerivGroup --> DecryptGroup[Decapsulate with Group Key]
    
    DecryptSelf --> Verify[Verify AES-GCM MAC]
    DecryptWorld --> Verify
    DecryptGroup --> Verify
    
    Verify -- Success --> Success[Return File Key]
    Verify -- Failure --> Iterate
    CheckGroup -- No --> Iterate
```

1.  The client iterates over all entries in the `Lockbox`.
2.  If an entry targets the user's explicit ID, they decapsulate it directly using their ML-KEM private key.
3.  If it targets a Group, the client must first decrypt the Group's `Lockbox` to obtain the Group's symmetric **Epoch Key**, which is then used to decrypt the Inode's Lockbox entry.

### 3.4 Group Lockboxes & Forward Secrecy
Groups utilize rotating **Epoch Keys** to manage access.
*   When a user is added to a group, the current Epoch Key is encapsulated for their public key and added to the group's Lockbox.
*   If a user is removed, the Epoch Key is rotated. The new key is encapsulated *only* for the remaining members.
*   This ensures forward secrecy: a removed member cannot decrypt newly created files within the group.

## 4. Chunk Distribution and Data Nodes

Data nodes provide scalable, horizontal persistence for encrypted chunks.

1.  **Allocation:** The client asks the Metadata Leader to allocate space for a new `ChunkID`. The Leader returns a set of target Data Nodes based on consistent hashing and available capacity.
2.  **Pipelined Replication:** The client pushes the encrypted chunk to the primary Data Node. The primary forwards it to the secondary, which forwards it to the tertiary.
3.  **Capability Tokens:** Data nodes enforce access control via short-lived, signed Capability Tokens issued by the Metadata Leader. The client must present a valid token to read or write a specific `ChunkID`.

```mermaid
sequenceDiagram
    participant Client
    participant MetaLeader as Metadata Leader
    participant D1 as Data Node 1
    participant D2 as Data Node 2
    participant D3 as Data Node 3

    Client->>MetaLeader: Allocate(ChunkID)
    MetaLeader-->>Client: Return [D1, D2, D3] + Write Token
    Client->>D1: Push Chunk (Token, Replicas: [D2, D3])
    D1->>D2: Forward Chunk
    D2->>D3: Forward Chunk
    D3-->>D2: Ack
    D2-->>D1: Ack
    D1-->>Client: Ack
    Client->>MetaLeader: Commit Chunk Manifest
```