# DistFS Filesystem Operations & Cryptography

This document provides an analysis of the DistFS filesystem architecture. It details the strict separation of responsibilities between the untrusted server and the cryptographic client, the establishment of trust, and the execution of cryptographic protocols.

## 1. Separation of Responsibilities

DistFS operates under a strict "Trust No One" model. The server infrastructure is treated as an untrusted persistence and coordination layer.

### 1.1 Server Responsibilities
*   **Metadata Enforcement:** The server maintains the file system graph via Raft, enforcing referential integrity.
*   **Concurrency Control:** The server utilizes Optimistic Concurrency Control (OCC) and Server-Side Leases for POSIX compliance.
*   **Resource Management:** The server enforces multi-tenant quotas at the User and Group levels.

### 1.2 Client Responsibilities
*   **Data Encryption:** All file content and sensitive metadata are encrypted by the client before transmission.
*   **Data Chunking:** The client splits file data into uniform 1MB chunks.
*   **Authorization:** Access control is entirely cryptographic using ML-KEM and ML-DSA.

## 2. Filesystem Identity

Identity in DistFS is decentralized and cryptographically enforced.

### 2.1 User Identity
A user's identity is defined by a pair of PQC keys:
*   **SignKey (ML-DSA):** Proves **Attribution**.
*   **EncKey (ML-KEM):** Proves **Authorization**.

### 2.2 Server and Cluster Identity
*   **ClusterSignKey (ML-DSA):** Used by the cluster to notarize the metadata timeline (`ClusterSig`).
*   **Epoch Keys:** Rotating symmetric keys used to protect Layer 7 traffic.

## 3. Establishing Trust

Trust is established using a self-sovereign, recursive verification model.

### 3.1 Sovereign Bootstrap
The cluster is anchored by the first registered user ("Alice").

### 3.2 Optimistic Verification
Clients fetch metadata optimistically and perform deferred confirmation against the trusted `/registry` anchors.

## 4. Cryptographic Operations

### 4.1 Layer 7 End-to-End Encryption (E2EE)
Requests are packaged as `SealedRequest` envelopes (see `DISTFS-RAFT.md`).

### 4.2 Data Encryption (Chunks and ClientBlobs)
*   **AES-256-GCM:** Used for all symmetric encryption.
*   **ClientBlobs:** Encrypted Inode metadata (filenames, ACLs).
*   **Chunks:** File data encrypted with a unique File Key and Nonce.

### 4.3 Lockboxes and Trial Decryption
Access to the **File Key** is obtained via decapsulation of a `Lockbox` entry using ML-KEM.

### 4.4 Group Forward Secrecy & Epoch Ratcheting
Groups manage access via a rotating **Epoch Seed**.
1.  **Epoch Advancement:** When a member is removed, the Group Manager rotates the Epoch Seed. The new seed is encapsulated *only* for current members.
2.  **Ratcheting:** Each Epoch Seed $S_t$ can be used to derive the previous seed $S_{t-1}$ via a one-way Hash-based ratchet: $S_{t-1} = KDF(S_t)$. This allows current members to access legacy files without re-encrypting them.
3.  **Forward Secrecy:** Because the ratchet is a one-way function, a removed member possessing $S_{t-1}$ cannot derive $S_t$.

## 5. Formal Cryptography Proofs

### 5.1 Definitions
Let $\mathcal{U}$ be the set of all identities.
Let $PK_u, SK_u$ be the keypair for user $u$.
Let $\mathcal{T}$ be the set of trusted users.

### 5.2 Theorem 1: Trust Model Security (Identity Spoofing)
**Theorem:** If ML-DSA is Existentially Unforgeable under Chosen Message Attack (EUF-CMA), the DistFS trust model is secure against unauthorized identity spoofing.

**Proof Sketch:**
Assume there exists an adversary $\mathcal{A}$ that can output a forged attestation $A^*(Alice, w)$ for some user $w$. We construct a reduction $\mathcal{B}$ that uses $\mathcal{A}$ to break the EUF-CMA security of ML-DSA.
1.  $\mathcal{B}$ receives a public key $PK^*$ from the ML-DSA challenger.
2.  $\mathcal{B}$ sets $PK_{Alice} = PK^*$ and starts $\mathcal{A}$.
3.  $\mathcal{B}$ answers $\mathcal{A}$'s registration and attestation queries by acting as a proxy to its own signing oracle.
4.  Eventually, $\mathcal{A}$ outputs a forged attestation $A^*(Alice, w) = \sigma^*$.
Since $\mathcal{A}$ wins, $\sigma^*$ is a valid signature on $PK_w$ under $PK_{Alice}$. Thus, $\mathcal{B}$ outputs $(PK_w, \sigma^*)$, breaking the EUF-CMA security of ML-DSA. Since ML-DSA is assumed secure, the probability of $\mathcal{A}$ succeeding is negligible.

### 5.3 Theorem 2: Data Integrity
**Theorem:** If AES-GCM is unforgeable (AEAD), the hash function provides Second Preimage Resistance (SPR), and ML-DSA is EUF-CMA secure, then the integrity of DistFS file data is preserved.

**Proof Sketch:**
Let a file $F$ consist of chunks $c_1, \dots, c_n$. Encryption is $E_k(N_i, c_i) = (C_i, T_i)$ and ChunkID is $ID_i = H(N_i || C_i || T_i)$. The Inode manifest $M = [ID_1, \dots, ID_n]$ is signed as $\sigma_M = Sign(SK_{owner}, M)$.
An adversary $\mathcal{A}$ attempting to modify a chunk without detection has three avenues:
1.  **AEAD:** Modifying $(C_i, T_i)$ without $k$ is prevented by AEAD unforgeability. Even with $k$, the new $ID_i^*$ won't match the signed manifest.
2.  **SPR:** Finding a different chunk that hashes to the same $ID_i$ is prevented by the Second Preimage Resistance of the hash function.
3.  **EUF-CMA:** Modifying the manifest $M$ requires forging the owner's signature $\sigma_M$, which is prohibited by Theorem 1.
Thus, tampering is detected with overwhelming probability.

### 5.4 Theorem 3: Metadata Attribution & Delegation
**Theorem:** An adversary cannot modify an Inode or forge a file without being identified.

**Proof Sketch:**
Every `Inode` contains a `UserSig` ($\sigma_I = Sign(SK_{signer}, Hash(Inode))$).
1.  **Verification:** The client verifies $\sigma_I$ against the `SignKey` bound to `SignerID` in the `/registry`.
2.  **Delegation:** If `SignerID != OwnerID`, the client additionally requires and verifies an `OwnerDelegationSig` ($\sigma_D = Sign(SK_{owner}, Hash(ID || GroupID))$), proving the owner authorized the group/ACL containing the signer.
3.  **Reduction:** Forging either $\sigma_I$ or $\sigma_D$ requires breaking the EUF-CMA security of ML-DSA. Therefore, all metadata mutations are cryptographically attributable and verifiable.

### 5.5 Theorem 4: Zero-Knowledge Confidentiality
**Theorem:** The storage nodes (server) cannot access plaintext user data.

**Proof Sketch:**
1.  **Encryption:** Data is encrypted via AES-GCM with a random File Key $k$.
2.  **Lockbox:** $k$ is stored in the `Lockbox`, encrypted *only* for authorized recipients using ML-KEM.
3.  **Privacy:** The server only sees encrypted chunks $C$ and the opaque `Lockbox` entries.
4.  **Reduction:** To obtain the plaintext, the server must either break AES-GCM IND-CPA security or decapsulate an ML-KEM entry without the recipient's private key. Both are assumed computationally infeasible. Thus, the server possesses zero knowledge of the data content.

### 5.6 Theorem 12: Group Forward Secrecy
**Theorem:** A removed group member cannot access file data created after their removal.

**Proof Sketch:**
Let $S_t$ be the epoch seed for epoch $t$. Let a user $u$ be removed at epoch $t$.
1.  **Authorization:** At epoch $t$, $S_t$ is encapsulated only for users in the current membership list $\mathcal{M}_t$. Since $u \notin \mathcal{M}_t$, $u$ cannot obtain $S_t$ via decapsulation.
2.  **One-way Ratchet:** The relationship between seeds is $S_{i-1} = KDF(S_i)$. By the pre-image resistance of the KDF, it is computationally infeasible to derive $S_i$ from $S_{i-1}$.
3.  **Conclusion:** Even if $u$ possesses $S_{t-1}$ (the seed from before their removal), they cannot derive $S_t$ or any subsequent seed. Therefore, they cannot decapsulate the File Keys for any new files protected by the new epoch, satisfying Forward Secrecy.

**Known Weakness: Replay / Rollback Attacks (Stale Manifests)**
*TODO: The DistFS implementation must be updated to incorporate a monotonic version number within the Inode signature that the client verifies against a strictly linearizable registry.*
