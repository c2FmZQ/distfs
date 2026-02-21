# DistFS Security Review Report

This document outlines the security vulnerabilities identified during the manual audit of the DistFS codebase and node configuration.

---

## 1. Critical Vulnerabilities

### 1.1. Unencrypted Metadata (FSM) at Rest
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Insecure Data Handling
*   **Location:** `pkg/metadata/fsm.go`
*   **Severity:** **CRITICAL**
*   **Description:** The BoltDB file (`fsm.bolt`) storing the FSM state is not encrypted. It contains the `cluster_secret`, User IDs, public keys, and file manifests.
*   **Resolution:** Implemented value-level encryption using AES-256-GCM with a unique `fsmKey` derived from the node's MasterKey. Added `EncryptedStableStore` for Raft state and secured snapshots by including the `fsmKey` in the encrypted snapshot stream.

### 1.2. SSRF and Token Leakage in Data Replication
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Broken Access Control / SSRF
*   **Location:** `pkg/data/api.go` (`replicate` method)
*   **Severity:** **CRITICAL**
*   **Description:** The `Validator` is uninitialized in `cmd/storage-node`, allowing a user with a Write token to specify an arbitrary URL. The node will send the chunk and the signed `CapabilityToken` to that URL.
*   **Resolution:** Refactored `data.NewServer` to mandate a non-nil `Validator`. Implemented `DenyAllValidator` as a secure default and `NoopValidator` for controlled testing. Updated `MetadataFSM.ValidateNode` to safely handle encrypted node metadata. Removed the nil-bypass in the `replicate` method, ensuring all replication targets are strictly validated against the cluster registry.

---

## 2. High-Severity Vulnerabilities

### 2.1. Insecure Direct Object Reference (IDOR) in User Retrieval
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Broken Access Control (IDOR)
*   **Location:** `pkg/metadata/server.go` (`handleGetUser`)
*   **Severity:** **HIGH**
*   **Description:** `GET /v1/user/{id}` returns user metadata without checking if the requester is the owner or an admin.
*   **Resolution:** Implemented ownership and administrator checks in `handleGetUser`. If the requester is neither the owner of the user account nor a cluster administrator, the sensitive `Usage` and `Quota` fields are redacted (zeroed out) before returning the user metadata. Public keys (`SignKey`, `EncKey`) remain accessible to all authenticated users to support distributed signature verification and encrypted sharing.

### 2.2. Shared Secret Leakage in Node Discovery
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Broken Access Control / Info Leak
*   **Location:** `pkg/metadata/server.go` (`handleClusterJoin`)
*   **Severity:** **HIGH**
*   **Description:** The Leader sends the global `X-Raft-Secret` to the provided join address during discovery.
*   **Resolution:** Implemented a Mutual HMAC-SHA256 Challenge-Response handshake. The Leader and Candidate node now prove knowledge of the `X-Raft-Secret` using random nonces without ever transmitting the secret itself over the network. This provides mutual authentication and replay protection for the discovery process.

### 2.3. Arbitrary Code Execution in Device Flow
*   **Vulnerability Type:** Command Injection
*   **Location:** `pkg/auth/device_flow.go` (`GetToken`)
*   **Severity:** **HIGH**
*   **Description:** The `Browser` config string is passed directly to `exec.Command`.
*   **Impact:** Execution of arbitrary shell commands during client initialization.
*   **Recommendation:** Sanitize or allow-list browser commands.

### 2.4. Cross-Node Token Forgery
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Broken Access Control
*   **Location:** `pkg/data/api.go` (`authenticate`)
*   **Severity:** **HIGH**
*   **Description:** Data nodes trust tokens signed by *any* registered node.
*   **Resolution:** Implemented a cluster-wide PQC signing key managed by the Raft cluster. Metadata leaders now sign all session and capability tokens using this shared key. Data nodes strictly verify tokens against the cluster public key stored in the FSM. This prevents any single compromised storage node from forging tokens for other nodes.

---

## 3. Medium & Low Severity Vulnerabilities

### 3.1. Unauthenticated Information Disclosure
*   **Vulnerability Type:** Information Disclosure
*   **Location:** `pkg/metadata/server.go` (`/v1/health` and `/v1/node`)
*   **Severity:** **MEDIUM**
*   **Description:** Health and node list endpoints are public and return detailed Raft/Network stats.
*   **Impact:** Aids attacker in mapping the cluster architecture.
*   **Recommendation:** Restrict to authenticated users.

### 3.2. Denial of Service (DoS) via Memory Exhaustion
*   **Vulnerability Type:** DoS
*   **Location:** `pkg/metadata/server.go` (Multiple)
*   **Severity:** **MEDIUM**
*   **Description:** Large request bodies (10MB) are read fully into memory.
*   **Impact:** Server crash under concurrent high-volume requests.
*   **Recommendation:** Implement streaming or stricter limits.

### 3.3. Lack of Trust Revocation
*   **Vulnerability Type:** Broken Access Control
*   **Location:** `pkg/metadata/fsm.go`
*   **Severity:** **MEDIUM**
*   **Description:** No mechanism to remove node keys from the `trusted` map.
*   **Impact:** Compromised nodes cannot be easily evicted.
*   **Recommendation:** Implement a node removal/revocation Raft command.
