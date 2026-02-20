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
*   **Vulnerability Type:** Broken Access Control / SSRF
*   **Location:** `pkg/data/api.go` (`replicate` method)
*   **Severity:** **CRITICAL**
*   **Description:** The `Validator` is uninitialized in `cmd/storage-node`, allowing a user with a Write token to specify an arbitrary URL. The node will send the chunk and the signed `CapabilityToken` to that URL.
*   **Impact:** Information disclosure, SSRF, and theft of signed access tokens.
*   **Recommendation:** Initialize `Validator` and enforce a strict allow-list of cluster nodes.

---

## 2. High-Severity Vulnerabilities

### 2.1. Insecure Direct Object Reference (IDOR) in User Retrieval
*   **Vulnerability Type:** Broken Access Control (IDOR)
*   **Location:** `pkg/metadata/server.go` (`handleGetUser`)
*   **Severity:** **HIGH**
*   **Description:** `GET /v1/user/{id}` returns user metadata without checking if the requester is the owner or an admin.
*   **Impact:** Authenticated users can harvest metadata (usage, quota, keys) for all other users.
*   **Recommendation:** Restrict access to self or admin.

### 2.2. Shared Secret Leakage in Node Discovery
*   **Vulnerability Type:** Broken Access Control / Info Leak
*   **Location:** `pkg/metadata/server.go` (`handleClusterJoin`)
*   **Severity:** **HIGH**
*   **Description:** The Leader sends the global `X-Raft-Secret` to the provided join address during discovery.
*   **Impact:** A malicious node can steal the cluster's management secret.
*   **Recommendation:** Use short-lived join tokens instead of the global secret.

### 2.3. Arbitrary Code Execution in Device Flow
*   **Vulnerability Type:** Command Injection
*   **Location:** `pkg/auth/device_flow.go` (`GetToken`)
*   **Severity:** **HIGH**
*   **Description:** The `Browser` config string is passed directly to `exec.Command`.
*   **Impact:** Execution of arbitrary shell commands during client initialization.
*   **Recommendation:** Sanitize or allow-list browser commands.

### 2.4. Cross-Node Token Forgery
*   **Vulnerability Type:** Broken Access Control
*   **Location:** `pkg/data/api.go` (`authenticate`)
*   **Severity:** **HIGH**
*   **Description:** Data nodes trust tokens signed by *any* registered node.
*   **Impact:** A single compromised storage node can grant itself access to all chunks in the cluster.
*   **Recommendation:** Trust only the authoritative Metadata Leader for token signing.

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
