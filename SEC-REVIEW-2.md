# DistFS Security Review Report - Part 2 (Manual Review)

This document outlines security weaknesses identified during the manual audit focusing on data exfiltration and user deception.

---

## 1. Critical Vulnerabilities

### 1.1. Missing Group Metadata Verification
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Broken Access Control / Integrity Failure
*   **Location:** `pkg/client/client.go` (`GetGroup` and `AddUserToGroup` methods)
*   **Severity:** **CRITICAL**
*   **Description:** The client library fetches `Group` objects from the Metadata Server but does not verify the `Signature` or `SignerID` fields.
*   **Resolution:** Implemented mandatory client-side signing for all group metadata. Refactored group creation and update flows to ensure the client signs the final state (including server-allocated GIDs) before submission. Implemented strict ML-DSA signature verification in the client's `GetGroup` method and the server's `handleCreateGroup`/`handleUpdateGroup` endpoints. Enhanced concurrency safety using client-side serialization and optimistic retry loops.
*   **Impact:** A compromised Metadata Node can modify group ownership, swap group public keys, or manipulate member lists. This allows an attacker to intercept shared keys or trick users into trusting malicious group configurations.

---

## 2. High-Severity Vulnerabilities

### 2.1. Admin API Over-Exposure (PII/Metadata Leak)
*   **Vulnerability Type:** Information Disclosure / Privacy Violation
*   **Location:** `pkg/metadata/server.go` (`handleClusterUsers` and `handleClusterNodes`)
*   **Severity:** **HIGH**
*   **Description:** Administrative endpoints return full `User` and `Node` objects, exposing all public keys and detailed usage metrics in bulk.
*   **Impact:** Bulk exposure of User IDs and public keys facilitates correlation attacks, undermining the anonymity provided by the HMAC-based User ID scheme.
*   **Recommendation:** Redact public keys from bulk admin list responses unless explicitly requested for a specific ID.

### 2.2. Targeted Deanonymization via Admin Lookup
*   **Vulnerability Type:** Privacy Violation
*   **Location:** `pkg/metadata/server.go` (`handleClusterLookup`)
*   **Severity:** **HIGH**
*   **Description:** The admin lookup endpoint allows resolving any email address to its User ID.
*   **Impact:** Allows a compromised or malicious administrator to deanonymize any user in the system.
*   **Recommendation:** Limit lookup functionality or require additional justification/logging for deanonymization actions.

---

## 3. Medium & Low Severity Vulnerabilities

### 3.1. Group Name Phishing
*   **Vulnerability Type:** User Deception / Social Engineering
*   **Location:** `cmd/distfs/admin.go` (`updateGroupTable`)
*   **Severity:** **MEDIUM**
*   **Description:** Group names are user-provided and not unique.
*   **Impact:** A malicious user can name a group "SYSTEM" or "ADMIN" to trick an administrator or other users into performing unauthorized actions or assuming higher trust.
*   **Recommendation:** Distinguish user-provided names from system-generated metadata in the UI and consider adding "trusted" labels for system groups.

### 3.2. Signer Identity Leakage in Inodes
*   **Vulnerability Type:** Information Disclosure
*   **Location:** `pkg/metadata/types.go` (`Inode` struct)
*   **Severity:** **LOW**
*   **Description:** `SignerID` and `AuthorizedSigners` are stored in plaintext within the `Inode` metadata.
*   **Impact:** Exposes the identity of users interacting with specific files to the Metadata Server, leaking usage patterns.
*   **Recommendation:** Consider encrypting these fields within the metadata layer if privacy of interaction patterns is a priority.
