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
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Information Disclosure / Privacy Violation
*   **Location:** `pkg/metadata/server.go` (`handleClusterUsers`, `handleClusterNodes`, and `handleClusterGroups`)
*   **Severity:** **HIGH**
*   **Description:** Administrative endpoints return full `User`, `Node`, and `Group` objects, exposing all public keys and detailed usage metrics in bulk.
*   **Resolution:** Modified bulk administrative list handlers to redact sensitive cryptographic fields (SignKey, EncKey, Lockbox, etc.) from the response. Administrators can still retrieve full metadata for a specific object by ID through the established single-object GET endpoints, which enforce appropriate authorization checks.
*   **Impact:** Bulk exposure of User IDs and public keys facilitates correlation attacks, undermining the anonymity provided by the HMAC-based User ID scheme.

### 2.2. Targeted Deanonymization via Admin Lookup
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Privacy Violation
*   **Location:** `pkg/metadata/server.go` (`handleClusterLookup`)
*   **Severity:** **HIGH**
*   **Description:** The admin lookup endpoint allows resolving any email address to its User ID.
*   **Resolution:** Implemented mandatory audit logging and justification requirements for the deanonymization lookup. The `AdminLookup` API now requires a `reason` parameter, which is logged on the server along with the administrator's ID and the resulting User ID. This provides a clear audit trail and acts as a deterrent against unauthorized deanonymization.
*   **Impact:** Allows a compromised or malicious administrator to deanonymize any user in the system.

---

## 3. Medium & Low Severity Vulnerabilities

### 3.1. Group Name Phishing
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** User Deception / Social Engineering
*   **Location:** `cmd/distfs/admin.go`, `cmd/distfs/main.go`, and `pkg/metadata/server.go`
*   **Severity:** **MEDIUM**
*   **Description:** Group names are user-provided and not unique. A malicious user can name a group "SYSTEM" or "ADMIN" to trick an administrator or other users into performing unauthorized actions or assuming higher trust.
*   **Resolution:** Implemented a `IsSystem` bit in group metadata that can only be set or modified by cluster administrators. The Metadata Server enforces this restriction during group creation and updates. Both the CLI group list and the interactive Admin Console now display a prominent `[SYSTEM]` label for groups with this bit set, allowing users and administrators to clearly distinguish between user-provided names and verified system groups.
*   **Impact:** A malicious user can name a group "SYSTEM" or "ADMIN" to trick an administrator or other users into performing unauthorized actions or assuming higher trust.

### 3.2. Signer Identity Leakage in Inodes
*   **Status:** **RESOLVED**
*   **Vulnerability Type:** Information Disclosure
*   **Location:** `pkg/metadata/types.go` (`Inode` struct)
*   **Severity:** **LOW**
*   **Description:** `SignerID` and `AuthorizedSigners` are stored in plaintext within the `Inode` metadata.
*   **Resolution:** Replaced plaintext signer fields with `EncryptedSignerID` and `EncryptedAuthorizedSigners` within the `Inode` metadata. The Metadata Server now verifies the authenticated submitter's signature during updates without needing access to the plaintext identity history. Interaction patterns are now hidden from the server, while clients retain the ability to perform fine-grained integrity and ACL audits using their shared keys.
*   **Impact:** Exposes the identity of users interacting with specific files to the Metadata Server, leaking usage patterns.
