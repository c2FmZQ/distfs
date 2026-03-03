# DistFS Server API Documentation (v1)

This document is the authoritative technical specification for the DistFS protocol. It provides every detail necessary for a clean-room implementation of a Server (Metadata/Data) or Client.

---

## 1. Cryptographic Foundations & Wire Formats

### 1.1 Primitive Standards
- **Identity/Signing:** ML-DSA-65 (FIPS 204). Signature size: 2420 bytes.
- **Asymmetric Encryption:** ML-KEM-768 (FIPS 203). Ciphertext size: 1088 bytes.
- **Symmetric Encryption:** AES-256-GCM. 12-byte random nonces. 16-byte tags.
- **Hashing:** SHA-256.

### 1.2 Serialization & Canonicalization
- **JSON:** All JSON payloads used in signatures or encryption MUST be **minified** (no whitespace) and use **lexicographically sorted keys** (JCS).
- **Binary:** Multi-byte integers are **Big-Endian** by default unless specified otherwise.

### 1.3 The "Sealing" Protocol (L7 E2EE)
Provides end-to-end encryption for sensitive Metadata API requests.

**Inner Payload Format (Binary):**
`[Timestamp (8b BigEndian uint64)][Signature (2420b ML-DSA-65)][Plaintext JSON]`
- **Signature:** Calculated over `[Timestamp][Plaintext JSON]`.

**Encrypted Wrapper (Binary):**
`[KEM_CT (1088b)][NONCE (12b)][AES_GCM_CT + TAG]`
- **KEM_CT:** Encapsulates a 32-byte Shared Secret for the recipient's ML-KEM-768 public key.
- **AES_GCM_CT:** The Inner Payload encrypted using the Shared Secret.

**HTTP Request/Response Wrappers:**
- **Request:** `{"uid": "user_id", "sealed": "base64_enc_wrapper"}`
- **Response:** `{"sealed": "base64_enc_wrapper"}`
- **Header:** `X-DistFS-Sealed: true` MUST be set for all sealed requests.

---

## 2. Exhaustive Endpoint Catalog

### 2.1 Public & Discovery
| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/health` | None | Node health status. |
| `GET` | `/v1/meta/key` | None | Cluster ML-KEM Public Key. |
| `GET` | `/v1/meta/key/sign` | None | Cluster ML-DSA Public Key. |
| `GET` | `/v1/meta/key/world` | None | Public Key for the 'world' identity. |
| `GET` | `/v1/node/info` | None | Node ID and protocol version. |
| `GET` | `/v1/auth/config` | None | OIDC Issuer and endpoint configuration. |
| `GET` | `/v1/cluster/stats` | None | Cluster-wide storage and node metrics. |

### 2.2 Identity & Authentication
| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/user/register` | OIDC JWT | Register a new user and public keys. |
| `POST` | `/v1/auth/challenge` | None | Request a login challenge for a User ID. |
| `POST` | `/v1/login` | Challenge | Exchange a signed challenge for a Session Token. |
| `GET` | `/v1/user/keysync` | Bearer JWT | Retrieve encrypted configuration backup. |
| `POST` | `/v1/user/keysync` | Session + E2EE | Store encrypted configuration backup. |
| `GET` | `/v1/user/{id}` | Session | Fetch a user's public profile (ID, UID, Keys). |
| `GET` | `/v1/user/groups` | Session | List all groups the user belongs to. |

### 2.3 Metadata & Inodes
| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/meta/inode/{id}` | Session | Fetch an Inode manifest. |
| `POST` | `/v1/meta/inodes` | Session | Batch fetch Inode manifests by ID. |
| `POST` | `/v1/meta/batch` | Session + E2EE | Atomic multi-command execution. |
| `POST` | `/v1/meta/allocate` | Session | Request target Data Nodes for a new chunk. |
| `POST` | `/v1/meta/token` | Session | Issue Storage Capability Token. |

### 2.4 Groups & Permissions
| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/group/` | Session + E2EE | Create a new security group. Payload: `{"id": "name", "quota_enabled": bool}`. |
| `GET` | `/v1/group/{id}` | Session | Fetch group metadata and members. |
| `PUT` | `/v1/group/{id}` | Session + E2EE | Update group (Owner/Admin only). |
| `GET` | `/v1/group/{id}/private` | Session + E2EE | Get Group Key (Encapsulated for member). |
| `GET` | `/v1/group/gid/allocate` | Session | Request a unique numeric GID. |

### 2.5 Data Node API
| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/data/{id}` | Signed Token | Download encrypted chunk. |
| `PUT` | `/v1/data/{id}` | Signed Token | Upload encrypted chunk. |
| `DELETE` | `/v1/data/{id}` | Signed Token | Permanently remove chunk. |
| `POST` | `/v1/data/{id}/replicate` | Signed Token | Trigger P2P replication to target nodes. |

---

## 3. Core Object Schemas

### 3.1 Inode
```json
{
  "id": "32_char_hex",
  "links": {"parentID:nameHMAC": true},
  "type": 0, // 0:File, 1:Dir, 2:Symlink
  "owner_id": "user_id",
  "group_id": "group_id",
  "mode": 420, // octal 0644
  "size": 1024,
  "ctime": 1772517680144,
  "nlink": 1,
  "client_blob": "base64_enc_metadata",
  "children": {"nameHMAC": "childID"},
  "manifest": [{"id": "chunk_hash", "nodes": ["node_id"]}],
  "chunk_pages": ["page_id"],
  "lockbox": {"recipient_id": {"kem": "base64", "dem": "base64"}},
  "version": 5,
  "is_system": false,
  "leases": {"nonce": {"id": "session_id", "exp": 123, "type": 1}},
  "unlinked": false,
  "user_sig": "base64_sig",
  "group_sig": "base64_sig"
}
```

### 3.2 `client_blob` (Internal Metadata)
Clients MUST use this schema inside the encrypted `client_blob`:
```json
{
  "name": "filename",
  "symlink_target": "path",
  "inline_data": "base64",
  "mtime": int64_ns,
  "uid": uint32,
  "gid": uint32,
  "signer_id": "user_id",
  "authorized_signers": ["user_id"]
}
```

### 3.3 User
```json
{
  "id": "derived_user_id",
  "uid": 1001,
  "sign_key": "base64_pub_dsa",
  "enc_key": "base64_pub_kem",
  "usage": {"inodes": 10, "bytes": 1048576},
  "quota": {"max_inodes": 1000, "max_bytes": 1073741824}
}
```

### 3.4 Group
```json
{
  "id": "group_id",
  "gid": 5001,
  "owner_id": "owner_user_id",
  "members": {"user_id": true},
  "enc_key": "base64_pub_kem",
  "sign_key": "base64_pub_dsa",
  "lockbox": {"recipient_id": {"kem": "base64", "dem": "base64"}},
  "version": 1,
  "signer_id": "user_id",
  "signature": "base64_sig",
  "quota_enabled": true
}
```

---

## 4. Manifest Integrity (Hashing Algorithms)

All multi-byte integers in hashes are **Big-Endian**.

### 4.1 Inode Hash
The `user_sig` is over the SHA-256 hash of these fields concatenated **exactly**:
1. `[]byte("id:" + id + "|")`
2. `[]byte("v:")` + `BigEndian(uint64(version))` + `[]byte("|")`
3. `[]byte("mode:")` + `BigEndian(uint32(mode))` + `[]byte("|")`
4. `[]byte("gid_str:" + group_id + "|")`
5. `[]byte("sys:" + (is_system ? "1" : "0") + "|")`
6. `[]byte("client_blob:")` + `raw_encrypted_bytes` + `[]byte("|")`
7. `[]byte("owner:" + owner_id + "|")`
8. `[]byte("type:")` + `BigEndian(uint32(type))` + `[]byte("|")`
9. `[]byte("links:")` + `SortedCSV(parentID:nameHMAC)` + `[]byte("|")`
10. `[]byte("children:")` + `SortedCSV(nameHMAC:childID)` + `[]byte("|")`
11. `[]byte("manifest:")` + `CSV(chunk_id(node1,node2,...))` + `[]byte("|")`
12. `[]byte("pages:")` + `SortedCSV(chunk_page_ids)` + `[]byte("|")`
13. `[]byte("lockbox:")` + `SortedCSV(id:kem+dem)` + `[]byte("|")`

### 4.2 Group Hash
The group `signature` is over the SHA-256 hash of these fields concatenated **exactly**:
1. `[]byte("DistFS-Group-v1|")`
2. `[]byte("group-id:" + id + "|")`
3. `[]byte("v:")` + `BigEndian(uint64(version))` + `[]byte("|")`
4. `[]byte("sys:" + (is_system ? "1" : "0") + "|")`
5. `[]byte("client_blob:")` + `client_blob_bytes` + `[]byte("|")`
6. `[]byte("owner:" + owner_id + "|")`
7. `[]byte("signer:" + signer_id + "|")`
8. `[]byte("members:")` + `SortedCSV(member_id:status)` + `[]byte("|")`
9. `[]byte("enc_key:")` + `enc_key_bytes` + `[]byte("|")`
10. `[]byte("sign_key:")` + `sign_key_bytes` + `[]byte("|")`
11. `[]byte("enc_sign_key:")` + `enc_sign_key_bytes` + `[]byte("|")`
12. `[]byte("lockbox:")` + `SortedCSV(id:kem+dem)` + `[]byte("|")`
13. `[]byte("registry_lockbox:")` + `SortedCSV(id:kem+dem)` + `[]byte("|")`
14. `[]byte("enc_registry:")` + `enc_registry_bytes` + `[]byte("|")`
15. `[]byte("quota_enabled:" + (quota_enabled ? "1" : "0") + "|")`

---

## 5. Zero-Knowledge Resolution

To hide filenames from the server, all map keys in `children` and `links` are HMACs:
`nameHMAC = Hex(HMAC-SHA256(Parent_FileKey, plaintext_filename))`

---

## 6. Coordination and Concurrency

### 6.1 Leases (`POST /v1/meta/lease/acquire`)
- **Request:** `{"inode_ids": ["..."], "type": 1, "duration": ns, "nonce": "..."}`
- **Types:** `0: Shared`, `1: Exclusive`.
- **Rule:** Mutations are rejected if an Exclusive lease is held by a different session.

### 6.2 Storage Tokens (`POST /v1/meta/token`)
- **Request:** `{"inode_id": "...", "chunks": ["hash"], "mode": "R|W|D"}`
- **Response:** `{"payload": "base64_minified_json", "sig": "base64_cluster_sig"}`
- **Capability Schema:** `{"chunks": ["hash"], "mode": "RWD", "exp": unix_ts}`

---

## 7. Error Code Registry

The DistFS API maps FSM sentinel errors to structured JSON HTTP responses (`APIErrorResponse`). The following table defines the authoritative conditions under which each error MUST be triggered.

| Code | HTTP | FSM Sentinel | Intended Trigger Condition |
| :--- | :--- | :--- | :--- |
| `DISTFS_NOT_FOUND` | 404 | `ErrNotFound` | The requested Inode, User, or Group ID does not exist in the BoltDB state. |
| `DISTFS_EXISTS` | 409 | `ErrExists` | Attempting to create an Inode, User, or Group ID that already exists. |
| `DISTFS_VERSION_CONFLICT` | 409 | `ErrConflict` | Optimistic concurrency failure: the `Version` field in an update command does not strictly equal the current `Version` in the BoltDB state + 1. |
| `DISTFS_LEASE_REQUIRED` | 409 | `ErrLeaseRequired` | A mutation (update/delete) was attempted on an Inode, but the request's `sessionID` does not hold a valid, unexpired `LeaseExclusive` for that Inode. |
| `DISTFS_QUOTA_EXCEEDED` | 403 | `ErrQuotaExceeded` | The operation would cause the debtor's (User or Group) `Usage` to strictly exceed their `Quota`. Note: Groups with `quota_enabled: true` are always the debtors for their files. |
| `DISTFS_QUOTA_DISABLED` | 403 | `ErrQuotaDisabled` | Attempted to set a quota on a group that was created with `quota_enabled: false`. |
| `DISTFS_UNAUTHORIZED` | 401 | (Auth Middleware) | The client failed to provide a valid signature, a valid session JWT, or the OIDC token is invalid/expired. |
| `DISTFS_FORBIDDEN` | 403 | (ACL Checks) | The authenticated user is not the owner of the Inode/Group, is not an Admin, or is attempting a restricted action (e.g. promoting an admin). |
| `DISTFS_NOT_LEADER` | 503 | `raft.ErrNotLeader` | The HTTP request was routed to a node that is not the current Raft leader. Clients MUST retry against a different node. |
| `DISTFS_STRUCTURAL_INCONSISTENCY` | 409 | `ErrStructuralInconsistency` | An atomic batch mutation would result in a corrupted filesystem graph. Examples: a parent directory claims a child, but the child does not have a reciprocal `links` entry; an Inode is deleted but still has an active lease. |
| `DISTFS_ATOMIC_ROLLBACK` | 500 / 409 | `ErrAtomicRollback` | An explicitly marked atomic `CmdBatch` encountered a failure in one of its sub-commands (e.g., a version conflict). The FSM MUST trigger a BoltDB `tx.Rollback()` and return this error wrapping the original sub-command failure. |
| `DISTFS_INTERNAL_ERROR` | 500 | (Various) | Unexpected errors, panics, cryptographic seal verification failures, or disk I/O errors. |

---

## 8. Header Behaviors

| Header | Usage | Effect |
| :--- | :--- | :--- |
| `Session-Token` | Mandatory for auth routes | Identifies the session and lease-owner. |
| `X-DistFS-Sealed` | Mandatory for mutations | Signals request body is a `SealedRequest`. |
| `X-DistFS-Admin-Bypass` | Optional (Admins only) | Bypasses ownership checks for recovery. |
| `X-DistFS-Sealed` | Optional for `GET` | If `true`, server returns a `SealedResponse`. |
