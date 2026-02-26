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
| `POST` | `/v1/meta/batch` | Session + E2EE | Atomic multi-command execution. |
| `POST` | `/v1/meta/allocate` | Session | Request target Data Nodes for a new chunk. |
| `POST` | `/v1/meta/token` | Session | Issue Storage Capability Token. |

### 2.4 Groups & Permissions
| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/group/` | Session + E2EE | Create a new security group. |
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
  "type": 0, // 0:File, 1:Dir, 2:Symlink
  "owner_id": "user_id",
  "group_id": "group_id",
  "mode": 420, // octal 0644
  "size": 1024,
  "links": {"parentID:nameHMAC": true},
  "children": {"nameHMAC": "childID"},
  "manifest": [{"id": "chunk_hash", "nodes": ["node_id"]}],
  "lockbox": {"recipient_id": {"kem": "base64", "dem": "base64"}},
  "client_blob": "base64_enc_metadata",
  "version": 5,
  "user_sig": "base64_sig"
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
  "signature": "base64_sig"
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
8. `[]byte("links:")` + `SortedCSV(parentID:nameHMAC)` + `[]byte("|")`
9. `[]byte("children:")` + `SortedCSV(nameHMAC:childID)` + `[]byte("|")`
10. `[]byte("manifest:")` + `CSV(chunk_ids)` + `[]byte("|")`
11. `[]byte("pages:")` + `SortedCSV(chunk_page_ids)` + `[]byte("|")`
12. `[]byte("lockbox:")` + `SortedCSV(id:kem+dem)` + `[]byte("|")`

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

| Code | HTTP | Description |
| :--- | :--- | :--- |
| `DISTFS_NOT_FOUND` | 404 | Resource does not exist. |
| `DISTFS_EXISTS` | 409 | Resource already exists. |
| `DISTFS_VERSION_CONFLICT` | 409 | Version mismatch (Optimistic concurrency). |
| `DISTFS_LEASE_REQUIRED` | 409 | Mutation attempted without Exclusive lease. |
| `DISTFS_QUOTA_EXCEEDED` | 403 | Storage or Inode limit reached. |
| `DISTFS_UNAUTHORIZED` | 401 | Invalid session, signature, or token. |
| `DISTFS_FORBIDDEN` | 403 | Insufficient permissions (ACL). |
| `DISTFS_NOT_LEADER` | 503 | Node is not the Raft leader. |

---

## 8. Header Behaviors

| Header | Usage | Effect |
| :--- | :--- | :--- |
| `Session-Token` | Mandatory for auth routes | Identifies the session and lease-owner. |
| `X-DistFS-Sealed` | Mandatory for mutations | Signals request body is a `SealedRequest`. |
| `X-DistFS-Admin-Bypass` | Optional (Admins only) | Bypasses ownership checks for recovery. |
| `X-DistFS-Sealed` | Optional for `GET` | If `true`, server returns a `SealedResponse`. |
