Here's a summary of how `github.com/c2FmZQ/storage` is used for encryption.

The system employs authenticated encryption (AES-256-GCM) via the `github.com/c2FmZQ/storage` library to secure persistent data on disk.

**Key Management:**
*   **Node-Local Key Management:** Each node maintains its own unique encryption keys.
*   **Root Secret:** An `DISTFS_MASTER_KEY` environment variable provides a master passphrase.
*   **Master Key Derivation:** A `crypto.MasterKey` (from github.com/c2FmZQ/storage/crypto) is derived from this passphrase. If a `data/master.key` file exists, it's decrypted; otherwise, a new Master Key is generated, encrypted, and saved.
*   **Isolation:** Encryption keys are never shared across the network; data is decrypted by the sender and re-encrypted by the receiver using their own local keys.

**Local files:**
* All local metadata files and encrypted at rest using `github.com/c2FmZQ/storage` via `Storage.ReadDataFile()` and `Storage.SaveDataFile()`.
* This includes the local raft configuration, cryptographic keys, etc.
* The chunk files are encrypted again by the backend using `Storage.OpenBlobWrite` and `Storage.OpenBlobRead`.

**Summary**
* All files written to local disk are encrypted using either `github.com/c2FmZQ/storage` itself, or an encryption key that is itself stored encrypted.
* `DISTFS_MASTER_KEY` is the only thing that is not encrypted.
