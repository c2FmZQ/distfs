# <img src="distfs-256x256.png" width="48" height="48" align="center" style="margin-right: 10px;"> DistFS: Secure Distributed File System

[![Overview Video](https://img.youtube.com/vi/nVz-Q2cq1rU/0.jpg)](https://youtu.be/nVz-Q2cq1rU)

DistFS is an experimental distributed, end-to-end encrypted (E2EE) file system. It is designed as a research platform to explore the boundaries of zero-knowledge privacy, strongly consistent metadata, and post-quantum cryptography (PQC) within a POSIX-compliant architecture.

The core tension DistFS resolves is the fundamental incompatibility between high-fidelity POSIX environments (which require granular ACLs, atomic renames, distributed locking) and a zero-knowledge model (where the server must remain mathematically blind to the data payload and structure).

## 📖 Design Documentation

For comprehensive technical deep-dives into the architecture and security model, please refer to our living documentation:

*   **[DISTFS.md](docs/DISTFS.md):** Core architectural pillars, threat model, and cryptographic mechanisms.
*   **[SERVER-API.md](docs/SERVER-API.md):** The exhaustive Client <-> Server protocol contract.
*   **[CLIENT-API.md](docs/CLIENT-API.md):** The high-level Go Client API (`fs.FS` compatible).

## ✨ Key Research Areas

*   **Post-Quantum Cryptography (PQC) at Layer 7:** Bakes NIST-standardized PQC (ML-KEM-768 / ML-DSA-65) directly into the application layer for all RPC mutations.
*   **Zero-Knowledge POSIX ACLs:** Maps standard Linux FUSE xattrs into a dynamic cryptographic "Lockbox" for granular, server-blind access control.
*   **WASM-Powered Web Client:** Brings the "Trust No One" mandate to the browser with decryption-on-the-fly via Service Workers.
*   **The "Dark Registry":** Minimizes PII exposure by operating entirely on opaque cryptographic UUIDs and enforcing Out-Of-Band (OOB) governance.
*   **Sovereign Chain of Trust:** Ensures mathematical truth (signatures and hashes) always overrides server database claims via a verifiable timeline and response binding.
*   **Secure Persistent Caching:** Provides seamless read-only offline access backed by an AES-256-GCM encrypted Universal KVStore.

## 🚀 Quick Start

DistFS is built for Linux and requires Go 1.25+ and `fuse3`.

```bash
git clone https://github.com/c2FmZQ/distfs.git
cd distfs

# Build core binaries
go build ./cmd/distfs
go build ./cmd/distfs-fuse
go build ./cmd/storage-node

# Spin up a local test cluster
export DISTFS_MASTER_KEY="local-dev-secret"
./storage-node --id local-1 --bootstrap --api-addr :8080 --raft-bind :8081

# Initialize a new account
./distfs init --new --server http://localhost:8080
```

Run the automated test suite (requires Docker for full E2E testing):
```bash
./scripts/run-tests.sh
```

## 🤝 Call for Scrutiny and Contributions

DistFS is an active research project. We deliberately invite researchers, cryptographers, and systems engineers to review the architecture, attempt to break the cryptographic provenance, and contribute to the evolution of post-quantum distributed storage.

*   **Security Audits:** If you find a flaw in the cryptographic provenance, Lockbox expansion, sealing algorithms, or rollback protections, please open an issue or reach out.
*   **Performance:** We welcome benchmarking data and PRs for further zero-copy network paths and GC optimizations.
*   **Contributions:** Pull requests are highly encouraged. Please ensure all modifications pass the rigorous test suite before submitting.

## License

Copyright 2026 TTBT Enterprises LLC. Licensed under the Apache License, Version 2.0.
