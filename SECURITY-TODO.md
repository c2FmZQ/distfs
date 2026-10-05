# Security Review TODO

Findings from the 2026-10-05 full-codebase security review. Each item is resolved in its own
commit with a regression test. This file is deleted once every item is checked off.

Threat model: (a) unauthenticated network attackers, (b) authenticated users attacking other
users, (c) a malicious/compromised metadata server (clients must detect tampering).

## Critical

- [x] **S1. Double `RUnlock` crashes the leader** — `pkg/metadata/server.go` `unsealRequest`.
  Expired cached session key path calls `sessionKeyMu.RUnlock()` twice → fatal, unrecoverable.
  Fix: remove the second `RUnlock`. Test: expired cache entry falls back without panicking.

- [x] **S2. Login challenge is a signing oracle** — `pkg/client/client.go` `Login`, `pkg/metadata/server.go` `handleLogin`.
  Client signs a raw server-chosen 32-byte challenge with its identity key; a malicious server can
  set it to an inode `ManifestHash()` and obtain a valid `UserSig`.
  Fix: domain-separate (sign `"DistFS-Login-v1\x00" || challenge`), verify the same on server;
  document in SERVER-API.md. Test: login sig does not verify as a raw signature over the challenge.

- [x] **S3. IssueToken mints arbitrary chunk capabilities** — `pkg/metadata/server.go` `handleIssueToken`.
  Modes other than exactly `"W"` only require read; `req.Chunks` is never checked against the
  inode manifest; `"D"`/`"RW"` grant delete / skip quota reservation.
  Fix: allow only modes `R`, `W`, `D`. `R`: require read + every chunk in the inode manifest.
  `W`: require write (or new inode) + reservation. `D`: require write + chunks must NOT be referenced
  by the inode's committed manifest (upload-failure cleanup only). Test: D/RW/R-on-foreign-chunk rejected.

- [x] **S4. Group takeover via CreateGroup on existing ID** — `pkg/metadata/fsm.go` `executeCreateGroup`, server Batch handler.
  No existence check; `SelfOwnedGroup` skips authz. Fix: reject if `groups[ID]` exists (FSM + handler).
  Test: second CreateGroup with existing ID fails.

- [x] **S5. Chunk-page hijack / deletion** — `pkg/metadata/fsm.go` create/update inode & lease placeholders.
  Client-supplied `ChunkPages` IDs are not bound to the inode; update-to-`[]` deletes victim pages,
  and delete→GC loads victim pages. Fix: reject any page ID not of the form `<inode.ID>:p<i>`.
  Test: foreign page IDs rejected.

- [x] **S6. GC / replication delete chunks listed in any manifest** — `pkg/metadata/fsm.go`, `gc.go`, `replication.go`.
  `ChunkManifest` IDs are client-chosen and not bound to the uploader. A user lists a victim's chunk
  IDs in their own file and deletes it → GC deletes the victim's chunks; listing extra nodes makes the
  replication "over-replicated" prune delete real replicas. Fix: FSM chunk ownership index
  (chunk ID → inode); a manifest may only add chunks that are unowned or already owned by the same
  inode; GC only deletes chunks owned by the inode being finalized; rebuild index from inodes on
  restore. Replication must not prune based on client-supplied node lists. Test.

## High — client must not trust the server

- [x] **C1. Inode signer key fetched unverified** — `pkg/client/client.go` `verifyInode` (+ group signer, owner delegation).
  Signature checked against a fresh server-supplied key; deferred queue only re-checks by ID.
  Fix: resolve signer keys via the anchor-verified path (`getUser`/verified cache), never `getUserUnverified`.
  Test: server substitutes signer key → verification fails.

- [x] **C2. verifyUser / verifyGroup chain uses unverified verifier keys** — `client.go` `verifyUser`, `verifyGroup`.
  Also check `entry.UserID == user.ID` and group ID equality. Test: forged attestation rejected.

- [x] **C3. Key substitution in provisionRecipient / AddUserToGroup** — `client.go` `provisionRecipient`, `AddUserToGroup`, `setAttrByID`.
  Fix: use verified user/group keys; honor `ContactInfo` keys when provided; fail (not debug-log) on
  group verification failure. Test: unverified recipient key rejected.

- [x] **C4. Admin anchoring TOCTOU + 24-bit code** — `client.go` `GetUserVerificationCode`, `AnchorUserInRegistry`, `cmd/distfs/admin.go`.
  Fix: anchor exactly the keys the code was computed from (pass them through); lengthen code to ≥ 80 bits.

- [x] **C5. Inode ID substitution** — `client.go` `getInodeInternal`, `directory.go` `resolveSequential`, FUSE refresh paths.
  Fix: reject when `fetched.ID != requested id`. Test.

- [x] **C6. Unsealed / unbound responses trusted** — `client.go` `unsealResponse`, `doRequest`.
  Fix: when the request expects a sealed response, reject unsealed bodies; require binding signature
  on sealed responses; don't silently skip when cluster key fetch fails.

- [x] **C7. Chunk ciphertext not checked against chunk ID** — `client.go` `downloadChunk`.
  Fix: verify `sha256(ciphertext) == chunkID` before decrypt/cache. Test: swapped chunk rejected.

- [x] **C8. Inode `Size` unsigned** — `pkg/metadata/types.go` `ManifestHash`.
  Fix: include `Size` in the manifest hash (client + server). Test: size tamper detected.

- [x] **C9. Mutation results trusted & cached unverified** — `client.go` `updateInodeInternal`, `createInode`; root anchor updated before verify in `getInodeInternal`.
  Fix: verify returned inodes before caching; update root anchor only after verification.

## Medium

- [x] **M1. JWT missing audience/issuer/exp checks** — `server.go` `verifyJWT`. Fix: `WithIssuer`, `WithAudience` (configured client ID), `WithExpirationRequired`.
- [x] **M2. GetInode/GetInodes unauthorized** — `server.go`. Resolved as far as the design allows:
  other sessions' lease identifiers are redacted. Signed fields (chunk IDs, children) cannot be
  withheld without breaking client verification (e.g. `ls -l` of files the user cannot read), and
  the server cannot see anonymous group members; S3/S5/S6 removed what made chunk IDs exploitable.
- [x] **M3. Leases unauthorized; batch sub-command `sid`/`ts` overridable** — `fsm.go` `executeAcquireLeases`, batch apply.
  Fix: require write access to lease; always overwrite `uid`/`sid`/`ts` from the authenticated outer command.
- [x] **M4. Group membership HMAC keyed by public group ID** — Doc fix: DISTFS-RAFT §2.3 overstated the guarantee. Membership must be visible to the server (it enforces group permissions) and members cannot hold a secret before decrypting their entry; anonymity is provided by the AnonymousLockbox (Theorem 11).
- [x] **M5. Quota bypasses** — self-owned quota group with quota 0 = unlimited; client-set `Usage`/`Quota` persisted on group create/update; client-declared `Size` 0. Fix: ignore client `Usage`/`Quota`; enforce user quota as fallback.
- [x] **M6. Locked users keep live sessions** — `server.go` `sessionTokenCache`. Fix: re-check lock state from FSM per request / evict on lock.
- [x] **M7. Replay key uses unauthenticated prefix** — `server.go` `checkReplay`. Fix: key on hash of the authenticated DEM ciphertext / signature.
- [ ] **M8. Cluster join TOFU MITM** — `server.go` `handleClusterJoin`. Fix: bind HMAC proof over the returned public keys; don't send raft secret over unverified channel.
- [ ] **M9. Web service worker serves decrypted HTML/SVG inline** — `web/sw.js`. Fix: `Content-Security-Policy: sandbox`, `nosniff`, block active types / force attachment, reject navigations; unregister stale workers.
- [ ] **M10. Web login ignores pinned server key** — `web/ts/app.ts`. Fix: use `config.server_key`.

## Low

- [ ] **L1. Peer identity truncated to 64 bits** — `node_identity.go`, `raft_manager.go` `verifyPeer`. Fix: compare full public key.
- [ ] **L2. Unbounded `/v1/auth/challenge` body + cache** — `server.go`. Fix: `MaxBytesReader`, validate user ID format, cap cache.
- [ ] **L3. Non-deterministic FSM apply (`time.Now()`)** — `fsm.go`. Fix: leader stamps `LogCommand.Timestamp`; FSM uses it.
