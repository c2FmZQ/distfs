# Copyright 2026 TTBT Enterprises LLC
FROM alpine:latest

# Install fuse3 and acl for the fuse-tester container
RUN apk add --no-cache fuse3 tzdata jq curl acl

COPY bin/storage-node /bin/storage-node
COPY bin/distfs /bin/distfs
COPY bin/distfs-fuse /bin/distfs-fuse
COPY bin/test-auth /bin/test-auth
COPY bin/distfs-bench /bin/distfs-bench
COPY bin/distfs-fuse-load /bin/distfs-fuse-load
COPY scripts/test-e2e.sh /bin/test-e2e.sh
COPY scripts/test-fuse.sh /bin/test-fuse.sh
COPY scripts/test-ha.sh /bin/test-ha.sh
COPY scripts/test-stress.sh /bin/test-stress.sh
COPY scripts/test-gc.sh /bin/test-gc.sh
COPY scripts/test-integrity.sh /bin/test-integrity.sh
COPY scripts/test-public.sh /bin/test-public.sh
COPY scripts/test-group.sh /bin/test-group.sh
COPY scripts/test-group-quota.sh /bin/test-group-quota.sh
COPY scripts/test-keysync-e2e.sh /bin/test-keysync-e2e.sh
COPY scripts/test-hedged-reads.sh /bin/test-hedged-reads.sh
COPY scripts/test-contact-exchange.sh /bin/test-contact-exchange.sh
COPY scripts/test-dump-inodes.sh /bin/test-dump-inodes.sh
COPY scripts/test-quota-cmd.sh /bin/test-quota-cmd.sh
COPY scripts/test-ls-e2e.sh /bin/test-ls-e2e.sh
COPY scripts/test-audit.sh /bin/test-audit.sh
COPY scripts/test-registry.sh /bin/test-registry.sh
COPY scripts/test-posix-acls.sh /bin/test-posix-acls.sh
COPY scripts/benchmark.sh /bin/benchmark.sh
COPY scripts/test-fuse-load.sh /bin/test-fuse-load.sh
COPY scripts/test-all-e2e.sh /bin/test-all-e2e.sh
RUN chmod +x /bin/test-e2e.sh /bin/test-fuse.sh /bin/test-ha.sh /bin/test-stress.sh /bin/test-gc.sh /bin/test-integrity.sh /bin/test-public.sh /bin/test-group.sh /bin/test-group-quota.sh /bin/test-keysync-e2e.sh /bin/test-hedged-reads.sh /bin/test-contact-exchange.sh /bin/test-dump-inodes.sh /bin/test-quota-cmd.sh /bin/test-ls-e2e.sh /bin/test-audit.sh /bin/test-registry.sh /bin/test-posix-acls.sh /bin/benchmark.sh /bin/test-fuse-load.sh /bin/test-all-e2e.sh

ENTRYPOINT ["/bin/storage-node"]