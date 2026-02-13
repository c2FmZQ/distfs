# Copyright 2026 TTBT Enterprises LLC
FROM alpine:latest

# Install fuse3 for the fuse-tester container
RUN apk add --no-cache fuse3

COPY bin/storage-node /bin/storage-node
COPY bin/distfs /bin/distfs
COPY bin/distfs-fuse /bin/distfs-fuse
COPY bin/test-auth /bin/test-auth
COPY scripts/test-e2e.sh /bin/test-e2e.sh
COPY scripts/test-fuse.sh /bin/test-fuse.sh
COPY scripts/test-ha.sh /bin/test-ha.sh
COPY scripts/test-stress.sh /bin/test-stress.sh
COPY scripts/test-gc.sh /bin/test-gc.sh
COPY scripts/test-integrity.sh /bin/test-integrity.sh
COPY scripts/test-public.sh /bin/test-public.sh
COPY scripts/test-writable.sh /bin/test-writable.sh
COPY scripts/test-all-e2e.sh /bin/test-all-e2e.sh
RUN chmod +x /bin/test-e2e.sh /bin/test-fuse.sh /bin/test-ha.sh /bin/test-stress.sh /bin/test-gc.sh /bin/test-integrity.sh /bin/test-public.sh /bin/test-writable.sh /bin/test-all-e2e.sh

ENTRYPOINT ["/bin/storage-node"]