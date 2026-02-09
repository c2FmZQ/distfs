# Copyright 2026 TTBT Enterprises LLC
FROM alpine:latest

# Install fuse3 for the fuse-tester container
RUN apk add --no-cache fuse3

COPY bin/storage-node /bin/storage-node
COPY bin/distfs /bin/distfs
COPY bin/distfs-fuse /bin/distfs-fuse
COPY scripts/test-e2e.sh /bin/test-e2e.sh
COPY scripts/test-fuse.sh /bin/test-fuse.sh
RUN chmod +x /bin/test-e2e.sh /bin/test-fuse.sh

ENTRYPOINT ["/bin/storage-node"]