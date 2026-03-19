# Copyright 2026 TTBT Enterprises LLC
FROM mcr.microsoft.com/playwright:v1.58.2-jammy

# Disable interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install fuse3 and acl for the fuse-tester container
RUN apt-get update && apt-get install -y tzdata fuse3 jq curl acl wget && rm -rf /var/lib/apt/lists/*

WORKDIR /distfs
COPY package.json package-lock.json tests/playwright.config.ts tsconfig.json ./
COPY web/ts ./web/ts
RUN npm ci && npx tsc && npx playwright install --with-deps chromium

COPY tests/bin/storage-node /bin/storage-node
COPY tests/bin/distfs /bin/distfs
COPY tests/bin/distfs-fuse /bin/distfs-fuse
COPY tests/bin/test-auth /bin/test-auth
COPY tests/bin/distfs-bench /bin/distfs-bench
COPY tests/bin/distfs-fuse-load /bin/distfs-fuse-load
COPY tests/bin/web-test-server /bin/web-test-server
COPY web /distfs/web
COPY tests/test-e2e.sh /bin/test-e2e.sh
COPY tests/test-fuse.sh /bin/test-fuse.sh
COPY tests/test-ha.sh /bin/test-ha.sh
COPY tests/test-stress.sh /bin/test-stress.sh
COPY tests/test-gc.sh /bin/test-gc.sh
COPY tests/test-integrity.sh /bin/test-integrity.sh
COPY tests/test-public.sh /bin/test-public.sh
COPY tests/test-group.sh /bin/test-group.sh
COPY tests/test-group-quota.sh /bin/test-group-quota.sh
COPY tests/test-keysync-e2e.sh /bin/test-keysync-e2e.sh
COPY tests/test-hedged-reads.sh /bin/test-hedged-reads.sh
COPY tests/test-contact-exchange.sh /bin/test-contact-exchange.sh
COPY tests/test-dump-inodes.sh /bin/test-dump-inodes.sh
COPY tests/test-quota-cmd.sh /bin/test-quota-cmd.sh
COPY tests/test-ls-e2e.sh /bin/test-ls-e2e.sh
COPY tests/test-audit.sh /bin/test-audit.sh
COPY tests/test-registry.sh /bin/test-registry.sh
COPY tests/benchmark.sh /bin/benchmark.sh
COPY tests/test-fuse-load.sh /bin/test-fuse-load.sh
COPY tests/test-fileutils.sh /bin/test-fileutils.sh
COPY tests/test-all-e2e.sh /bin/test-all-e2e.sh
RUN chmod +x /bin/test-e2e.sh /bin/test-fuse.sh /bin/test-ha.sh /bin/test-stress.sh /bin/test-gc.sh /bin/test-integrity.sh /bin/test-public.sh /bin/test-group.sh /bin/test-group-quota.sh /bin/test-keysync-e2e.sh /bin/test-hedged-reads.sh /bin/test-contact-exchange.sh /bin/test-dump-inodes.sh /bin/test-quota-cmd.sh /bin/test-ls-e2e.sh /bin/test-audit.sh /bin/test-registry.sh /bin/benchmark.sh /bin/test-fuse-load.sh /bin/test-fileutils.sh /bin/test-all-e2e.sh

ENTRYPOINT ["/bin/storage-node"]