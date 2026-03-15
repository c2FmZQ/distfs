# Copyright 2026 TTBT Enterprises LLC
FROM mcr.microsoft.com/playwright:v1.58.2-jammy

# Disable interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install fuse3 and acl for the fuse-tester container
RUN apt-get update && apt-get install -y tzdata fuse3 jq curl acl wget && rm -rf /var/lib/apt/lists/*

WORKDIR /distfs
COPY package.json package-lock.json playwright.config.ts tsconfig.json ./
COPY web/ts ./web/ts
RUN npm ci && npx tsc && npx playwright install --with-deps chromium

COPY bin/storage-node /bin/storage-node
COPY bin/distfs /bin/distfs
COPY bin/distfs-fuse /bin/distfs-fuse
COPY bin/test-auth /bin/test-auth
COPY bin/distfs-bench /bin/distfs-bench
COPY bin/distfs-fuse-load /bin/distfs-fuse-load
COPY bin/web-test-server /bin/web-test-server
COPY web /distfs/web
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
COPY scripts/benchmark.sh /bin/benchmark.sh
COPY scripts/test-fuse-load.sh /bin/test-fuse-load.sh
COPY scripts/test-all-e2e.sh /bin/test-all-e2e.sh
RUN chmod +x /bin/test-e2e.sh /bin/test-fuse.sh /bin/test-ha.sh /bin/test-stress.sh /bin/test-gc.sh /bin/test-integrity.sh /bin/test-public.sh /bin/test-group.sh /bin/test-group-quota.sh /bin/test-keysync-e2e.sh /bin/test-hedged-reads.sh /bin/test-contact-exchange.sh /bin/test-dump-inodes.sh /bin/test-quota-cmd.sh /bin/test-ls-e2e.sh /bin/test-audit.sh /bin/test-registry.sh /bin/benchmark.sh /bin/test-fuse-load.sh /bin/test-all-e2e.sh

ENTRYPOINT ["/bin/storage-node"]