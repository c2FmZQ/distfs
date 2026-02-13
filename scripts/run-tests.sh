#!/bin/bash
# Copyright 2026 TTBT Enterprises LLC
set -e

# 1. Build static binaries for Alpine compatibility
echo "Building binaries (static linking)..."
mkdir -p bin
CGO_ENABLED=0 go build -o bin/storage-node ./cmd/storage-node
CGO_ENABLED=0 go build -o bin/distfs ./cmd/distfs
CGO_ENABLED=0 go build -o bin/distfs-fuse ./cmd/distfs-fuse
CGO_ENABLED=0 go build -o bin/test-auth ./cmd/test-auth

# 2. Cleanup existing environment
echo "Cleaning up Docker environment..."
docker compose down -v --remove-orphans

# 3. Run tests
echo "Starting E2E and FUSE tests..."
docker compose up --build --exit-code-from e2e-runner
