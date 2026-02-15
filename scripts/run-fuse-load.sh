#!/bin/bash
# Independent runner for FUSE POSIX Load Test
set -e

echo "Building binaries for FUSE Load Test..."
mkdir -p bin
CGO_ENABLED=0 go build -o bin/storage-node ./cmd/storage-node
CGO_ENABLED=0 go build -o bin/distfs ./cmd/distfs
CGO_ENABLED=0 go build -o bin/distfs-fuse ./cmd/distfs-fuse
CGO_ENABLED=0 go build -o bin/test-auth ./cmd/test-auth
CGO_ENABLED=0 go build -o bin/distfs-fuse-load ./cmd/distfs-fuse-load

echo "Cleaning up existing load test environment..."
docker compose -f docker-compose.fuse-load.yml down -v --remove-orphans > /dev/null 2>&1

echo "Launching 15-minute FUSE Load Test..."
docker compose -f docker-compose.fuse-load.yml up --build --exit-code-from fuse-load-runner
