#!/bin/bash -e
# Copyright 2026 TTBT Enterprises LLC

echo "Building production binaries (static linking)..."
mkdir -p bin

CGO_ENABLED=0 go build -o bin/storage-node ./cmd/storage-node
CGO_ENABLED=0 go build -o bin/distfs ./cmd/distfs
CGO_ENABLED=0 go build -o bin/distfs-fuse ./cmd/distfs-fuse
CGO_ENABLED=0 go build -o bin/distfs-bench ./cmd/distfs-bench
CGO_ENABLED=0 go build -o bin/distfs-fuse-load ./cmd/distfs-fuse-load

echo "Building WASM module..."
GOOS=js GOARCH=wasm go build -o web/distfs.wasm ./cmd/distfs-wasm

echo "Transpiling TypeScript..."
npx tsc

echo "Production build complete. Binaries are in bin/"
