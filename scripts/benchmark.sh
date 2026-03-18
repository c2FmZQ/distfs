#!/bin/sh
set -e
# DistFS System Benchmark Script
# Measures latency and throughput for various operations

export DISTFS_PASSWORD=testpassword

echo "--- Starting DistFS System Benchmark ---"

# 1. Setup Benchmark Identity
echo "Initializing identity..."
JWT=$(wget -qO- "http://test-auth:8080/mint?email=bench-user@example.com")
# Benchmark user is already promoted and added to Administrators group by global setup.
# test-all-e2e.sh provisioned /tmp/bench-dir/config.json
export DISTFS_CONFIG_DIR="/tmp/bench-dir"

if [ ! -f "$DISTFS_CONFIG_DIR/config.json" ]; then
    distfs -disable-doh -use-pinentry=false init -server http://storage-node-1:8080 -jwt "$JWT" || \
    distfs -disable-doh -use-pinentry=false init --new -server http://storage-node-1:8080 -jwt "$JWT"
fi

echo "Stressing Metadata Layer (Raft)..."
# Use pre-provisioned /bench-workspace to avoid root signing issues
distfs-bench -server http://storage-node-1:8080 -jwt "$JWT" -mode mkdir -count 100 -path /bench-workspace

echo "Measuring Data Throughput (1MB Chunks)..."
distfs-bench -server http://storage-node-1:8080 -jwt "$JWT" -mode put -size 1048576 -count 10 -path /bench-workspace

echo "Benchmark Complete."
