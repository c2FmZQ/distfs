#!/bin/sh
set -e
# System Performance Benchmark
set -e

echo "--- Starting DistFS System Benchmark ---"

# Wait for services
sleep 2

SERVER_URL="http://storage-node-1:8080"
AUTH_URL="http://test-auth:8080"
JWT=$(wget -qO- "$AUTH_URL/mint?email=bench-user@example.com")

# 1. Metadata Benchmark (mkdir)
echo "Stressing Metadata Layer (Raft)..."
/bin/distfs-bench -server "$SERVER_URL" -jwt "$JWT" -admin -mode mkdir -workers 5 -count 100

# 2. Small File Throughput (1KB)
echo "Benchmarking Small File Throughput (1KB)..."
/bin/distfs-bench -server "$SERVER_URL" -jwt "$JWT" -admin -mode put -workers 5 -count 10 -size 1024

# 3. Large File Throughput (5MB)
echo "Benchmarking Large File Throughput (5MB)..."
/bin/distfs-bench -server "$SERVER_URL" -jwt "$JWT" -admin -mode put -workers 2 -count 20 -size 5242880

# 4. Read Latency & Throughput (5MB)
echo "Benchmarking Read Performance (5MB)..."
/bin/distfs-bench -server "$SERVER_URL" -jwt "$JWT" -admin -mode get -workers 2 -count 20 -size 5242880

echo "--- Benchmark Complete ---"
