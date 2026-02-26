#!/bin/bash
set -e
set -ex

# Build
echo "Building binaries..."
go build -o bin/storage-node ./cmd/storage-node
go build -o bin/distfs-bench ./cmd/distfs-bench

# Cleanup
rm -rf data-bench
rm -f /tmp/bench-config.json

# Start Server
echo "Starting Storage Node..."
export DISTFS_MASTER_KEY=bench-secret
./bin/storage-node -id node1 -bootstrap -data-dir data-bench -raft-secret mysecret -oidc-discovery-url http://127.0.0.1:8081/.well-known/openid-configuration > node.log 2>&1 &
SERVER_PID=$!

cleanup() {
    echo "Stopping server..."
    kill $SERVER_PID
    wait $SERVER_PID 2>/dev/null
}
trap cleanup EXIT

# Wait for startup
sleep 5

echo "Starting Auth Server..."
go build -o bin/test-auth ./cmd/test-auth
./bin/test-auth -addr :8082 > auth.log 2>&1 &
AUTH_PID=$!

cleanup_all() {
    echo "Stopping servers..."
    kill $SERVER_PID
    kill $AUTH_PID
    wait $SERVER_PID 2>/dev/null
    wait $AUTH_PID 2>/dev/null
}
trap cleanup_all EXIT

sleep 2

# Restart Storage Node with OIDC
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null
./bin/storage-node -id node1 -data-dir data-bench -raft-secret mysecret -oidc-discovery-url http://127.0.0.1:8082/.well-known/openid-configuration > node.log 2>&1 &
SERVER_PID=$!
sleep 5

# Get JWT
JWT=$(curl -s "http://127.0.0.1:8082/mint?email=bench@example.com")
echo "Got JWT: $JWT"

go build -o bin/distfs ./cmd/distfs

echo "Running Benchmark (Creating Inodes)..."
./bin/distfs-bench -server http://127.0.0.1:8080 -jwt "$JWT" -mode mkdir -count 1000 -workers 4 > bench.log 2>&1
cat bench.log

# Capture Metrics
echo "Metrics:"
curl -s -H "X-Raft-Secret: mysecret" http://127.0.0.1:8080/v1/system/metrics > metrics_before.json
cat metrics_before.json
