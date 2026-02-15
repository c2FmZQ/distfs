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

LOG_FILE="fuse-load-$(date +%Y%m%d-%H%M%S).log"
echo "Launching 15-minute FUSE Load Test (Logging to $LOG_FILE)..."

# Run docker-compose in the background
docker compose -f docker-compose.fuse-load.yml up --build --exit-code-from fuse-load-runner > "$LOG_FILE" 2>&1 &
DOCKER_PID=$!

# Heartbeat loop
while ps -p $DOCKER_PID > /dev/null; do
    echo "Test is running. See output in $LOG_FILE"
    sleep 10
done

# Wait for process to get final exit code
wait $DOCKER_PID || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}

if [ $EXIT_CODE -eq 0 ]; then
    echo "FUSE Load Test finished successfully."
else
    echo "FUSE Load Test failed with exit code $EXIT_CODE."
    exit $EXIT_CODE
fi
