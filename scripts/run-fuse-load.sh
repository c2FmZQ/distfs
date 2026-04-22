#!/bin/bash
# Independent runner for FUSE POSIX Load Test
set -e

echo "Building binaries for FUSE Load Test..."
mkdir -p tests/bin
CGO_ENABLED=0 go build -tags debug,pprof -o tests/bin/storage-node ./cmd/storage-node
CGO_ENABLED=0 go build -tags debug,pprof -o tests/bin/distfs ./cmd/distfs
CGO_ENABLED=0 go build -tags debug,pprof -o tests/bin/distfs-fuse ./cmd/distfs-fuse
CGO_ENABLED=0 go build -tags debug,pprof -o tests/bin/test-auth ./cmd/test-auth
CGO_ENABLED=0 go build -tags debug,pprof -o tests/bin/distfs-fuse-load ./cmd/distfs-fuse-load

echo "Cleaning up existing load test environment..."
docker compose -f tests/docker-compose.fuse-load.yml down -v --remove-orphans

LOG_FILE="logs/fuse-load-$(date +%Y%m%d-%H%M%S).log"
echo "Launching 5-minute FUSE Load Test (Logging to $LOG_FILE)..."

# Run docker-compose in the background
timeout 10m docker compose -f tests/docker-compose.fuse-load.yml up --build --exit-code-from fuse-load-runner > "$LOG_FILE" 2>&1 &
DOCKER_PID=$!

PROFILED=0
START_TIME=$(date +%s)

# Heartbeat loop
while ps -p $DOCKER_PID > /dev/null; do
    echo "Test is running. See output in $LOG_FILE"

    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))

    if [ $ELAPSED -gt 60 ] && [ $PROFILED -eq 0 ]; then
        echo "Capturing CPU profiles (15s)..."
        curl -s http://localhost:8080/debug/pprof/profile?seconds=15 > node1.pprof &
        P1=$!
        curl -s http://localhost:6061/debug/pprof/profile?seconds=15 > fuse.pprof &
        P2=$!
        wait $P1 $P2 || true
        echo "Profiles captured: node1.pprof, fuse.pprof"
        PROFILED=1
    fi

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
