#!/bin/bash
set -e
# Copyright 2026 TTBT Enterprises LLC
set -e

REPORT="DISTFS-REPORT.md"
LOG_DIR="$(dirname "$0")/../logs"
mkdir -p "$LOG_DIR"

echo "# DistFS Test & Performance Report" > $REPORT
echo "Date: $(date)" >> $REPORT
echo "" >> $REPORT

# 1. Build static binaries for Alpine compatibility
echo "Building binaries (static linking)..."
mkdir -p bin
CGO_ENABLED=0 go build -tags debug -o bin/storage-node ./cmd/storage-node
CGO_ENABLED=0 go build -o bin/distfs ./cmd/distfs
CGO_ENABLED=0 go build -o bin/distfs-fuse ./cmd/distfs-fuse
CGO_ENABLED=0 go build -o bin/test-auth ./cmd/test-auth
CGO_ENABLED=0 go build -o bin/distfs-bench ./cmd/distfs-bench
CGO_ENABLED=0 go build -o bin/distfs-fuse-load ./cmd/distfs-fuse-load

# Copy scripts to bin
cp scripts/test-*.sh bin/
chmod +x bin/test-*.sh

# 2. Run Unit Tests
echo "## Unit Tests" >> $REPORT
echo '```' >> $REPORT
echo "Running Unit Tests..."
go fmt ./...
go vet ./...
if ! go test ./... > "$LOG_DIR/unit-tests.log" 2>&1; then
    cat "$LOG_DIR/unit-tests.log" >> $REPORT
    echo '```' >> $REPORT
    echo "Unit Tests Failed"
    exit 1
fi
grep "ok" "$LOG_DIR/unit-tests.log" >> $REPORT || true
grep "FAIL" "$LOG_DIR/unit-tests.log" >> $REPORT || true
echo '```' >> $REPORT
echo "" >> $REPORT

# 3. Cleanup existing environment
echo "Cleaning up Docker environment..."
docker compose down -v --remove-orphans > /dev/null 2>&1

# 4. Run E2E Tests & Benchmarks
echo "Starting E2E and FUSE tests (15m timeout)..."
# Capture all output
if ! timeout 15m docker compose up --build --exit-code-from e2e-runner > "$LOG_DIR/all-logs.log" 2>&1; then
    E2E_FAILED=1
fi

# Extract clean logs from the e2e-runner service
docker compose logs --no-color --no-log-prefix e2e-runner > "$LOG_DIR/e2e-runner.log" 2>&1 || true

echo "## E2E and Benchmarks" >> $REPORT
echo '```' >> $REPORT
# Use -- to protect patterns starting with -
if grep -F -- "--- DISTFS E2E REPORT ---" "$LOG_DIR/e2e-runner.log" > /dev/null; then
    sed -n '/--- DISTFS E2E REPORT ---/,$p' "$LOG_DIR/e2e-runner.log" >> $REPORT
else
    echo "Warning: Report marker not found. Appending last 100 lines of the log." >> $REPORT
    tail -n 100 "$LOG_DIR/all-logs.log" >> $REPORT
fi
echo '```' >> $REPORT

# 5. Summary
echo "" >> $REPORT
echo "## Summary" >> $REPORT
if [ -z "$E2E_FAILED" ]; then
    echo "Overall Result: **PASSED**" >> $REPORT
else
    echo "Overall Result: **FAILED**" >> $REPORT
    echo "## Full Logs" >> $REPORT
    echo '```' >> $REPORT
    cat "$LOG_DIR/e2e-runner.log" >> $REPORT
    echo '```' >> $REPORT
fi

cat $REPORT

if [ ! -z "$E2E_FAILED" ]; then
    exit 1
fi
