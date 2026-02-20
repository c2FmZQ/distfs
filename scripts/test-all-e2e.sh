#!/bin/sh
# Unified E2E and Benchmark Runner
REPORT_FILE="/tmp/distfs-e2e-report.txt"
echo "--- DISTFS E2E REPORT ---" > $REPORT_FILE

run_test() {
    name=$1
    script=$2
    echo "Running $name..."
    # Run in subshell
    ( $script )
    if [ $? -eq 0 ]; then
        echo "[PASS] $name" | tee -a $REPORT_FILE
        return 0
    else
        echo "[FAIL] $name" | tee -a $REPORT_FILE
        return 1
    fi
}

echo "Starting Unified E2E Test Suite..."
sleep 2

# GLOBAL SETUP: Create Admin and make root world-writable
echo "PERFORMING GLOBAL SETUP..."
MAX_RETRIES=30
COUNT=0
while true; do
    JWT=$(wget -qO- "http://test-auth:8080/mint?email=admin@example.com")
    if distfs -use-pinentry=false init --new -server http://storage-node-1:8080 -jwt "$JWT"; then
        break
    fi
    COUNT=$((COUNT + 1))
    if [ $COUNT -ge $MAX_RETRIES ]; then
        echo "GLOBAL SETUP FAILED: Could not initialize admin"
        exit 1
    fi
    sleep 2
done

echo "GLOBAL SETUP COMPLETE. Admin ID:"
distfs -use-pinentry=false whoami

echo "Creating /users directory..."
distfs -use-pinentry=false mkdir /users
distfs -use-pinentry=false chmod 0755 /users

# Pre-register and promote benchmark user to avoid 403s during performance test
BENCH_JWT=$(wget -qO- "http://test-auth:8080/mint?email=bench-user@example.com")
DISTFS_PASSWORD=benchpass distfs -use-pinentry=false -config /tmp/bench-config.json init --new -server http://storage-node-1:8080 -jwt "$BENCH_JWT"
distfs -use-pinentry=false admin-promote bench-user@example.com || echo "bench-user promotion failed"

FAILED=0

run_test "Core CLI E2E" "/bin/test-e2e.sh" || FAILED=1
run_test "FUSE POSIX Compliance" "/bin/test-fuse.sh" || FAILED=1
run_test "Garbage Collection" "/bin/test-gc.sh" || FAILED=1
run_test "Stress Test" "/bin/test-stress.sh" || FAILED=1
run_test "Data Integrity" "/bin/test-integrity.sh" || FAILED=1
run_test "Public Sharing" "/bin/test-public.sh" || FAILED=1
run_test "Group Sharing" "/bin/test-group.sh" || FAILED=1
run_test "Group Quota" "/bin/test-group-quota.sh" || FAILED=1
run_test "KeySync Cloud Backup" "/bin/test-keysync-e2e.sh" || FAILED=1
run_test "Hedged Reads Performance" "/bin/test-hedged-reads.sh" || FAILED=1
run_test "Contact Exchange" "/bin/test-contact-exchange.sh" || FAILED=1
run_test "Dump Inodes Debugging" "/bin/test-dump-inodes.sh" || FAILED=1
run_test "Quota Command" "/bin/test-quota-cmd.sh" || FAILED=1
run_test "Enhanced LS E2E" "/bin/test-ls-e2e.sh" || FAILED=1

echo "" | tee -a $REPORT_FILE
echo "--- PERFORMANCE BENCHMARKS ---" | tee -a $REPORT_FILE
echo "Running System Benchmarks..."
/bin/benchmark.sh >> $REPORT_FILE 2>&1 || FAILED=1

# HA test last because it kills a node
run_test "High Availability Failover" "/bin/test-ha.sh" || FAILED=1

# Final print of the report
echo "--- FINAL SUMMARY ---"
cat $REPORT_FILE

if [ $FAILED -ne 0 ]; then
    echo "One or more tests failed."
    exit 1
fi

echo "ALL E2E TESTS AND BENCHMARKS PASSED"
