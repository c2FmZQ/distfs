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

FAILED=0

run_test "Core CLI E2E" "/bin/test-e2e.sh" || FAILED=1
run_test "FUSE POSIX Compliance" "/bin/test-fuse.sh" || FAILED=1
run_test "Garbage Collection" "/bin/test-gc.sh" || FAILED=1
run_test "Stress Test" "/bin/test-stress.sh" || FAILED=1
run_test "Data Integrity" "/bin/test-integrity.sh" || FAILED=1
run_test "Public Sharing" "/bin/test-public.sh" || FAILED=1
run_test "World Writable" "/bin/test-writable.sh" || FAILED=1
run_test "Group Sharing" "/bin/test-group.sh" || FAILED=1
run_test "KeySync Cloud Backup" "/bin/test-keysync-e2e.sh" || FAILED=1
run_test "Hedged Reads Performance" "/bin/test-hedged-reads.sh" || FAILED=1

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
