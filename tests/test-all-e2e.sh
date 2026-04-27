#!/bin/sh
set -e
# Unified E2E and Benchmark Runner
REPORT_FILE="/tmp/distfs-e2e-report.txt"
echo "--- DISTFS E2E REPORT ---" > $REPORT_FILE

. "$(dirname $0)/test-lib.sh"

run_test() {
    name=$1
    script=$2
    echo "Running $name..."
    # Run in subshell, propagate config dir
    ( export DISTFS_CONFIG_DIR=$DISTFS_CONFIG_DIR; $script )
    if [ $? -eq 0 ]; then
        echo "[PASS] $name" | tee -a $REPORT_FILE
        return 0
    else
        echo "[FAIL] $name" | tee -a $REPORT_FILE
        return 1
    fi
}

echo "Starting Unified E2E Test Suite..."

wait_for_ready || exit 1

# Use a clean temporary directory for this run's configuration
export DISTFS_CONFIG_DIR=$(mktemp -d)
export DISTFS_PASSWORD="testpassword"
echo "Using config directory: $DISTFS_CONFIG_DIR"

global_setup "$DISTFS_CONFIG_DIR"

# 1. Shared Administrators Group for root management
# The 'admin' group already exists from admin-create-root, but we create an 'administrators' one
# for the test to verify that anchoring works for newly created groups.
echo "Creating Administrators group..."
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" group-create administrators > /tmp/admin-group.txt
ADMIN_GID=$(grep "^ID:" /tmp/admin-group.txt | awk '{print $2}')
echo "Administrators GID: $ADMIN_GID"

provision_user "fuse-user" "fuse-user@example.com"
provision_user "gc-user" "gc-user@example.com"
provision_user "stress-user" "stress-user@example.com"
provision_user "integrity-user" "integrity-user@example.com"
provision_user "public-user" "public-user@example.com"
provision_user "group-user" "group-user@example.com"
provision_user "quota-user" "quota-user@example.com"
provision_user "ls-user" "ls-user@example.com"

# Pre-register benchmark user and add to Administrators
echo "Provisioning benchmark workspace..."
BENCH_JWT=$(wget -qO- "http://test-auth:8080/mint?email=bench-user@example.com")
# Benchmark uses a persistent config at /tmp/bench-dir/config.json
mkdir -p /tmp/bench-dir
BENCH_OUT=$(distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "/tmp/bench-dir/config.json" init --new --server http://storage-node-1:8080 --jwt "$BENCH_JWT")
BENCH_ID=$(echo "$BENCH_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

# Provision, unlock, and assign to admin group
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" registry-add --yes --unlock bench-user "$BENCH_ID"
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" mkdir --owner bench-user /bench-workspace

# Promote and add to Administrators group
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" admin-promote bench-user
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" group-add "$ADMIN_GID" bench-user
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" group-add "users" bench-user

# Provision HA directory (world-writable for test flexibility)
echo "Provisioning /ha..."
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" mkdir /ha
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" chmod 0777 /ha

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
run_test "System Audit & Integrity" "/bin/test-audit.sh" || FAILED=1
run_test "OOB Identity & Registry" "/bin/test-registry.sh" || FAILED=1
run_test "FileUtils CLI Expansion" "/bin/test-fileutils.sh" || FAILED=1

echo "--- WEB UI TESTS ---" | tee -a $REPORT_FILE
echo "Running Playwright E2E..." | tee -a $REPORT_FILE
# Navigate to workspace and run playwright
export CAPTURE_SCREENSHOTS="${CAPTURE_SCREENSHOTS:-}"
cd /distfs && npx playwright test >> $REPORT_FILE 2>&1 || FAILED=1

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
