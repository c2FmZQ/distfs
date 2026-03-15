#!/bin/sh
set -e
# Unified E2E and Benchmark Runner
REPORT_FILE="/tmp/distfs-e2e-report.txt"
echo "--- DISTFS E2E REPORT ---" > $REPORT_FILE

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

# Function to wait for cluster readiness
wait_for_ready() {
    echo "Waiting for cluster leader..."
    for i in $(seq 1 30); do
        if wget -qO- "http://storage-node-1:8080/v1/health" | grep -q '"is_leader":true'; then
            echo "Cluster leader found."
            return 0
        fi
        sleep 1
    done
    echo "Timed out waiting for cluster leader."
    return 1
}

wait_for_ready || exit 1

# Use a clean temporary directory for this run's configuration
export DISTFS_CONFIG_DIR=$(mktemp -d)
echo "Using config directory: $DISTFS_CONFIG_DIR"

# GLOBAL SETUP: Create Admin
echo "PERFORMING GLOBAL SETUP..."
JWT=$(wget -qO- "http://test-auth:8080/mint?email=admin@example.com")
if ! distfs -disable-doh -use-pinentry=false -config "$DISTFS_CONFIG_DIR/config.json" init --new -server http://storage-node-1:8080 -jwt "$JWT"; then
    echo "GLOBAL SETUP FAILED: Admin initialization failed"
    exit 1
fi

ADMIN_ID=$(distfs -disable-doh -use-pinentry=false -config "$DISTFS_CONFIG_DIR/config.json" whoami)
echo "Global Admin ID: $ADMIN_ID"

# 1. Create a Shared Administrators Group for root management
echo "Creating Administrators group..."
distfs -disable-doh -use-pinentry=false -config "$DISTFS_CONFIG_DIR/config.json" group-create administrators > /tmp/admin-group.txt
ADMIN_GID=$(grep "^ID:" /tmp/admin-group.txt | awk '{print $2}')
echo "Administrators GID: $ADMIN_GID"

echo "Assigning root directory to Administrators group..."
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" chgrp "$ADMIN_GID" /
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" chmod 0775 /

# 2. Provision Users and Workspaces under /users/
echo "Provisioning /users base directory..."
USERS_GROUP_OUT=$(distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" group-create users || true)
USERS_GID=$(echo "$USERS_GROUP_OUT" | grep "ID:" | awk '{print $2}' || echo "")
if [ -z "$USERS_GID" ]; then
    USERS_GID="users" # Fallback if it already existed and we couldn't parse it easily
fi
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" mkdir /users || true
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" chmod 0755 /users || true

provision_user() {
    name=$1
    email=$2
    conf="/tmp/${name}-config.json"
    path="/users/${name}"
    echo "Provisioning ${name} ($email) at ${path}..."
    
    U_JWT=$(wget -qO- "http://test-auth:8080/mint?email=$email")
    U_OUT=$(distfs -disable-doh -use-pinentry=false -config "$conf" init --new -server http://storage-node-1:8080 -jwt "$U_JWT")
    U_ID=$(echo "$U_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
    
    # Provision directory and unlock via Global Admin
    echo "y" | distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" registry-add --unlock --home "$name" "$email"
    
    # Add to users group to allow traversal
    distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" group-add "$USERS_GID" "$name"
}

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
BENCH_OUT=$(distfs -disable-doh -use-pinentry=false -config "/tmp/bench-dir/config.json" init --new -server http://storage-node-1:8080 -jwt "$BENCH_JWT")
BENCH_ID=$(echo "$BENCH_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

# Provision, unlock, and assign to admin group
echo "y" | distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" registry-add --unlock bench-user bench-user@example.com
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" mkdir --owner bench-user /bench-workspace

# Promote and add to Administrators group
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" admin-promote bench-user
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" group-add "$ADMIN_GID" bench-user

# Provision HA directory (world-writable for test flexibility)
echo "Provisioning /ha..."
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" mkdir /ha
distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" chmod 0777 /ha

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

echo "--- WEB UI TESTS ---" | tee -a $REPORT_FILE
echo "Running Playwright E2E..." | tee -a $REPORT_FILE
# Navigate to workspace and run playwright
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
