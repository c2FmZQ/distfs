#!/bin/sh
set -e
# System Audit & Forest Visualization E2E Test
export DISTFS_PASSWORD=testpassword

# Use the admin config from global setup
export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"

echo "Starting System Audit E2E..."

echo "1. Creating complex tree structure..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" mkdir /audit-test
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" mkdir /audit-test/subdir1
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" mkdir /audit-test/subdir2
echo "file1" > /tmp/f1.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" put /tmp/f1.txt /audit-test/subdir1/file1.bin

echo "2. Creating a secondary root tree..."
# Use admin-create-root to initialize a completely separate root ID
# The command will dynamically generate a valid ID based on the user ID and nonce.
# Provide a dummy string, the CLI overrides it and prints the final ID.
OUTPUT=$(distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" admin-create-root --secondary)
SECOND_ROOT=$(echo "$OUTPUT" | grep "Root inode" | awk '{print $3}')
if [ -z "$SECOND_ROOT" ]; then
    echo "FAIL: Could not extract generated secondary root ID"
    exit 1
fi
echo "Generated Secondary Root: $SECOND_ROOT"

distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" --root "$SECOND_ROOT" mkdir /sec-dir

echo "3. Running Admin Audit..."
distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" admin-audit > /tmp/audit.out
cat /tmp/audit.out

echo "4. Verifying output..."

# Verify Forest visualization
if grep -q "Canonical Root" /tmp/audit.out && grep -q "Implicit Root" /tmp/audit.out; then
    echo "PASS: Forest roots identified"
else
    echo "FAIL: Forest roots missing"
    exit 1
fi

# Verify tree structure indicators (ASCII markers)
if grep -q "├──" /tmp/audit.out || grep -q "└──" /tmp/audit.out; then
    echo "PASS: Tree visualization rendered"
else
    echo "FAIL: Tree visualization missing"
    cat /tmp/audit.out
    exit 1
fi

# Verify Registry summaries
if grep -q "ACTOR REGISTRY" /tmp/audit.out && grep -q "User:" /tmp/audit.out; then
    echo "PASS: Actor registry summary present"
else
    echo "FAIL: Actor registry missing"
    exit 1
fi

# Verify Infrastructure
if grep -q "INFRASTRUCTURE" /tmp/audit.out && grep -q "Node:" /tmp/audit.out; then
    echo "PASS: Infrastructure summary present"
else
    echo "FAIL: Infrastructure missing"
    exit 1
fi

# Verify Integrity (should show PASS or explicit FAIL records)
if grep -q "INTEGRITY" /tmp/audit.out; then
    echo "PASS: Integrity section present"
else
    echo "FAIL: Integrity section missing"
    exit 1
fi

echo "SYSTEM AUDIT E2E PASSED"
