#!/bin/sh
set -e
# OOB Registry & Locked by Default E2E Test
export DISTFS_PASSWORD=testpassword

# Use the admin config from global setup
export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"

echo "Starting Registry E2E..."

# 1. Register a new user (Bob) - Should be locked by default
echo "1. Registering new user (Bob)..."
BOB_DIR="/tmp/bob-reg-dir"
mkdir -p "$BOB_DIR"
BOB_JWT=$(wget -qO- "http://test-auth:8080/mint?email=bob-registry@example.com")
# Bob runs init
BOB_INIT_OUT=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config "$BOB_DIR/config.json" init -server "http://storage-node-1:8080" -jwt "$BOB_JWT" -new)
BOB_ID=$(echo "$BOB_INIT_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

# Wait a moment for Raft consensus
sleep 1

# Bob tries to create a file (should fail with 403 Forbidden)
echo "2. Testing Locked State..."
echo "bob data" > /tmp/bob.txt
if distfs -disable-doh -allow-insecure -use-pinentry=false -config "$BOB_DIR/config.json" put /tmp/bob.txt /users/bob.txt 2>/dev/null; then
    echo "FAIL: Locked user was able to upload a file"
    exit 1
fi
echo "PASS: Locked user rejected"

# 3. Admin provisions Bob via registry-add
echo "3. Admin provisioning Bob via registry..."
# Note: we use echo "y" to pipe the "yes" confirmation to the OOB prompt
echo "y" | distfs -disable-doh -allow-insecure -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" registry-add --unlock --quota 1000000,5000 --home bob-reg "$BOB_ID"

# 4. Verify Bob can now access his home directory
echo "4. Verifying Bob's unlocked access..."
if distfs -disable-doh -allow-insecure -use-pinentry=false -config "$BOB_DIR/config.json" put /tmp/bob.txt /users/bob-reg/mydata.txt; then
    echo "PASS: Bob successfully uploaded to his home directory"
else
    echo "FAIL: Bob could not upload after unlock/provisioning"
    exit 1
fi

# 5. Admin lists registry
distfs -disable-doh -allow-insecure -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" ls -l /registry > /tmp/reg-ls.txt
if grep -q "bob-reg.user" /tmp/reg-ls.txt; then
    echo "PASS: Registry contains bob-reg.user"
else
    echo "FAIL: Registry missing bob-reg.user"
    exit 1
fi

echo "REGISTRY E2E PASSED"
