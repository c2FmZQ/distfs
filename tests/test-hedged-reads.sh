#!/bin/sh
set -e
# Hedged Reads & Failover Performance Test
set -e

echo "--- Starting Hedged Reads E2E Test ---"

export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"

# Wait for services
sleep 2

SERVER_URL="http://storage-node-1:8080"
AUTH_URL="http://test-auth:8080"
CONFIG="/tmp/hedge-config.json"

# 1. Obtain JWT and Initialize
echo "Initializing Account..."
JWT=$(wget -qO- "$AUTH_URL/mint?email=hedge-user@example.com")
# We'll use a new identity for this test to ensure clean state
INIT_OUT=$(distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" init --new --server "$SERVER_URL" --jwt "$JWT")
USER_ID=$(echo "$INIT_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

echo "Admin: Anchoring and unlocking $USER_ID..."
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" registry-add --yes --unlock hedge-user "$USER_ID"
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" group-add users "$USER_ID"

# Admin: Provision Home
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" mkdir --owner "$USER_ID" "/users/hedge-$USER_ID" || true

# 2. Write a file
echo "Uploading test file..."
echo "Hedged read test data" > /tmp/hedge.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" put /tmp/hedge.txt "/users/hedge-$USER_ID/hedge-test.txt"

# 3. Verify normal read
echo "Verifying normal read..."
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" get "/users/hedge-$USER_ID/hedge-test.txt" /tmp/hedge-back.txt
grep -q "Hedged read test data" /tmp/hedge-back.txt

# 4. SIMULATE SLOW/DEAD NODE
# We'll use the debug API to kill storage-node-3
echo "Killing storage-node-3 to trigger failover..."
wget -qO- --post-data="" http://storage-node-3:8080/api/debug/suicide || true
sleep 2

# 5. Perform Hedged Read
echo "Performing hedged read (should be fast)..."
start=$(date +%s)
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" get "/users/hedge-$USER_ID/hedge-test.txt" /tmp/hedge-failover.txt
end=$(date +%s)
duration=$((end - start))

echo "Read took ${duration} seconds."

# Verify content
grep -q "Hedged read test data" /tmp/hedge-failover.txt

if [ $duration -gt 5 ]; then
    echo "FAIL: Read took too long ($duration seconds). Hedge logic might not be working."
    exit 1
fi

echo "Hedged Reads E2E Test Passed!"
