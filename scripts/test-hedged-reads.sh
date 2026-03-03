#!/bin/sh
set -e
# Hedged Reads & Failover Performance Test
set -e

echo "--- Starting Hedged Reads E2E Test ---"

# Wait for services
sleep 2

SERVER_URL="http://storage-node-1:8080"
AUTH_URL="http://test-auth:8080"
CONFIG="/tmp/hedge-config.json"

# 1. Obtain JWT and Initialize
echo "Initializing Account..."
JWT=$(wget -qO- "$AUTH_URL/mint?email=hedge-user@example.com")
OUT=$(/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG" init --new -server "$SERVER_URL" -jwt "$JWT")
echo "$OUT"
USER_ID=$(echo "$OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

# Provision User Home Directory via Admin
echo "Admin: Provisioning home directory for $USER_ID..."
/bin/distfs -disable-doh -use-pinentry=false -config /root/.distfs/config.json mkdir "/users/$USER_ID" || true
sleep 2
echo "y" | /bin/distfs -disable-doh -use-pinentry=false -admin -config /root/.distfs/config.json admin-chown "$USER_ID" "/users/$USER_ID"

# 2. Write a file
echo "Uploading test file..."
echo "Hedged read test data" > /tmp/hedge.txt
/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG" put /tmp/hedge.txt "/users/$USER_ID/hedge-test.txt"

# 3. Verify normal read
echo "Verifying normal read..."
/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG" get "/users/$USER_ID/hedge-test.txt" /tmp/hedge-back.txt
grep -q "Hedged read test data" /tmp/hedge-back.txt

# 4. SIMULATE SLOW/DEAD NODE
# We'll use the debug API to kill storage-node-3
echo "Killing storage-node-3 to trigger failover..."
wget -qO- --post-data="" http://storage-node-3:8080/api/debug/suicide || true
sleep 2

# 5. Perform Hedged Read
# This should succeed quickly because of the 1s staggered start.
echo "Performing hedged read (should be fast)..."
start=$(date +%s)
/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG" get "/users/$USER_ID/hedge-test.txt" /tmp/hedge-failover.txt
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
