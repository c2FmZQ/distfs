#!/bin/sh
set -e
set -e

# DistFS KeySync E2E Test (Docker Compose version)
# This script verifies that a user can push their keys from one config
# and pull them to another using their OIDC identity.

echo "--- Starting KeySync E2E Test ---"

export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"

# Wait for services
sleep 2

SERVER_URL="http://storage-node-1:8080"
AUTH_URL="http://test-auth:8080"
# We'll create two local configs for the same user
CONFIG1="/tmp/keysync-1.json"
CONFIG2="/tmp/keysync-2.json"

# 1. Obtain JWT
echo "Obtaining JWT..."
JWT=$(wget -qO- "$AUTH_URL/mint?email=keysync-user@example.com")
if [ -z "$JWT" ]; then
    echo "Failed to obtain JWT"
    exit 1
fi

# 2. Initialize First Config (New User simulation)
echo "Initializing First Config..."
# Note: user was already provisioned in global setup, but we'll use a new email here
# to avoid conflicts if needed, or just re-init.
# Let's use a unique email for this test.
JWT_SYNC=$(wget -qO- "$AUTH_URL/mint?email=sync-test-unique@example.com")
OUT=$(/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG1" init --new -server "$SERVER_URL" -jwt "$JWT_SYNC")
USER_ID=$(echo "$OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

echo "Admin: Provisioning home directory for $USER_ID..."
/bin/distfs -disable-doh -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" mkdir --owner "$USER_ID" "/users/$USER_ID" || true

# 3. Pull Keys to Config 2 (New Device simulation)
echo "Pulling Keys to Config 2 (New Device simulation)..."
/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG2" init -server "$SERVER_URL" -jwt "$JWT_SYNC"

# 4. Verify Config 2 works
echo "Verifying Config 2 works..."
# Write to user directory
echo "synced" > /tmp/sync.txt
/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG2" put /tmp/sync.txt "/users/$USER_ID/sync.txt"
/bin/distfs -disable-doh -use-pinentry=false -config "$CONFIG2" ls "/users/$USER_ID"

echo "KeySync E2E Test Passed!"
