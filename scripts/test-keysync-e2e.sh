#!/bin/sh
set -e

# DistFS KeySync E2E Test (Docker Compose version)
# This script verifies that a user can push their keys from one config
# and pull them to another using their OIDC identity.

echo "--- Starting KeySync E2E Test ---"

# Wait for services
sleep 2

SERVER_URL="http://storage-node-1:8080"
AUTH_URL="http://test-auth:8080"
CONFIG1="/tmp/config1.json"
CONFIG2="/tmp/config2.json"

# 1. Obtain JWT
echo "Obtaining JWT..."
JWT=$(wget -qO- "$AUTH_URL/mint?email=keysync-user@example.com")
if [ -z "$JWT" ]; then
    echo "Failed to obtain JWT"
    exit 1
fi

# 2. Initialize New Account (Flow 1: Init + Register + Cloud Backup)
echo "Initializing New Account..."
/bin/distfs -use-pinentry=false -config "$CONFIG1" init --new -server "$SERVER_URL" -jwt "$JWT"

# 3. Pull Keys to Config 2 (Flow 2: Auth + Pull + Decrypt)
echo "Pulling Keys to Config 2 (New Device simulation)..."
/bin/distfs -use-pinentry=false -config "$CONFIG2" init -server "$SERVER_URL" -jwt "$JWT"

# 4. Verify Config 2 works
echo "Verifying Config 2 works..."
# Ensure we can list root.
/bin/distfs -use-pinentry=false -config "$CONFIG2" ls / > /dev/null

echo "KeySync E2E Test Passed!"
