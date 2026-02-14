#!/bin/sh
set -e

# DistFS KeySync E2E Test (Docker Compose version)
# This script verifies that a user can push their keys from one config
# and pull them to another using their OIDC identity.

echo "--- Starting KeySync E2E Test ---"

# Wait for services
sleep 2

META_URL="http://storage-node-1:8080"
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

# 2. Initialize and Register User
echo "Initializing and Registering User..."
/bin/distfs -config "$CONFIG1" init -meta "$META_URL" -id "keysync-user@example.com"
/bin/distfs -config "$CONFIG1" register -jwt "$JWT"

# 3. Push Keys from Config 1
echo "Pushing Keys from Config 1..."
# Use DISTFS_PASSWORD from environment (set in docker-compose.yml)
/bin/distfs -config "$CONFIG1" keysync push

# 4. Pull Keys to Config 2
echo "Pulling Keys to Config 2..."
# We simulate a new device by only knowing the MetaURL and having a JWT.
/bin/distfs -config "$CONFIG2" keysync pull -meta "$META_URL" -jwt "$JWT"

# 5. Verify Config 2 works
echo "Verifying Config 2 works..."
# Ensure we can list root.
/bin/distfs -config "$CONFIG2" ls / > /dev/null

echo "KeySync E2E Test Passed!"
