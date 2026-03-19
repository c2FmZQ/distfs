#!/bin/sh
set -e
# FUSE POSIX Load Test
set -e

MOUNT_POINT="/tmp/distfs-fuse-load-mount"
mkdir -p $MOUNT_POINT

cleanup() {
    echo "Cleaning up..."
    fusermount3 -u $MOUNT_POINT || true
    rm -rf $MOUNT_POINT
}
trap cleanup EXIT

echo "--- Starting 15-Minute FUSE POSIX Load Test ---"

# 1. Initialize identity
# We use a distinct admin config to join nodes
ADMIN_CONF="/tmp/fuse-load-admin.json"
LOAD_CONF="/tmp/fuse-load-config.json"
rm -f $ADMIN_CONF $LOAD_CONF

AUTH_URL="http://test-auth:8080"
SERVER_URL="http://storage-node-1:8080"

# Wait for auth server
echo "Waiting for test-auth..."
until wget -qO- "$AUTH_URL/mint?email=admin@example.com" > /dev/null 2>&1; do
    sleep 1
done
ADMIN_JWT=$(wget -qO- "$AUTH_URL/mint?email=admin@example.com")
LOAD_JWT=$(wget -qO- "$AUTH_URL/mint?email=load-worker@example.com")

export DISTFS_PASSWORD="loadpass"

# Wait for storage node leader
echo "Waiting for storage-node-1..."
until wget -qO- "$SERVER_URL/v1/meta/key" > /dev/null 2>&1; do
    sleep 1
done
echo "Server ready."

# 1.1 First user registered becomes admin automatically
echo "Initializing admin account..."
ADMIN_INIT_OUT=$(/bin/distfs -disable-doh -config "$ADMIN_CONF" init --new -server "$SERVER_URL" -jwt "$ADMIN_JWT")
ADMIN_ID=$(echo "$ADMIN_INIT_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
echo "Admin ID: $ADMIN_ID"

# Add admin to registry so they can perform admin tasks
/bin/distfs -disable-doh -config "$ADMIN_CONF" -admin registry-add --yes --home --unlock admin "$ADMIN_ID"

# Promote to full cluster admin
/bin/distfs -disable-doh -config "$ADMIN_CONF" -admin admin-promote admin

# Give cluster a moment to settle
sleep 5
# 1.2 Join secondary nodes
echo "Joining secondary nodes to cluster..."
for i in $(seq 1 10); do
    echo "Join attempt $i..."
    # Join node-2
    /bin/distfs -disable-doh -admin -config "$ADMIN_CONF" admin-join https://storage-node-2:9090 supersecret || echo "Join node-2 request failed"
    # Join node-3
    /bin/distfs -disable-doh -admin -config "$ADMIN_CONF" admin-join https://storage-node-3:9090 supersecret || echo "Join node-3 request failed"
    # We check if nodes are active. Node 1 is already there. We need 2 more.
    ACTIVE_COUNT=$(wget -qO- --header="X-Raft-Secret: supersecret" "$SERVER_URL/v1/node" 2>/dev/null | grep -o '"status":"active"' | wc -l)
    if [ "$ACTIVE_COUNT" -ge 3 ]; then
        echo "All 3 nodes joined and active."
        break
    fi
    sleep 5
done

if [ $(wget -qO- --header="X-Raft-Secret: supersecret" "$SERVER_URL/v1/node" 2>/dev/null | grep -o '"status":"active"' | wc -l) -lt 3 ]; then
    echo "FAILED: Cluster failed to reach 3 active nodes."
    wget -qO- --header="X-Raft-Secret: supersecret" "$SERVER_URL/v1/node"
    exit 1
fi

# 1.3 Initialize load worker account
echo "Initializing load worker account..."
LOAD_INIT_OUT=$(/bin/distfs -disable-doh -config "$LOAD_CONF" init --new -server "$SERVER_URL" -jwt "$LOAD_JWT")
LOAD_ID=$(echo "$LOAD_INIT_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
echo "Load Worker ID: $LOAD_ID"

# Register and provision load worker
/bin/distfs -disable-doh -config "$ADMIN_CONF" -admin registry-add --yes --unlock --home --quota 2000000000,50000 load-worker "$LOAD_ID"

# 2. Mount
echo "Mounting DistFS to $MOUNT_POINT..."
/bin/distfs-fuse --config "$LOAD_CONF" --mount $MOUNT_POINT &
FUSE_PID=$!

# Wait for mount
MAX_RETRIES=10
for i in $(seq 1 $MAX_RETRIES); do
    if mountpoint -q $MOUNT_POINT; then
        echo "Mounted successfully."
        break
    fi
    if [ $i -eq $MAX_RETRIES ]; then
        echo "Failed to mount after $MAX_RETRIES attempts."
        exit 1
    fi
    sleep 1
done

# 3. Run Load Tester (15 minutes = 900s)
echo "Starting load generator..."
/bin/distfs-fuse-load -mount $MOUNT_POINT -workdir "users/load-worker" -duration 5m -workers 8 -max-total-size 1073741824

echo "FUSE Load Test Complete."
