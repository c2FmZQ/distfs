#!/bin/sh
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
rm -f /tmp/fuse-load-config.json
AUTH_URL="http://test-auth:8080"
SERVER_URL="http://storage-node-1:8080"
JWT=$(wget -qO- "$AUTH_URL/mint?email=fuse-load@example.com")

export DISTFS_PASSWORD="loadpass"
/bin/distfs init --server "$SERVER_URL" --jwt "$JWT" --config /tmp/fuse-load-config.json

# 2. Mount
echo "Mounting DistFS to $MOUNT_POINT..."
/bin/distfs-fuse --config /tmp/fuse-load-config.json --mount $MOUNT_POINT &
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
/bin/distfs-fuse-load -mount $MOUNT_POINT -duration 15m -workers 4 -max-total-size 1073741824

echo "FUSE Load Test Complete."
