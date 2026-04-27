#!/bin/sh
# FUSE POSIX Load Test
set -e

. "$(dirname $0)/test-lib.sh"

MOUNT_POINT="/tmp/distfs-fuse-load-mount"
mkdir -p $MOUNT_POINT

cleanup() {
    echo "Cleaning up..."
    fusermount3 -u $MOUNT_POINT || true
    rm -rf $MOUNT_POINT
}
trap cleanup EXIT

echo "--- Starting 15-Minute FUSE POSIX Load Test ---"

wait_for_ready || exit 1

# Use a clean temporary directory for this run's configuration
export DISTFS_CONFIG_DIR=$(mktemp -d)
export DISTFS_PASSWORD="testpassword"

global_setup "$DISTFS_CONFIG_DIR"

echo "Initializing load worker account..."
provision_user "load-worker" "load-worker@example.com"

/bin/distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" admin-user-quota load-worker $((2*1024*1024*1024)) 10000

echo "Mounting DistFS to $MOUNT_POINT..."
/bin/distfs-fuse --config /tmp/load-worker-config.json --server $DISTFS_SERVER_URL --mount $MOUNT_POINT &
FUSE_PID=$!

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

echo "Starting load generator..."
/bin/distfs-fuse-load --mount $MOUNT_POINT --workdir "users/load-worker" --duration 5m --workers 8 --max-total-size 1073741824

echo "FUSE Load Test Complete."
