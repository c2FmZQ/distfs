#!/bin/sh
set -e
# E2E Test for dump-inodes command
export DISTFS_PASSWORD=testpassword

export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"
echo "Waiting for client configuration..."
until [ -f "$DISTFS_CONFIG_DIR/config.json" ]; do sleep 1; done

echo "Dumping inodes via Admin CLI..."
if distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" dump-inodes / > /tmp/dump.log; then

    echo "dump-inodes executed successfully."
else
    echo "FAIL: dump-inodes failed."
    exit 1
fi

echo "Verifying output..."
if grep -q "Inode ID:" /tmp/dump.log; then
    echo "PASS: Output contains expected metadata."
    head -n 20 /tmp/dump.log
else
    echo "FAIL: Output missing expected metadata."
    cat /tmp/dump.log
    exit 1
fi
