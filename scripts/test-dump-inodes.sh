#!/bin/sh
# E2E Test for dump-inodes command
export DISTFS_PASSWORD=testpassword

echo "Waiting for client configuration..."
until [ -f /root/.distfs/config.json ]; do sleep 1; done

echo "Running dump-inodes on root..."
if distfs -use-pinentry=false -config /root/.distfs/config.json dump-inodes / > /tmp/dump.log; then
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
