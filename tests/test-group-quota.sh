#!/bin/sh
set -e
# Group Quota E2E Test
set -e

CONFIG="/tmp/quota-user-config.json"

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

# User Alice already provisioned by test-all-e2e.sh at /users/quota-user
echo "Alice: Creating group 'quota-test' with independent quota enabled..."
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" group-create --quota --owner quota-user quota-test > /tmp/group-out.txt
G_ID=$(grep "^ID:" /tmp/group-out.txt | awk '{print $2}')

export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"

echo "Alice: Setting up group-owned directory in workspace..."
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" mkdir /users/quota-user/group-dir
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" chgrp "$G_ID" /users/quota-user/group-dir
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" chmod 0770 /users/quota-user/group-dir

echo "Alice: Uploading 1st file to group-owned directory..."
echo "hello world" > /tmp/file1.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" put /tmp/file1.txt /users/quota-user/group-dir/file1.txt
echo "PASS: 1st file uploaded to group-owned directory"

echo "Admin: Setting Group Inode Quota (2 Inodes)..."
# Current Group usage: 1 (group-dir) + 1 (file1.txt) = 2.
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" admin-group-quota "$G_ID" 1000 2

echo "Alice: Uploading 2nd file to group-owned directory (should fail: Group Inode Quota 2+1 > 2)..."
echo "overflow" > /tmp/file2.txt
if distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" put /tmp/file2.txt /users/quota-user/group-dir/file2.txt 2>/dev/null; then
    echo "FAIL: 2nd file uploaded despite group inode quota"
    exit 1
fi
echo "PASS: 2nd file blocked by group inode quota"

echo "Admin: Increasing Group Inode Quota (3)..."
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" admin-group-quota "$G_ID" 10 3

echo "Alice: Uploading 2nd file (should fail: Group STORAGE Quota 11+8 > 10)..."
if distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" put /tmp/file2.txt /users/quota-user/group-dir/file2.txt 2>/dev/null; then
    echo "FAIL: 2nd file uploaded despite group storage quota"
    exit 1
fi
echo "PASS: 2nd file blocked by group storage quota"

echo "Admin: Setting Alice's User Quota (2 Inodes)..."
# Get Alice's UserID. Assuming the config is at /tmp/quota-user-config.json
ALICE_ID=$(distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config /tmp/quota-user-config.json whoami)
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --admin --config "$DISTFS_CONFIG_DIR/config.json" admin-user-quota "$ALICE_ID" 1000 2

echo "Alice: Uploading 2nd file to personal space (should succeed - usage 1->2 <= 2)..."
# Alice currently has 1 personal inode (/users/quota-user)
echo "personal file" > /tmp/personal.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" put /tmp/personal.txt /users/quota-user/personal.txt
echo "PASS: Alice uploaded 1st personal file (2/2)"

echo "Alice: Uploading 3rd file (should fail: User Inode Quota 2+1 > 2)..."
if distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" put /tmp/file2.txt /users/quota-user/personal2.txt 2>/dev/null; then
    echo "FAIL: 3rd file uploaded despite user inode quota"
    exit 1
fi
echo "PASS: 3rd file blocked by user inode quota"

echo "GROUP QUOTA TEST PASSED"
