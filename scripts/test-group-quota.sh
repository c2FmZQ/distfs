#!/bin/sh
# Group Quota E2E Test
set -e

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing Alice..."
JWT_A=$(wget -qO- "http://test-auth:8080/mint?email=alice-quota@example.com")
U1_OUT=$(distfs -use-pinentry=false -config /tmp/alice-quota.json init --new -server http://storage-node-1:8080 -jwt "$JWT_A")
U1_ID=$(echo "$U1_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

echo "Alice: Creating group 'quota-test'..."
G_OUT=$(distfs -use-pinentry=false -config /tmp/alice-quota.json group-create quota-test)
G_ID=$(echo "$G_OUT" | grep "ID:" | cut -d: -f2 | tr -d ' ')
echo "Group ID: $G_ID"

echo "Admin: Creating group-owned directory..."
distfs -use-pinentry=false -config /root/.distfs/config.json mkdir /quota-dir
distfs -use-pinentry=false -config /root/.distfs/config.json chgrp "$G_ID" /quota-dir
distfs -use-pinentry=false -config /root/.distfs/config.json chmod 0770 /quota-dir

echo "Admin: Setting Group Quota (2 Inodes, 1000 Bytes)..."
# Dir + 1 File = 2 Inodes
distfs -use-pinentry=false -config /root/.distfs/config.json admin-group-quota "$G_ID" 1000 2

echo "Alice: Uploading 1st file to group-owned directory..."
echo "hello group" > /tmp/file1.txt
distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file1.txt /quota-dir/file1.txt
echo "PASS: 1st file uploaded to group-owned directory"

echo "Alice: Uploading 2nd file to group-owned directory (should fail: Group Inode Quota)..."
echo "second file" > /tmp/file2.txt
if distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file2.txt /quota-dir/file2.txt 2>/dev/null; then
    echo "FAIL: 2nd file uploaded despite group inode quota"
    exit 1
fi
echo "PASS: 2nd file blocked by group inode quota"

echo "Admin: Increasing Group Quota (3 Inodes, 10 Bytes)..."
# Dir + File1 + File2 = 3 Inodes
distfs -use-pinentry=false -config /root/.distfs/config.json admin-group-quota "$G_ID" 10 3

echo "Alice: Uploading 2nd file to group-owned directory (should fail: Group Storage Quota)..."
if distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file2.txt /quota-dir/file2.txt 2>/dev/null; then
    echo "FAIL: 2nd file uploaded despite group storage quota"
    exit 1
fi
echo "PASS: 2nd file blocked by group storage quota"

echo "Admin: Removing Group Quota (set to 0)..."
distfs -use-pinentry=false -config /root/.distfs/config.json admin-group-quota "$G_ID" 0 0

echo "Admin: Setting Alice's User Quota (2 Inodes)..."
# Alice currently has 0 personal files. file1 is in group-owned dir with group usage.
# Provisioning /alice-dir will consume 1 personal inode.
distfs -use-pinentry=false -config /root/.distfs/config.json admin-user-quota alice-quota@example.com 1000 2

echo "Admin: Provisioning test dir for Alice..."
TEST_DIR="/alice-dir-$(date +%s)"
distfs -use-pinentry=false -config /root/.distfs/config.json mkdir "$TEST_DIR"
distfs -use-pinentry=false -config /root/.distfs/config.json admin-chown -f alice-quota@example.com "$TEST_DIR"
# Wait for directory to be visible to Alice (Raft consistency)
until distfs -use-pinentry=false -config /tmp/alice-quota.json ls "$TEST_DIR" >/dev/null 2>&1; do sleep 0.5; done

echo "Alice: Uploading 2nd file (should succeed - usage 1->2 <= 2)..."
echo "personal file" > /tmp/personal.txt
if ! distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/personal.txt "$TEST_DIR/personal.txt"; then
    echo "FAIL: Alice failed to upload her first personal file"
    exit 1
fi
echo "PASS: Alice uploaded 1st personal file (2/2)"

echo "Alice: Uploading 3rd file (should fail: User Inode Quota fallback)..."
if distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file2.txt "$TEST_DIR/file2.txt" 2>/dev/null; then
    echo "FAIL: 3rd file uploaded despite user inode quota (fallback)"
    exit 1
fi
echo "PASS: 3rd file blocked by user inode quota (fallback)"

echo "GROUP QUOTA TEST PASSED"
