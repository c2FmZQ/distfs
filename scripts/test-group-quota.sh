#!/bin/sh
set -e
# Group Quota E2E Test
set -e

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing Alice..."
ALICE_JWT=$(wget -qO- "http://test-auth:8080/mint?email=alice-quota@example.com")
distfs -use-pinentry=false -config /tmp/alice-quota.json init --new --jwt "$ALICE_JWT" --server http://storage-node-1:8080

echo "Alice: Creating group 'quota-test' with independent quota enabled..."
# Enabling --quota makes this group the primary debtor for its files.
distfs -use-pinentry=false -config /tmp/alice-quota.json group-create --quota quota-test > /tmp/group-out.txt
cat /tmp/group-out.txt
G_ID=$(grep "^ID:" /tmp/group-out.txt | awk '{print $2}')
if [ -z "$G_ID" ]; then
    echo "FAIL: Failed to extract Group ID"
    cat /tmp/group-out.txt
    exit 1
fi
echo "Extracted Group ID: $G_ID"

echo "Admin: Creating group-owned directory..."
distfs -use-pinentry=false -config /root/.distfs/config.json mkdir /quota-dir
distfs -use-pinentry=false -config /root/.distfs/config.json admin-chown -f ":$G_ID" /quota-dir
distfs -use-pinentry=false -config /root/.distfs/config.json chmod 0770 /quota-dir
# Wait for directory to be visible to Alice
echo "Waiting for /quota-dir to be visible to Alice..."
MAX_WAIT=20
COUNT=0
until distfs -use-pinentry=false -config /tmp/alice-quota.json ls /quota-dir >/dev/null 2>/tmp/ls-err.txt; do 
    sleep 1
    COUNT=$((COUNT + 1))
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo "FAIL: /quota-dir never became visible to Alice"
        echo "Last error: $(cat /tmp/ls-err.txt)"
        distfs -use-pinentry=false -config /tmp/alice-quota.json ls /
        exit 1
    fi
done
echo "/quota-dir is now visible."

echo "Alice: Uploading 1st file to group-owned directory (should succeed, usage 0->1)..."
echo "hello world" > /tmp/file1.txt
if ! timeout 30s distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file1.txt /quota-dir/file1.txt; then
    echo "FAIL: Alice failed to upload her first group file (or timed out)"
    exit 1
fi
echo "PASS: 1st file uploaded to group-owned directory"

echo "Admin: Setting Group Inode Quota (2 Inodes)..."
# Current Group usage: 1 (/quota-dir) + 1 (file1.txt) = 2.
distfs -use-pinentry=false -config /root/.distfs/config.json admin-group-quota "$G_ID" 1000 2

echo "Alice: Uploading 2nd file to group-owned directory (should fail: Group Inode Quota 2+1 > 2)..."
echo "overflow" > /tmp/file2.txt
if distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file2.txt /quota-dir/file2.txt 2>/dev/null; then
    echo "FAIL: 2nd file uploaded despite group inode quota"
    exit 1
fi
echo "PASS: 2nd file blocked by group inode quota"

echo "Admin: Increasing Group Inode Quota (3)..."
distfs -use-pinentry=false -config /root/.distfs/config.json admin-group-quota "$G_ID" 10 3

echo "Alice: Uploading 2nd file (should fail: Group STORAGE Quota 11+8 > 10)..."
if distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file2.txt /quota-dir/file2.txt 2>/dev/null; then
    echo "FAIL: 2nd file uploaded despite group storage quota"
    exit 1
fi
echo "PASS: 2nd file blocked by group storage quota"

echo "Admin: Setting Alice's User Quota (2 Inodes)..."
# Alice currently has 0 personal files. Her group-owned files don't count because group has --quota enabled.
# Provisioning /alice-dir will consume 1 personal inode.
distfs -use-pinentry=false -config /root/.distfs/config.json admin-user-quota alice-quota@example.com 1000 2

echo "Admin: Provisioning test dir for Alice..."
TEST_DIR="/alice-dir-$(date +%s)"
distfs -use-pinentry=false -config /root/.distfs/config.json mkdir "$TEST_DIR"
distfs -use-pinentry=false -config /root/.distfs/config.json admin-chown -f alice-quota@example.com "$TEST_DIR"
# Wait for directory to be visible to Alice
until distfs -use-pinentry=false -config /tmp/alice-quota.json ls "$TEST_DIR" >/dev/null 2>&1; do sleep 0.5; done

echo "Alice: Uploading 2nd file (should succeed - usage 1->2 <= 2)..."
echo "personal file" > /tmp/personal.txt
if ! distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/personal.txt "$TEST_DIR/personal.txt"; then
    echo "FAIL: Alice failed to upload her first personal file"
    exit 1
fi
echo "PASS: Alice uploaded 1st personal file (2/2)"

echo "Alice: Uploading 3rd file (should fail: User Inode Quota 2+1 > 2)..."
if distfs -use-pinentry=false -config /tmp/alice-quota.json put /tmp/file2.txt "$TEST_DIR/file2.txt" 2>/dev/null; then
    echo "FAIL: 3rd file uploaded despite user inode quota"
    exit 1
fi
echo "PASS: 3rd file blocked by user inode quota"

echo "GROUP QUOTA TEST PASSED"
