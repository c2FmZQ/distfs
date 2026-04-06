#!/bin/sh
set -e
# Group Sharing & Collaboration Test
set -e

CONFIG1="/tmp/group-user-config.json"
CONFIG2="/tmp/u2-group.json"
CONFIG3="/tmp/u3-group.json"

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing user2 (Group Member)..."
JWT2=$(wget -qO- "http://test-auth:8080/mint?email=user2-group@example.com")
INIT_OUT2=$(distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG2" init --new --server http://storage-node-1:8080 --jwt "$JWT2")
U2_ID=$(echo "$INIT_OUT2" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" registry-add --yes --unlock user2-group "$U2_ID"
distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" group-add users "$U2_ID"

echo "Initializing user3 (Non-Member)..."
JWT3=$(wget -qO- "http://test-auth:8080/mint?email=user3-group@example.com")
INIT_OUT3=$(distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG3" init --new --server http://storage-node-1:8080 --jwt "$JWT3")
U3_ID=$(echo "$INIT_OUT3" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" registry-add --yes --unlock user3-group "$U3_ID"
distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" group-add users "$U3_ID"

echo "User 1: Creating group 'project-x'..."
distfs --disable-doh --allow-insecure --use-pinentry=false --admin --config "$DISTFS_CONFIG_DIR/config.json" group-create --owner group-user project-x > /tmp/group-out.txt
G1_ID=$(grep "^ID:" /tmp/group-out.txt | awk '{print $2}')
echo "Group project-x ID: $G1_ID"

echo "User 1: Adding user2 to group..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" group-add "$G1_ID" "$U2_ID"

echo "User 1: Creating shared directory in workspace /users/group-user/shared..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" chmod 0755 /users/group-user
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" mkdir /users/group-user/shared
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" chgrp "$G1_ID" /users/group-user/shared
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" chmod 0770 /users/group-user/shared

echo "User 1: Uploading file to group-shared..."
echo "shared plan" > /tmp/project.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" put /tmp/project.txt /users/group-user/shared/plan.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" chmod 0660 /users/group-user/shared/plan.txt

echo "User 2 (Member): Attempting to read file..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG2" get /users/group-user/shared/plan.txt /tmp/u2-plan.txt
echo "PASS: Member can read group file"

echo "User 3 (Non-Member): Attempting to read file (should fail)..."
if distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG3" get /users/group-user/shared/plan.txt /tmp/u3-fail.txt 2>/dev/null; then
    echo "FAIL: Non-member could read group file"
    exit 1
else
    echo "PASS: Non-member blocked from group file"
fi

echo "User 2 (Member): Attempting to write (overwrite)..."
echo "u2 update" > /tmp/u2-update.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG2" put -f /tmp/u2-update.txt /users/group-user/shared/plan.txt

echo "User 1 (Owner): Verifying member's update..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG1" get /users/group-user/shared/plan.txt /tmp/u1-verify.txt
if grep -q "u2 update" /tmp/u1-verify.txt; then
    echo "PASS: Member can write to group-writable file"
else
    echo "FAIL: Member update not seen"
    exit 1
fi

echo "GROUP SHARING TEST PASSED"
