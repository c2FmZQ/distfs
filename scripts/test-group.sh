#!/bin/sh
set -e
# Group Sharing & Collaboration Test
set -e

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing user1 (Group Owner)..."
JWT1=$(wget -qO- "http://test-auth:8080/mint?email=user1-group@example.com")
U1_OUT=$(distfs -use-pinentry=false -config /tmp/u1-group.json init --new -server http://storage-node-1:8080 -jwt "$JWT1")
echo "$U1_OUT"
U1_ID=$(echo "$U1_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
echo "User 1 ID: $U1_ID"

echo "Initializing user2 (Group Member)..."
JWT2=$(wget -qO- "http://test-auth:8080/mint?email=user2-group@example.com")
U2_OUT=$(distfs -use-pinentry=false -config /tmp/u2-group.json init --new -server http://storage-node-1:8080 -jwt "$JWT2")
echo "$U2_OUT"
U2_ID=$(echo "$U2_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
echo "User 2 ID: $U2_ID"

echo "Initializing user3 (Non-Member)..."
JWT3=$(wget -qO- "http://test-auth:8080/mint?email=user3-group@example.com")
U3_OUT=$(distfs -use-pinentry=false -config /tmp/u3-group.json init --new -server http://storage-node-1:8080 -jwt "$JWT3")
echo "$U3_OUT"
U3_ID=$(echo "$U3_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
echo "User 3 ID: $U3_ID"

echo "User 1: Creating group 'project-x'..."
G1_OUT=$(distfs -use-pinentry=false -config /tmp/u1-group.json group-create project-x)
echo "$G1_OUT"
G1_ID=$(echo "$G1_OUT" | grep "ID:" | cut -d: -f2 | tr -d ' ')
echo "Group project-x ID: $G1_ID"
sleep 2

echo "User 1: Adding user2 to group..."
distfs -use-pinentry=false -config /tmp/u1-group.json group-add "$G1_ID" "$U2_ID"

echo "Admin: Creating directory and assigning to user1..."
distfs -use-pinentry=false -config /root/.distfs/config.json mkdir /group-shared
sleep 2
echo "y" | distfs -use-pinentry=false -admin -config /root/.distfs/config.json admin-chown "$U1_ID" /group-shared

echo "User 1: Assigning directory to group..."
distfs -use-pinentry=false -config /tmp/u1-group.json chgrp "$G1_ID" /group-shared
distfs -use-pinentry=false -config /tmp/u1-group.json chmod 0770 /group-shared

echo "User 1: Uploading file to group-shared..."
echo "top secret project info" > /tmp/project.txt
distfs -use-pinentry=false -config /tmp/u1-group.json put /tmp/project.txt /group-shared/plan.txt
distfs -use-pinentry=false -config /tmp/u1-group.json chmod 0660 /group-shared/plan.txt

echo "User 2 (Member): Attempting to read file..."
distfs -use-pinentry=false -config /tmp/u2-group.json get /group-shared/plan.txt /tmp/u2-plan.txt
if grep -q "top secret" /tmp/u2-plan.txt; then
    echo "PASS: Member can read group file"
else
    echo "FAIL: Member could not read group file"
    exit 1
fi

echo "User 3 (Non-Member): Attempting to read file (should fail)..."
if distfs -use-pinentry=false -config /tmp/u3-group.json get /group-shared/plan.txt /tmp/u3-fail.txt 2>/dev/null; then
    echo "FAIL: Non-member read group file"
    exit 1
else
    echo "PASS: Non-member blocked from group file"
fi

echo "User 2 (Member): Attempting to write (overwrite)..."
echo "updated by user2" > /tmp/u2-update.txt
distfs -use-pinentry=false -config /tmp/u2-group.json put /tmp/u2-update.txt /group-shared/plan.txt

echo "User 1 (Owner): Verifying member's update..."
distfs -use-pinentry=false -config /tmp/u1-group.json get /group-shared/plan.txt /tmp/u1-verify.txt
if grep -q "updated by user2" /tmp/u1-verify.txt; then
    echo "PASS: Member can write to group-writable file"
else
    echo "FAIL: Member update not found"
    exit 1
fi

echo "User 2 (Member): Verifying group-list..."
if distfs -use-pinentry=false -config /tmp/u2-group.json group-list | grep -q "project-x"; then
    echo "PASS: Group listed in user2's memberships"
else
    echo "FAIL: Group project-x not found in user2's list"
    exit 1
fi

echo "User 1 (Owner): Removing user2 from group..."
distfs -use-pinentry=false -config /tmp/u1-group.json group-remove "$G1_ID" "$U2_ID"

echo "User 2 (Ex-Member): Verifying group-list after removal..."
if distfs -use-pinentry=false -config /tmp/u2-group.json group-list | grep -q "project-x"; then
    echo "FAIL: Group project-x still found in user2's list after removal"
    exit 1
else
    echo "PASS: Group project-x removed from user2's list"
fi

echo "User 2 (Ex-Member): Attempting to read file (should fail)..."
if distfs -use-pinentry=false -config /tmp/u2-group.json get /group-shared/plan.txt /tmp/u2-fail.txt 2>/dev/null; then
    echo "FAIL: Ex-member could still read group file"
    exit 1
else
    echo "PASS: Ex-member blocked from group file"
fi

echo "GROUP SHARING TEST PASSED"
