#!/bin/sh
# World-Writable (Collaborative) Sharing Test
set -e

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing user1 (Owner)..."
JWT1=$(wget -qO- "http://test-auth:8080/mint?email=user1-writable@example.com")
distfs -use-pinentry=false -config /tmp/u1-writable.json init --new -meta http://storage-node-1:8080 -jwt "$JWT1"

echo "Initializing user2 (Collaborator)..."
JWT2=$(wget -qO- "http://test-auth:8080/mint?email=user2-writable@example.com")
distfs -use-pinentry=false -config /tmp/u2-writable.json init --new -meta http://storage-node-1:8080 -jwt "$JWT2"

echo "User 1: Creating world-writable directory..."
distfs -use-pinentry=false -config /tmp/u1-writable.json mkdir /shared
distfs -use-pinentry=false -config /tmp/u1-writable.json chmod 0777 /shared

echo "User 2: Creating a file in shared directory..."
echo "user2 data" > /tmp/u2.txt
distfs -use-pinentry=false -config /tmp/u2-writable.json put /tmp/u2.txt /shared/user2-file.txt
distfs -use-pinentry=false -config /tmp/u2-writable.json chmod 0644 /shared/user2-file.txt

echo "User 1: Verifying file from user2..."
distfs -use-pinentry=false -config /tmp/u1-writable.json get /shared/user2-file.txt /tmp/u1-back.txt
if grep -q "user2 data" /tmp/u1-back.txt; then
    echo "PASS: user1 can read user2's file in shared dir"
else
    echo "FAIL: user1 could not read user2's file"
    exit 1
fi

echo "User 1: Creating world-writable file..."
echo "initial data" > /tmp/shared-file.txt
distfs -use-pinentry=false -config /tmp/u1-writable.json put /tmp/shared-file.txt /shared/shared-file.txt
distfs -use-pinentry=false -config /tmp/u1-writable.json chmod 0666 /shared/shared-file.txt

echo "User 2: Overwriting shared file..."
echo "overwritten by user2" > /tmp/u2-overwrite.txt
distfs -use-pinentry=false -config /tmp/u2-writable.json put /tmp/u2-overwrite.txt /shared/shared-file.txt

echo "User 1: Verifying overwrite..."
distfs -use-pinentry=false -config /tmp/u1-writable.json get /shared/shared-file.txt /tmp/u1-overwrite-back.txt
if grep -q "overwritten by user2" /tmp/u1-overwrite-back.txt; then
    echo "PASS: user2 successfully overwrote user1's world-writable file"
else
    echo "FAIL: user2 overwrite not found"
    exit 1
fi

echo "WORLD WRITABLE TEST PASSED"
