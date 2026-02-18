#!/bin/sh
# World-Readable (Public) Sharing Test
set -e

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing Owner (user1)..."
JWT1=$(wget -qO- "http://test-auth:8080/mint?email=user1-public@example.com")
distfs -use-pinentry=false -config /tmp/u1-public.json init --new -server http://storage-node-1:8080 -jwt "$JWT1"

echo "Initializing Reader (user2)..."
JWT2=$(wget -qO- "http://test-auth:8080/mint?email=user2-public@example.com")
distfs -use-pinentry=false -config /tmp/u2-public.json init --new -server http://storage-node-1:8080 -jwt "$JWT2"

echo "Admin: Creating public test dir..."
distfs -use-pinentry=false mkdir /public
sleep 2

echo "Admin: Chowning to user1..."
echo "y" | distfs -use-pinentry=false -admin admin-chown user1-public@example.com /public

echo "User 1: Making directory public (chmod 0755)..."
distfs -use-pinentry=false -config /tmp/u1-public.json chmod 0755 /public

echo "User 1: Uploading private file..."
echo "secret message" > /tmp/secret.txt
distfs -use-pinentry=false -config /tmp/u1-public.json put /tmp/secret.txt /public/test.txt

echo "User 2: Attempting to read (should fail initially)..."
if distfs -use-pinentry=false -config /tmp/u2-public.json get /public/test.txt /tmp/fail.txt 2>/dev/null; then
    echo "FAIL: User 2 read private file"
    exit 1
else
    echo "PASS: Initial read blocked"
fi

echo "User 1: Making file public (chmod 0644)..."
distfs -use-pinentry=false -config /tmp/u1-public.json chmod 0644 /public/test.txt

echo "User 2: Attempting to read public file..."
distfs -use-pinentry=false -config /tmp/u2-public.json get /public/test.txt /tmp/success.txt
if grep -q "secret message" /tmp/success.txt; then
    echo "PASS: World-Readable sharing successful"
else
    echo "FAIL: User 2 could not read public file"
    exit 1
fi

echo "User 1: Making file private again (chmod 0600)..."
distfs -use-pinentry=false -config /tmp/u1-public.json chmod 0600 /public/test.txt

echo "User 2: Attempting to read (should fail again)..."
if distfs -use-pinentry=false -config /tmp/u2-public.json get /public/test.txt /tmp/fail2.txt 2>/dev/null; then
    echo "FAIL: User 2 read revoked public file"
    exit 1
else
    echo "PASS: Revocation successful"
fi

echo "WORLD READABLE TEST PASSED"
