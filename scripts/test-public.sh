#!/bin/sh
set -e
# Public Data Sharing Test
set -e

CONFIG1="/tmp/public-user-config.json"
CONFIG2="/tmp/u2-public.json"

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing Reader (user2)..."
JWT2=$(wget -qO- "http://test-auth:8080/mint?email=user2-public@example.com")
distfs -disable-doh -use-pinentry=false -config "$CONFIG2" init --new -server http://storage-node-1:8080 -jwt "$JWT2"

echo "User 1 (Owner): Granting world read to workspace /users/public-user..."
distfs -disable-doh -use-pinentry=false -config "$CONFIG1" chmod 0755 /users/public-user

echo "User 1: Uploading file to public directory..."
echo "anyone can read this" > /tmp/public.txt
distfs -disable-doh -use-pinentry=false -config "$CONFIG1" put /tmp/public.txt /users/public-user/readme.txt
distfs -disable-doh -use-pinentry=false -config "$CONFIG1" chmod 0644 /users/public-user/readme.txt

echo "User 2: Reading public file..."
distfs -disable-doh -use-pinentry=false -config "$CONFIG2" get /users/public-user/readme.txt /tmp/u2-read.txt
if grep -q "anyone can read" /tmp/u2-read.txt; then
    echo "PASS: Public read successful"
else
    echo "FAIL: Public read failed"
    exit 1
fi

echo "PUBLIC SHARING TEST PASSED"
