#!/bin/sh
set -e
# Contact Exchange E2E Test
set -e

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Initializing Alice (Owner)..."
JWT_A=$(wget -qO- "http://test-auth:8080/mint?email=alice-contact@example.com")
distfs -use-pinentry=false -config /tmp/alice.json init --new -server http://storage-node-1:8080 -jwt "$JWT_A"

echo "Initializing Bob (Member)..."
JWT_B=$(wget -qO- "http://test-auth:8080/mint?email=bob-contact@example.com")
distfs -use-pinentry=false -config /tmp/bob.json init --new -server http://storage-node-1:8080 -jwt "$JWT_B"

echo "Bob: Generating contact info..."
BOB_CONTACT=$(distfs -use-pinentry=false -config /tmp/bob.json contact-info | grep "distfs-contact:v1:")
echo "Bob's contact string: $BOB_CONTACT"

echo "Alice: Creating group 'exchange-test'..."
G_OUT=$(distfs -use-pinentry=false -config /tmp/alice.json group-create exchange-test)
G_ID=$(echo "$G_OUT" | grep "^ID:" | awk '{print $2}')
echo "Group ID: $G_ID"

echo "Alice: Adding Bob via contact string (with -f)..."
distfs -use-pinentry=false -config /tmp/alice.json group-add -f "$G_ID" "$BOB_CONTACT" "Bob (OOB)"

echo "Alice: Verifying Bob is in member list..."
if distfs -use-pinentry=false -config /tmp/alice.json group-members "$G_ID" | grep -q "Bob (OOB)"; then
    echo "PASS: Bob added successfully via contact string"
else
    echo "FAIL: Bob not found in member list"
    exit 1
fi

echo "Initializing Carol..."
JWT_C=$(wget -qO- "http://test-auth:8080/mint?email=carol-contact@example.com")
distfs -use-pinentry=false -config /tmp/carol.json init --new -server http://storage-node-1:8080 -jwt "$JWT_C"
CAROL_CONTACT=$(distfs -use-pinentry=false -config /tmp/carol.json contact-info | grep "distfs-contact:v1:")

echo "Alice: Adding Carol via contact string (with interactive confirmation)..."
# Use 'echo y' to simulate user input
echo "y" | distfs -use-pinentry=false -config /tmp/alice.json group-add "$G_ID" "$CAROL_CONTACT" "Carol (Interactive)"

echo "Alice: Verifying Carol is in member list..."
if distfs -use-pinentry=false -config /tmp/alice.json group-members "$G_ID" | grep -q "Carol (Interactive)"; then
    echo "PASS: Carol added successfully via interactive confirmation"
else
    echo "FAIL: Carol not found in member list"
    exit 1
fi

echo "CONTACT EXCHANGE TEST PASSED"
