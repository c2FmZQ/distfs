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
INIT_A=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/alice.json init --new -server http://storage-node-1:8080 -jwt "$JWT_A")
U_A=$(echo "$INIT_A" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
distfs -disable-doh -allow-insecure -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" admin-unlock-user "$U_A"

echo "Initializing Bob (Member)..."
JWT_B=$(wget -qO- "http://test-auth:8080/mint?email=bob-contact@example.com")
INIT_B=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/bob.json init --new -server http://storage-node-1:8080 -jwt "$JWT_B")
U_B=$(echo "$INIT_B" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
distfs -disable-doh -allow-insecure -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" admin-unlock-user "$U_B"

echo "Bob: Generating contact info..."
BOB_CONTACT=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/bob.json contact-info | grep "distfs-contact:v1:")
echo "Bob's contact string: $BOB_CONTACT"

echo "Alice: Creating group 'exchange-test'..."
G_OUT=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/alice.json group-create exchange-test)
G_ID=$(echo "$G_OUT" | grep "^ID:" | awk '{print $2}')
echo "Group ID: $G_ID"

echo "Alice: Adding Bob via contact string (with -f)..."
distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/alice.json group-add -f "$G_ID" "$BOB_CONTACT" "Bob (OOB)"

echo "Alice: Verifying Bob is in member list..."
if distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/alice.json group-members "$G_ID" | grep -q "Bob (OOB)"; then
    echo "PASS: Bob added successfully via contact string"
else
    echo "FAIL: Bob not found in member list"
    exit 1
fi

echo "Initializing Carol..."
JWT_C=$(wget -qO- "http://test-auth:8080/mint?email=carol-contact@example.com")
INIT_C=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/carol.json init --new -server http://storage-node-1:8080 -jwt "$JWT_C")
U_C=$(echo "$INIT_C" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
distfs -disable-doh -allow-insecure -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" admin-unlock-user "$U_C"
CAROL_CONTACT=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/carol.json contact-info | grep "distfs-contact:v1:")

echo "Alice: Adding Carol via contact string (with interactive confirmation)..."
# Use 'echo y' to simulate user input
echo "y" | distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/alice.json group-add "$G_ID" "$CAROL_CONTACT" "Carol (Interactive)"

echo "Alice: Verifying Carol is in member list..."
if distfs -disable-doh -allow-insecure -use-pinentry=false -config /tmp/alice.json group-members "$G_ID" | grep -q "Carol (Interactive)"; then
    echo "PASS: Carol added successfully via interactive confirmation"
else
    echo "FAIL: Carol not found in member list"
    exit 1
fi

echo "CONTACT EXCHANGE TEST PASSED"
