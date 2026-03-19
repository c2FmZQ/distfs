#!/bin/sh
set -e
# Quota Command E2E Test
set -e

# Setup Admin
echo "Global Setup..."
export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"
export ADMIN_CONFIG="$DISTFS_CONFIG_DIR/config.json"
# Admin is already initialized by test-all-e2e.sh in "$DISTFS_CONFIG_DIR/config.json"

# Setup User
echo "User Setup..."
export USER_CONFIG=/tmp/user-quota.json
JWT=$(wget -qO- "http://test-auth:8080/mint?email=user-quota@example.com")
INIT_OUT=$(distfs -disable-doh -allow-insecure -use-pinentry=false -config "$USER_CONFIG" init --new -server http://storage-node-1:8080 -jwt "$JWT")
U_ID=$(echo "$INIT_OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')
distfs -disable-doh -allow-insecure -use-pinentry=false -admin -config "$DISTFS_CONFIG_DIR/config.json" admin-unlock-user "$U_ID"

echo "Admin: Setting User Quota..."
distfs -disable-doh -allow-insecure -use-pinentry=false -admin -config "$ADMIN_CONFIG" admin-user-quota "$U_ID" 5000 10

echo "User: Creating Group with independent quota..."
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$USER_CONFIG" group-create --quota my-project > /tmp/group-out.txt
G_ID=$(grep "^ID:" /tmp/group-out.txt | awk '{print $2}')

echo "Admin: Setting Group Quota for G_ID: '$G_ID'..."
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$ADMIN_CONFIG" admin-group-quota "$G_ID" 2000 5

echo "User: Running 'distfs quota'..."
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$USER_CONFIG" quota > /tmp/quota-out.txt
cat /tmp/quota-out.txt

echo "Verification: Checking for expected strings..."
grep -q "Personal Usage" /tmp/quota-out.txt
grep -q "Inodes: 0 / 10" /tmp/quota-out.txt
grep -q "Storage: 0 B / 4.9 KB" /tmp/quota-out.txt
grep -q "Group: my-project" /tmp/quota-out.txt
grep -q "Inodes: 0 / 5" /tmp/quota-out.txt
grep -q "Storage: 0 B / 2.0 KB" /tmp/quota-out.txt

echo "QUOTA COMMAND TEST PASSED"
