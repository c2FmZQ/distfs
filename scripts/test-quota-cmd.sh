#!/bin/sh
set -e

# Setup Admin
echo "Global Setup..."
export ADMIN_CONFIG=/root/.distfs/config.json
# Admin is already initialized by test-all-e2e.sh in /root/.distfs/config.json

# Setup User
echo "User Setup..."
export USER_CONFIG=/tmp/user-quota.json
JWT=$(wget -qO- "http://test-auth:8080/mint?email=user-quota@example.com")
distfs -use-pinentry=false -config $USER_CONFIG init --new -server http://storage-node-1:8080 -jwt "$JWT"
USER_ID=$(distfs -use-pinentry=false -config $USER_CONFIG whoami)

# Admin: Set User Quota
echo "Admin: Setting User Quota..."
distfs -use-pinentry=false -config $ADMIN_CONFIG admin-user-quota $USER_ID 5000 10

# User: Create Group
echo "User: Creating Group..."
distfs -use-pinentry=false -config $USER_CONFIG group-create "my-project"
G_ID=$(distfs -use-pinentry=false -config $USER_CONFIG group-list | grep "my-project" | awk '{print $1}')

# Admin: Set Group Quota
echo "Admin: Setting Group Quota for G_ID: '$G_ID'..."
distfs -use-pinentry=false -config $ADMIN_CONFIG admin-group-quota "$G_ID" 2000 5

# User: Check Quota
echo "User: Running 'distfs quota'..."
distfs -use-pinentry=false -config $USER_CONFIG quota

echo "Verification: Checking for expected strings..."
distfs -use-pinentry=false -config $USER_CONFIG quota | grep "Personal Usage for $USER_ID"
distfs -use-pinentry=false -config $USER_CONFIG quota | grep "Inodes: 0 / 10"
distfs -use-pinentry=false -config $USER_CONFIG quota | grep "Storage: 0 B / 4.9 KB"
distfs -use-pinentry=false -config $USER_CONFIG quota | grep "Group: my-project"
# Note: Group is empty initially
distfs -use-pinentry=false -config $USER_CONFIG quota | grep "Inodes: 0 / 5"
distfs -use-pinentry=false -config $USER_CONFIG quota | grep "Storage: 0 B / 2.0 KB"

echo "QUOTA COMMAND TEST PASSED"
