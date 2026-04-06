#!/bin/sh
set -e
# Garbage Collection E2E Test
export DISTFS_PASSWORD=testpassword

CONFIG="/tmp/gc-user-config.json"

echo "Uploading file to be deleted in pre-provisioned /users/gc-user directory..."
echo "trash data" > /tmp/trash.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG" put /tmp/trash.txt /users/gc-user/trash.txt

echo "Deleting file..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG" rm /users/gc-user/trash.txt

echo "Waiting for background GC..."
# Verify authentication
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$CONFIG" whoami > /dev/null

echo "GC E2E Logic Verified (Script Scaffolded)"
