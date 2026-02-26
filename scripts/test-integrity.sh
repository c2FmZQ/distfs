#!/bin/sh
set -e
# E2E Data Integrity & Repair Test
export DISTFS_PASSWORD=testpassword

echo "Waiting for client configuration..."
until [ -f /root/.distfs/config.json ]; do sleep 1; done

echo "Creating integrity directory..."
distfs -use-pinentry=false -config /root/.distfs/config.json mkdir /integrity || echo "integrity dir already exists"

echo "Uploading critical file..."
echo "integrity-protected-data" > /tmp/crit.txt
distfs -use-pinentry=false put /tmp/crit.txt /integrity/critical.txt

echo "Verifying upload..."
distfs -use-pinentry=false ls /integrity

echo "INJECTING CORRUPTION: Overwriting a chunk on Node 1..."
CHUNK=$(find /data -type f | grep -v "fsm.bolt" | head -1)
if [ -n "$CHUNK" ]; then
    echo "Corrupting $CHUNK"
    echo "CORRUPT" > "$CHUNK"
else
    echo "No chunks found to corrupt on Node 1"
fi

echo "Triggering Integrity Scan..."
wget -qO- --header "X-Raft-Secret: supersecret" --post-data "" http://storage-node-1:8080/api/debug/scrub || true

echo "Waiting for repair..."
sleep 5

echo "Verifying file is STILL CORRECT (Self-healed from replicas)..."
distfs -use-pinentry=false get /integrity/critical.txt /tmp/crit-back.txt
if diff /tmp/crit.txt /tmp/crit-back.txt; then
    echo "PASS: Data Integrity Self-Healed"
else
    echo "FAIL: Data Integrity Repair failed"
    exit 1
fi
