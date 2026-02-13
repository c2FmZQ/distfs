#!/bin/sh
# High-Availability Failure Injection Test
export DISTFS_PASSWORD=testpassword

echo "Waiting for client configuration..."
until [ -f /root/.distfs/config.json ]; do sleep 1; done

echo "Creating ha directory..."
until distfs mkdir /ha; do
    echo "Retrying ha mkdir..."
    sleep 1
done

echo "Uploading test file..."
echo "ha-resilience-data" > /tmp/ha.txt
distfs put /tmp/ha.txt /ha/ha-test.bin

echo "Ensuring replication has started..."
sleep 2

echo "INJECTING FAILURE: Killing storage-node-3 via debug API..."
wget -qO- --header "X-Raft-Secret: supersecret" --post-data "" http://storage-node-3:8080/api/debug/suicide || true

echo "Waiting for cluster to detect failure..."
sleep 5

echo "Verifying file is STILL readable from remaining nodes..."
distfs get /ha/ha-test.bin /tmp/ha-back.txt
if grep -q "ha-resilience-data" /tmp/ha-back.txt; then
    echo "PASS: HA Read consistency"
else
    echo "FAIL: HA Read consistency"
    exit 1
fi
