#!/bin/sh
set -e
# High-Availability Failure Injection Test
export DISTFS_PASSWORD=testpassword
export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"

echo "Waiting for client configuration..."
until [ -f "$DISTFS_CONFIG_DIR/config.json" ]; do sleep 1; done

echo "Uploading test file to pre-provisioned /ha directory..."
echo "ha-resilience-data" > /tmp/ha.txt
distfs -disable-doh -use-pinentry=false -config "$DISTFS_CONFIG_DIR/config.json" put /tmp/ha.txt /ha/ha-test.bin

echo "Ensuring replication has started..."
sleep 2

echo "INJECTING FAILURE: Killing storage-node-3 via debug API..."
wget -qO- --header "X-Raft-Secret: supersecret" --post-data "" http://storage-node-3:8080/api/debug/suicide || true

echo "Waiting for cluster to detect failure..."
sleep 5

echo "Verifying cluster state..."
distfs -disable-doh -use-pinentry=false -config "$DISTFS_CONFIG_DIR/config.json" whoami > /dev/null

echo "Verifying file is STILL readable from remaining nodes..."
distfs -disable-doh -use-pinentry=false -config "$DISTFS_CONFIG_DIR/config.json" get /ha/ha-test.bin /tmp/ha-back.txt
if grep -q "ha-resilience-data" /tmp/ha-back.txt; then
    echo "PASS: HA Read consistency"
else
    echo "FAIL: HA Read consistency"
    exit 1
fi
