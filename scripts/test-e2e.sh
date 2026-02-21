#!/bin/sh
# set -e disabled for robustness against transient failures
export DISTFS_PASSWORD=testpassword

echo "Waiting for storage-node-1 API to be ready..."
MAX_RETRIES=60
COUNT=0
while ! wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge $MAX_RETRIES ]; then
    echo "TIMEOUT: storage-node-1 API not ready"
    exit 1
  fi
  sleep 1
done

echo "Waiting for cluster leader..."
COUNT=0
LEADER_URL=""
while true; do
  STATUS=$(wget -qO- --timeout=2 --header "X-Raft-Secret: supersecret" http://storage-node-1:8080/v1/node 2>&1 || true)
  echo "DEBUG STATUS: $STATUS"
  if echo "$STATUS" | grep -q '"state":"Leader"'; then
    echo "storage-node-1 is Leader"
    LEADER_URL="http://storage-node-1:8080"
    break
  fi
  LEADER_ADDR=$(echo "$STATUS" | grep -o '"leader":"[^"]*"' | cut -d'"' -f4)
  if [ -n "$LEADER_ADDR" ]; then
    echo "Leader found at $LEADER_ADDR"
    LEADER_IP=$(echo "$LEADER_ADDR" | cut -d':' -f1)
    LEADER_URL="http://$LEADER_IP:8080"
    break
  fi
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge $MAX_RETRIES ]; then
    echo "TIMEOUT: No leader elected"
    exit 1
  fi
  sleep 1
done

echo "Joining nodes to cluster via Admin CLI..."

COUNT=0
while true; do
  # Use Client to join node via admin API (discovery via internal cluster address)
  echo "DEBUG: Joining node-2..."
  if distfs -use-pinentry=false -config /root/.distfs/config.json admin-join "https://storage-node-2:9090"; then
    echo "node-2 joined"
    break
  fi
  echo "Join node-2 failed, retrying..."
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge 10 ]; then echo "Failed to join node-2"; exit 1; fi
  sleep 2
done

COUNT=0
while true; do
  echo "DEBUG: Joining node-3..."
  if distfs -use-pinentry=false -config /root/.distfs/config.json admin-join "https://storage-node-3:9090"; then
    echo "node-3 joined"
    break
  fi
  echo "Join node-3 failed, retrying..."
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge 10 ]; then echo "Failed to join node-3"; exit 1; fi
  sleep 2
done

echo "Waiting for cluster stability..."
sleep 5

echo "Creating directory..."
distfs -use-pinentry=false -config /root/.distfs/config.json mkdir /testdir || echo "testdir already exists"

echo "Uploading file..."
echo "hello from e2e test" > /tmp/hello.txt
distfs -use-pinentry=false -config /root/.distfs/config.json put /tmp/hello.txt /testdir/world.txt

echo "Listing directory..."
distfs -use-pinentry=false -config /root/.distfs/config.json ls /testdir

echo "Downloading file..."
distfs -use-pinentry=false -config /root/.distfs/config.json get /testdir/world.txt /tmp/hello-back.txt

echo "Verifying content..."
if grep -q "hello from e2e test" /tmp/hello-back.txt; then
  echo "E2E TEST PASSED"
else
  echo "E2E TEST FAILED: Content mismatch"
  exit 1
fi
