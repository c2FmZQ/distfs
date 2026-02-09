#!/bin/sh
set -e

echo "Waiting for storage-node-1 API to be ready..."
MAX_RETRIES=60
COUNT=0
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
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
  STATUS=$(wget -qO- --timeout=2 http://storage-node-1:8080/v1/cluster/status 2>&1 || true)
  # Check if state is Leader
  if echo "$STATUS" | grep -q '"state":"Leader"'; then
    echo "storage-node-1 is Leader"
    LEADER_URL="http://storage-node-1:8080"
    break
  fi
  # Check if leader address is known
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

echo "Joining node-2 to cluster..."
wget -qO- --timeout=5 --post-data '{"id":"node-2","address":"storage-node-2:5000"}' $LEADER_URL/v1/cluster/join

echo "Joining node-3 to cluster..."
wget -qO- --timeout=5 --post-data '{"id":"node-3","address":"storage-node-3:5000"}' $LEADER_URL/v1/cluster/join

echo "Waiting for cluster stability..."
sleep 5

echo "Initializing distfs..."
distfs init -meta $LEADER_URL -id test@example.com

echo "Registering user..."
# Using a dummy JWT since server is in DEBUG_INSECURE mode
DUMMY_JWT="header.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.sig"
distfs register -jwt "$DUMMY_JWT"

echo "Creating directory..."
distfs mkdir /testdir

echo "Uploading file..."
echo "hello from e2e test" > /tmp/hello.txt
distfs put /tmp/hello.txt /testdir/world.txt

echo "Listing directory..."
distfs ls /testdir

echo "Downloading file..."
distfs get /testdir/world.txt /tmp/hello-back.txt

echo "Verifying content..."
if grep -q "hello from e2e test" /tmp/hello-back.txt; then
  echo "E2E TEST PASSED"
else
  echo "E2E TEST FAILED: Content mismatch"
  exit 1
fi
