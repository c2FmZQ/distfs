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

echo "Joining nodes to cluster..."
wget -qO- --timeout=5 --header "X-Raft-Secret: supersecret" --post-data '{"id":"node-2","address":"storage-node-2:5000"}' $LEADER_URL/v1/cluster/join || echo "node-2 already joined"
wget -qO- --timeout=5 --header "X-Raft-Secret: supersecret" --post-data '{"id":"node-3","address":"storage-node-3:5000"}' $LEADER_URL/v1/cluster/join || echo "node-3 already joined"

echo "Waiting for cluster stability..."
sleep 5

if [ ! -f /root/.distfs/config.json ]; then
  echo "Initializing distfs..."
  distfs init -meta $LEADER_URL -id test@example.com
  echo "Registering user..."
  
  # Fetch real JWT from test-auth
  JWT=$(wget -qO- "http://test-auth:8080/mint?email=test@example.com")
  distfs register -jwt "$JWT"
fi

echo "Creating directory..."
distfs mkdir /testdir || echo "testdir already exists"

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
