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
  STATUS=$(wget -qO- --timeout=2 --header "X-Raft-Secret: supersecret" http://storage-node-1:8080/v1/cluster/status 2>&1 || true)
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

echo "Joining nodes to cluster..."

# Fetch Node 2 ID with retry
COUNT=0
NODE2_ID=""
while [ -z "$NODE2_ID" ]; do
  NODE2_STATUS=$(wget -qO- --timeout=2 --header "X-Raft-Secret: supersecret" http://storage-node-2:8080/v1/cluster/status 2>&1 || true)
  NODE2_ID=$(echo "$NODE2_STATUS" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -n "$NODE2_ID" ]; then break; fi
  echo "Waiting for Node 2 ID... ($NODE2_STATUS)"
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge 30 ]; then echo "Timeout fetching Node 2 ID"; exit 1; fi
  sleep 1
done
echo "Node 2 ID: $NODE2_ID"

COUNT=0
while true; do
  if wget -qO- --timeout=5 --header "X-Raft-Secret: supersecret" --post-data "{\"id\":\"$NODE2_ID\",\"address\":\"storage-node-2:5000\"}" $LEADER_URL/api/cluster/join > /dev/null 2>&1; then
    echo "node-2 joined"
    break
  fi
  echo "Join node-2 failed, retrying..."
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge 10 ]; then echo "Failed to join node-2"; exit 1; fi
  sleep 2
done

# Fetch Node 3 ID with retry
COUNT=0
NODE3_ID=""
while [ -z "$NODE3_ID" ]; do
  NODE3_STATUS=$(wget -qO- --timeout=2 --header "X-Raft-Secret: supersecret" http://storage-node-3:8080/v1/cluster/status 2>&1 || true)
  NODE3_ID=$(echo "$NODE3_STATUS" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -n "$NODE3_ID" ]; then break; fi
  echo "Waiting for Node 3 ID... ($NODE3_STATUS)"
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge 30 ]; then echo "Timeout fetching Node 3 ID"; exit 1; fi
  sleep 1
done
echo "Node 3 ID: $NODE3_ID"

COUNT=0
while true; do
  if wget -qO- --timeout=5 --header "X-Raft-Secret: supersecret" --post-data "{\"id\":\"$NODE3_ID\",\"address\":\"storage-node-3:5000\"}" $LEADER_URL/api/cluster/join > /dev/null 2>&1; then
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

if [ ! -f /root/.distfs/config.json ]; then
  echo "Initializing distfs..."
  distfs init -meta $LEADER_URL -id test@example.com
  echo "Registering user..."
  
  # Fetch real JWT from test-auth
  JWT=$(wget -qO- "http://test-auth:8080/mint?email=test@example.com")
  distfs register -jwt "$JWT"
  echo "Making root world-writable for concurrent tests..."
  distfs chmod 0777 /
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