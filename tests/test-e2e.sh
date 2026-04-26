#!/bin/sh
set -e
# set -e disabled for robustness against transient failures
export DISTFS_PASSWORD=testpassword
# Use the config from global setup or fall back
export DISTFS_CONFIG_DIR="${DISTFS_CONFIG_DIR:-/root/.distfs}"

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

echo "Joining nodes to cluster via Admin CLI..."
# Note: Join node still requires admin bypass or specific permissions.
# The global setup initialized the admin at $DISTFS_CONFIG_DIR/config.json.

COUNT=0
while true; do
  echo "DEBUG: Joining node-2..."
  if distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" admin-join "https://storage-node-2:9090"; then
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
  if distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" admin-join "https://storage-node-3:9090"; then
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

echo "Anchoring cluster topology in /registry..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" registry-update-cluster

echo "Creating directory..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" mkdir /testdir || echo "testdir already exists"

echo "Uploading file..."
echo "hello from e2e test" > /tmp/hello.txt
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" put /tmp/hello.txt /testdir/world.txt

echo "Listing directory..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" ls /testdir

echo "Verifying timeline consistency across nodes..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" verify-timeline

echo "Downloading file..."
distfs --disable-doh --allow-insecure --use-pinentry=false --config "$DISTFS_CONFIG_DIR/config.json" get /testdir/world.txt /tmp/hello-back.txt

echo "Verifying content..."
if grep -q "hello from e2e test" /tmp/hello-back.txt; then
  echo "E2E TEST PASSED"
else
  echo "E2E TEST FAILED: Content mismatch"
  exit 1
fi
