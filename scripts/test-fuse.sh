#!/bin/sh
# set -e # Remove set -e to allow manual cleanup/tail on failure

echo "Waiting for client configuration..."
MAX_RETRIES=120
COUNT=0
until [ -f /root/.distfs/config.json ]; do
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge $MAX_RETRIES ]; then
    echo "TIMEOUT: client config not found"
    exit 1
  fi
  sleep 1
done

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Mounting FUSE..."
mkdir -p /mnt/distfs
/bin/distfs-fuse -mount /mnt/distfs > /tmp/fuse.log 2>&1 &
FUSE_PID=$!

echo "Waiting for FUSE mount..."
MAX_MOUNT_RETRIES=10
MOUNT_COUNT=0
while ! mountpoint -q /mnt/distfs; do
  MOUNT_COUNT=$((MOUNT_COUNT + 1))
  if [ $MOUNT_COUNT -ge $MAX_MOUNT_RETRIES ]; then
    echo "TIMEOUT: FUSE mount failed"
    cat /tmp/fuse.log
    exit 1
  fi
  sleep 1
done

echo "Testing FUSE Read (CLI created)..."
echo "hello from cli" > /tmp/hello-cli.txt
/bin/distfs mkdir /cli-dir || true
/bin/distfs put /tmp/hello-cli.txt /cli-dir/hello.txt

echo "Listing /mnt/distfs..."
ls -R /mnt/distfs

echo "Reading file..."
if grep -q "hello from cli" /mnt/distfs/cli-dir/hello.txt; then
  echo "FUSE READ PASSED"
else
  echo "FUSE READ FAILED"
  cat /tmp/fuse.log
  exit 1
fi

echo "Testing FUSE Write..."
echo "written via fuse" > /mnt/distfs/cli-dir/fuse-write.txt
sync
ls -la /mnt/distfs/cli-dir
if grep -q "written via fuse" /mnt/distfs/cli-dir/fuse-write.txt; then
  echo "FUSE WRITE PASSED"
else
  echo "FUSE WRITE FAILED"
  cat /tmp/fuse.log
  exit 1
fi

echo "Testing FUSE Mkdir..."
mkdir /mnt/distfs/fuse-dir
if [ -d /mnt/distfs/fuse-dir ]; then
  echo "FUSE MKDIR PASSED"
else
  echo "FUSE MKDIR FAILED"
  cat /tmp/fuse.log
  exit 1
fi

echo "Verifying FUSE-CLI Interop..."
/bin/distfs ls /fuse-dir
/bin/distfs get /cli-dir/fuse-write.txt /tmp/fuse-verify.txt
if grep -q "written via fuse" /tmp/fuse-verify.txt; then
  echo "FUSE-CLI INTEROP PASSED"
else
  echo "FUSE-CLI INTEROP FAILED"
  cat /tmp/fuse.log
  exit 1
fi

echo "Unmounting..."
kill $FUSE_PID
wait $FUSE_PID || true
echo "ALL FUSE TESTS PASSED"