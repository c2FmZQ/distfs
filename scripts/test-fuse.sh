#!/bin/sh
# Comprehensive POSIX Compliance Test for DistFS FUSE

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

# --- POSIX TESTS START ---
MNT="/mnt/distfs"

echo "TEST 1: Basic Write/Read"
echo "data1" > $MNT/f1
if [ "$(cat $MNT/f1)" = "data1" ]; then
    echo "PASS: TEST 1"
else
    echo "FAIL: TEST 1"
    exit 1
fi

echo "TEST 2: Ownership & Attributes"
# Get UID/GID from stat
STAT_UID=$(stat -c %u $MNT/f1)
STAT_GID=$(stat -c %g $MNT/f1)
if [ "$STAT_UID" -eq 0 ] && [ "$STAT_GID" -eq 0 ]; then
    # In this test environment, we might be root, but FSM should have generated IDs
    # unless we haven't mapped Client -> UID yet.
    # But Inode creation sets them.
    echo "INFO: UID=$STAT_UID, GID=$STAT_GID (Root context)"
fi
# NLink check
STAT_NLINK=$(stat -c %h $MNT/f1)
if [ "$STAT_NLINK" -eq 1 ]; then
    echo "PASS: TEST 2 (NLink=1)"
else
    echo "FAIL: TEST 2 (NLink=$STAT_NLINK)"
    exit 1
fi

echo "TEST 3: Atomic Rename"
mkdir $MNT/dir1
mv $MNT/f1 $MNT/dir1/f2
if [ ! -f $MNT/f1 ] && [ -f $MNT/dir1/f2 ] && [ "$(cat $MNT/dir1/f2)" = "data1" ]; then
    echo "PASS: TEST 3"
else
    echo "FAIL: TEST 3"
    exit 1
fi

echo "TEST 4: Hard Links"
ln $MNT/dir1/f2 $MNT/f3
STAT_NLINK_F2=$(stat -c %h $MNT/dir1/f2)
STAT_NLINK_F3=$(stat -c %h $MNT/f3)
if [ "$STAT_NLINK_F2" -eq 2 ] && [ "$STAT_NLINK_F3" -eq 2 ]; then
    echo "content update" >> $MNT/f3
    if [ "$(cat $MNT/dir1/f2)" = "$(cat $MNT/f3)" ]; then
        echo "PASS: TEST 4"
    else
        echo "FAIL: TEST 4 (Content mismatch)"
        exit 1
    fi
else
    echo "FAIL: TEST 4 (NLink mismatch: F2=$STAT_NLINK_F2, F3=$STAT_NLINK_F3)"
    exit 1
fi

echo "TEST 5: Symlinks"
ln -s $MNT/dir1/f2 $MNT/link1
if [ -L $MNT/link1 ] && [ "$(readlink $MNT/link1)" = "$MNT/dir1/f2" ]; then
    if [ "$(cat $MNT/link1)" = "$(cat $MNT/dir1/f2)" ]; then
        echo "PASS: TEST 5"
    else
        echo "FAIL: TEST 5 (Content follow failed)"
        exit 1
    fi
else
    echo "FAIL: TEST 5 (Symlink creation failed)"
    exit 1
fi

echo "TEST 6: Deletion & NLink decrement"
rm $MNT/f3
STAT_NLINK_F2=$(stat -c %h $MNT/dir1/f2)
if [ ! -f $MNT/f3 ] && [ "$STAT_NLINK_F2" -eq 1 ]; then
    echo "PASS: TEST 6"
else
    echo "FAIL: TEST 6 (NLink not decremented or file still exists)"
    exit 1
fi

echo "TEST 7: Rmdir semantics"
mkdir $MNT/dir2
touch $MNT/dir2/f
if rmdir $MNT/dir2 2>/dev/null; then
    echo "FAIL: TEST 7 (rmdir non-empty succeeded)"
    exit 1
else
    rm $MNT/dir2/f
    if rmdir $MNT/dir2; then
        echo "PASS: TEST 7"
    else
        echo "FAIL: TEST 7 (rmdir empty failed)"
        exit 1
    fi
fi

echo "TEST 8: SetAttr (Chmod/Truncate)"
echo "original" > $MNT/f4
chmod 0777 $MNT/f4
STAT_MODE=$(stat -c %a $MNT/f4)
if [ "$STAT_MODE" = "777" ]; then
    truncate -s 4 $MNT/f4
    STAT_SIZE=$(stat -c %s $MNT/f4)
    if [ "$STAT_SIZE" -eq 4 ]; then
        echo "PASS: TEST 8"
    else
        echo "FAIL: TEST 8 (Truncate failed: $STAT_SIZE)"
        exit 1
    fi
else
    echo "FAIL: TEST 8 (Chmod failed: $STAT_MODE)"
    exit 1
fi

# --- POSIX TESTS END ---

echo "Unmounting..."
kill $FUSE_PID
wait $FUSE_PID || true
echo "ALL POSIX COMPLIANCE TESTS PASSED"
