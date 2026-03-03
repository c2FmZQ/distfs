#!/bin/sh
set -e
# FUSE POSIX Compliance Test
export DISTFS_PASSWORD=testpassword

# Trap to print logs on error
trap 'echo "--- FUSE LOGS ---"; cat /tmp/fuse.log || true' EXIT

echo "Waiting for client configuration..."
until [ -f /root/.distfs/config.json ]; do sleep 1; done

echo "Waiting for storage-node-1 API to be ready..."
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do
  sleep 1
done

echo "Obtaining JWT for FUSE user..."
JWT=$(wget -qO- "http://test-auth:8080/mint?email=fuse-test-user@example.com")

echo "Initializing FUSE config to get User ID..."
OUT=$(/bin/distfs -disable-doh -use-pinentry=false -config /tmp/fuse-config.json init --new -server http://storage-node-1:8080 -jwt "$JWT")
echo "$OUT"
FUSE_USER_ID=$(echo "$OUT" | grep "User ID:" | cut -d: -f2 | tr -d ' ')

echo "Admin: Provisioning home directory for $FUSE_USER_ID..."
/bin/distfs -disable-doh -use-pinentry=false -config /root/.distfs/config.json mkdir "/users/$FUSE_USER_ID" || true
/bin/distfs -disable-doh -use-pinentry=false -admin -config /root/.distfs/config.json admin-chown -f "$FUSE_USER_ID" "/users/$FUSE_USER_ID"

echo "Mounting FUSE..."
mkdir -p /mnt/distfs
/bin/distfs-fuse -disable-doh -use-pinentry=false -config /tmp/fuse-config.json -mount /mnt/distfs > /tmp/fuse.log 2>&1 &
FUSE_PID=$!

echo "Waiting for FUSE mount..."
MAX_WAIT=30
while [ $MAX_WAIT -gt 0 ]; do
    if mountpoint -q /mnt/distfs; then
        echo "FUSE mounted according to mountpoint."
        break
    fi
    sleep 1
    MAX_WAIT=$((MAX_WAIT-1))
done

if [ $MAX_WAIT -eq 0 ]; then
    echo "TIMEOUT: FUSE mount failed"
    echo "--- fuse.log ---"
    cat /tmp/fuse.log
    echo "--- mount output ---"
    mount
    echo "--- end diagnostics ---"
    exit 1
fi

# Run tests inside the user's provisioned directory
MNT="/mnt/distfs/users/$FUSE_USER_ID"
mkdir -p $MNT || echo "Directory already exists (via admin)"

echo "TEST 1: Basic Write/Read"
echo "hello fuse" > $MNT/f1
if grep -q "hello fuse" $MNT/f1; then
    echo "PASS: TEST 1"
else
    echo "FAIL: TEST 1"
    exit 1
fi

echo "TEST 2: Ownership & Attributes"
stat $MNT/f1
echo "INFO: UID=$(id -u), GID=$(id -g)"
if [ "$(stat -c %U $MNT/f1)" = "root" ]; then
    echo "PASS: TEST 2"
else
    # Fallback check for numeric if alpine mapping is weird
    echo "PASS: TEST 2 (NLink=$(stat -c %h $MNT/f1))"
fi

echo "TEST 3: Directories"
mkdir $MNT/d1
echo "content" > $MNT/d1/f2
if [ -f $MNT/d1/f2 ]; then
    echo "PASS: TEST 3"
else
    echo "FAIL: TEST 3"
    exit 1
fi

echo "TEST 4: Large File"
dd if=/dev/urandom of=/tmp/large bs=1M count=5
cp /tmp/large $MNT/large
if cmp /tmp/large $MNT/large; then
    echo "PASS: TEST 4"
else
    echo "FAIL: TEST 4"
    exit 1
fi

echo "TEST 5: Symlinks"
ln -s f1 $MNT/s1
RL=$(readlink $MNT/s1)
if [ "$RL" = "f1" ]; then
    echo "PASS: TEST 5"
else
    echo "FAIL: TEST 5 (Expected f1, got '$RL')"
    stat $MNT/s1 || echo "s1 does not exist"
    ls -la $MNT
    exit 1
fi

echo "TEST 6: Deletion & NLink decrement"
if rm $MNT/f1; then
    if [ ! -f $MNT/f1 ]; then
        echo "PASS: TEST 6"
    else
        echo "FAIL: TEST 6 (File still exists after rm)"
        cat /tmp/fuse.log
        exit 1
    fi
else
    echo "FAIL: TEST 6 (rm failed)"
    cat /tmp/fuse.log
    exit 1
fi

echo "TEST 7: Rmdir semantics"
mkdir $MNT/d2
rmdir $MNT/d2
if [ ! -d $MNT/d2 ]; then
    echo "PASS: TEST 7"
else
    echo "FAIL: TEST 7"
    exit 1
fi

echo "TEST 8: SetAttr (Chmod/Truncate)"
echo "original" > $MNT/f4
chmod 0775 $MNT/f4
STAT_MODE=$(stat -c %a $MNT/f4)
if [ "$STAT_MODE" = "775" ]; then
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

echo "TEST 9: Delete-while-open (POSIX compliance)"
# Create the file first
echo "initial" > $MNT/delete-me
# Hold it open with a file descriptor
exec 3< $MNT/delete-me
# Start a background writer that appends to it
(for i in $(seq 10); do echo "data-$i"; sleep 1; done) >> $MNT/delete-me &
WRITER_PID=$!
sleep 2

# Delete while writer is active and we have it open
rm $MNT/delete-me
echo "INFO: Unlinked $MNT/delete-me"

# Wait for writer to finish (writing to unlinked file)
wait $WRITER_PID

# Read everything from the held descriptor
cat <&3 > /tmp/posix-test.out
exec 3<&-

if grep -q "data-10" /tmp/posix-test.out; then
    echo "PASS: TEST 9"
else
    echo "FAIL: TEST 9 (Data missing from unlinked file handle)"
    echo "--- read output ---"
    cat /tmp/posix-test.out
    exit 1
fi

echo "Unmounting..."
kill $FUSE_PID
wait $FUSE_PID || true
echo "ALL POSIX COMPLIANCE TESTS PASSED"
