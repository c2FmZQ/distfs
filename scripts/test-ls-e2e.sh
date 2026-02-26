#!/bin/sh
set -e
# E2E Test for Enhanced LS Command
set -e

echo "Starting LS E2E Tests..."

TEST_DIR="/ls-test-$(date +%s)"
distfs -use-pinentry=false mkdir $TEST_DIR

# Create a mix of files
# Use echo -n to avoid trailing newline for exact size checks
echo -n "small" > /tmp/small.txt
distfs -use-pinentry=false put /tmp/small.txt $TEST_DIR/small.txt

echo -n "large-data-for-sorting" > /tmp/large.txt
distfs -use-pinentry=false put /tmp/large.txt $TEST_DIR/large.txt

echo -n "hidden" > /tmp/hidden.txt
distfs -use-pinentry=false put /tmp/hidden.txt $TEST_DIR/.hidden.txt

distfs -use-pinentry=false mkdir $TEST_DIR/subdir
echo -n "subfile" > /tmp/sub.txt
distfs -use-pinentry=false put /tmp/sub.txt $TEST_DIR/subdir/sub.txt

# 1. Test basic ls (no hidden)
OUT=$(distfs -use-pinentry=false ls $TEST_DIR)
echo "$OUT" | grep "small.txt" > /dev/null
echo "$OUT" | grep "large.txt" > /dev/null
echo "$OUT" | grep "subdir" > /dev/null
if echo "$OUT" | grep ".hidden.txt" > /dev/null; then
    echo "FAIL: Hidden file shown in default ls"
    exit 1
fi
echo "[PASS] Basic LS"

# 2. Test ls -a (all)
OUT=$(distfs -use-pinentry=false ls -a $TEST_DIR)
echo "$OUT" | grep ".hidden.txt" > /dev/null
echo "[PASS] LS -a"

# 3. Test ls -l (long format)
OUT=$(distfs -use-pinentry=false ls -l $TEST_DIR)
echo "$OUT" | grep "small.txt" | grep "5" > /dev/null # Size check: 'small' is 5 bytes
echo "$OUT" | grep "large.txt" | grep "22" > /dev/null # Size check: 22 bytes
echo "$OUT" | grep "drwx" > /dev/null # Mode check for subdir
echo "[PASS] LS -l"

# 4. Test ls -R (recursive)
OUT=$(distfs -use-pinentry=false ls -R $TEST_DIR)
echo "$OUT" | grep "$TEST_DIR/subdir:" > /dev/null
echo "$OUT" | grep "sub.txt" > /dev/null
echo "[PASS] LS -R"

# 5. Test ls -S (sort by size)
# Go's flag package doesn't support -1S, must use separate flags
OUT=$(distfs -use-pinentry=false ls -1 -S $TEST_DIR)
FIRST=$(echo "$OUT" | head -n 1)
if [ "$FIRST" != "large.txt" ]; then
    echo "FAIL: Expected large.txt first in ls -S, got $FIRST"
    echo "Full output: $OUT"
    exit 1
fi
echo "[PASS] LS -S"

# 6. Test ls -t (sort by time)
# Wait a moment to ensure mtime difference
sleep 2
echo -n "newest" > /tmp/newest.txt
distfs -use-pinentry=false put /tmp/newest.txt $TEST_DIR/newest.txt
OUT=$(distfs -use-pinentry=false ls -1 -t $TEST_DIR)
FIRST=$(echo "$OUT" | head -n 1)
if [ "$FIRST" != "newest.txt" ]; then
    echo "FAIL: Expected newest.txt first in ls -t, got $FIRST"
    exit 1
fi
echo "[PASS] LS -t"

# 7. Test ls -F (classify)
OUT=$(distfs -use-pinentry=false ls -F $TEST_DIR)
echo "$OUT" | grep "subdir/" > /dev/null
echo "[PASS] LS -F"

echo "ALL LS E2E TESTS PASSED"
