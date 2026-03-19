#!/bin/sh
set -e
# LS Formatting and Sorting E2E Test
set -e

CONFIG="/tmp/ls-user-config.json"

echo "Starting LS E2E Tests..."

# Wait for readiness
until wget -qO- --timeout=2 http://storage-node-1:8080/v1/meta/key > /dev/null 2>&1; do sleep 1; done

# Pre-provisioned /users/ls-user directory owned by ls-user
# Setup Test Data
echo "small" > /tmp/small
echo "this is a much larger file" > /tmp/large
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" put /tmp/small /users/ls-user/a-small.txt
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" put /tmp/large /users/ls-user/z-large.txt
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" mkdir /users/ls-user/d-dir

# Set modes to match expectations (rwx)
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" chmod 0777 /users/ls-user/a-small.txt
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" chmod 0777 /users/ls-user/z-large.txt
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" chmod 0777 /users/ls-user/d-dir

echo "TEST: Standard LS (Alpha Sort)"
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" ls -1 /users/ls-user > /tmp/ls-std
if head -n 1 /tmp/ls-std | grep -q "a-small.txt"; then
    echo "PASS: Standard Alpha Sort"
else
    echo "FAIL: Standard Alpha Sort"
    cat /tmp/ls-std
    exit 1
fi

echo "TEST: Reverse Sort (-r)"
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" ls -1 -r /users/ls-user > /tmp/ls-rev
if head -n 1 /tmp/ls-rev | grep -q "z-large.txt"; then
    echo "PASS: Reverse Sort"
else
    echo "FAIL: Reverse Sort"
    cat /tmp/ls-rev
    exit 1
fi

echo "TEST: Size Sort (-S)"
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" ls -1 -S /users/ls-user > /tmp/ls-size
if head -n 1 /tmp/ls-size | grep -q "z-large.txt"; then
    echo "PASS: Size Sort"
else
    echo "FAIL: Size Sort"
    cat /tmp/ls-size
    exit 1
fi

echo "TEST: Long Format (-l)"
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" ls -l /users/ls-user > /tmp/ls-long
if grep -q "rwxrwx" /tmp/ls-long; then
    echo "PASS: Long Format"
else
    echo "FAIL: Long Format"
    cat /tmp/ls-long
    exit 1
fi

echo "TEST: Classification (-F)"
distfs -disable-doh -allow-insecure -use-pinentry=false -config "$CONFIG" ls -F /users/ls-user > /tmp/ls-class
if grep -q "d-dir/" /tmp/ls-class; then
    echo "PASS: Classification"
else
    echo "FAIL: Classification"
    cat /tmp/ls-class
    exit 1
fi

echo "LS E2E TESTS PASSED"
