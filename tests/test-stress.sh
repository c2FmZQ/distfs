#!/bin/sh
set -e
# Multi-client Concurrency Stress Test
export DISTFS_PASSWORD=testpassword

CONFIG="/tmp/stress-user-config.json"

echo "Using pre-provisioned /users/stress-user directory..."
mkdir -p /tmp/stress-in /tmp/stress-out

run_stress() {
    ID=$1
    echo "Worker $ID: Starting..."
    # Each worker uploads and downloads a unique file
    echo "worker-$ID data" > "/tmp/stress-in/f-$ID"
    distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" put "/tmp/stress-in/f-$ID" "/users/stress-user/file-$ID"
    distfs --disable-doh --allow-insecure --use-pinentry=false --timeline-sample-rate=1.0 --config "$CONFIG" get "/users/stress-user/file-$ID" "/tmp/stress-out/f-$ID"
    if ! grep -q "worker-$ID data" "/tmp/stress-out/f-$ID"; then
        echo "Worker $ID: FAILED integrity check"
        exit 1
    fi
}

echo "Launching 10 concurrent workers..."
for i in $(seq 1 10); do
    run_stress $i &
done

wait
echo "STRESS TEST COMPLETE"
