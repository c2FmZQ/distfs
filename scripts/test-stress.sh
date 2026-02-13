#!/bin/sh
# Multi-client Concurrency Stress Test
export DISTFS_PASSWORD=testpassword

echo "Waiting for client configuration..."
until [ -f /root/.distfs/config.json ]; do sleep 1; done

echo "Creating stress directory..."
distfs mkdir /stress || echo "stress dir already exists"

mkdir -p /tmp/stress-in /tmp/stress-out

run_stress() {
    ID=$1
    echo "Worker $ID: Starting..."
    FILE="/stress/stress-$ID.txt"
    DATA="stress data from worker $ID"
    echo "$DATA" > /tmp/stress-in/$ID
    distfs put /tmp/stress-in/$ID $FILE
    distfs get $FILE /tmp/stress-out/$ID
    if grep -q "$DATA" /tmp/stress-out/$ID; then
        echo "Worker $ID: PASS"
    else
        echo "Worker $ID: FAIL"
        exit 1
    fi
}

echo "Launching 10 concurrent workers..."
for i in $(seq 1 10); do
    run_stress $i &
done

wait
echo "STRESS TEST COMPLETE"
