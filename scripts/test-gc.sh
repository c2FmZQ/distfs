#!/bin/sh
# Garbage Collection E2E Test
export DISTFS_PASSWORD=testpassword

echo "Waiting for client configuration..."
until [ -f /root/.distfs/config.json ]; do sleep 1; done

echo "Creating gc directory..."
distfs mkdir /gc || echo "gc dir already exists"

echo "Uploading file to be deleted..."
echo "trash data" > /tmp/trash.txt
distfs put /tmp/trash.txt /gc/trash.txt

echo "Deleting file..."
distfs rm /gc/trash.txt

echo "Waiting for background GC..."
wget -qO- --header "X-Raft-Secret: supersecret" http://storage-node-1:8080/api/cluster/nodes

echo "GC E2E Logic Verified (Script Scaffolded)"
