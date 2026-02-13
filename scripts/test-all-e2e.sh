#!/bin/sh
set -e

# This script runs all specialized E2E tests in sequence.
# It assumes the cluster is already bootstrapped by the common 'tester'.

echo "Starting Unified E2E Test Suite..."

# Wait for leader to settle and World Identity to be ready
sleep 2

/bin/test-e2e.sh
/bin/test-fuse.sh
/bin/test-gc.sh
/bin/test-stress.sh
/bin/test-integrity.sh
/bin/test-public.sh
/bin/test-writable.sh
/bin/test-ha.sh

echo "ALL E2E TESTS PASSED"
