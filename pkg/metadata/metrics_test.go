package metadata

import (
	"testing"
	"time"
)

func TestMetricsCollector(t *testing.T) {
	mc := NewMetricsCollector()

	// 1. Test Operations Counting
	mc.RecordOp(CmdCreateInode, 100*time.Microsecond)
	mc.RecordOp(CmdCreateInode, 200*time.Microsecond)
	mc.RecordOp(CmdUpdateInode, 1*time.Millisecond)

	// 2. Test Latency Distribution (Histogram)
	// Add 95 ops at 100us
	for i := 0; i < 95; i++ {
		mc.RecordOp(CmdBatch, 100*time.Microsecond)
	}
	// Add 4 ops at 10ms
	for i := 0; i < 4; i++ {
		mc.RecordOp(CmdBatch, 10*time.Millisecond)
	}
	// Add 1 op at 1s
	mc.RecordOp(CmdBatch, 1*time.Second)

	// Total Ops: 2 + 1 + 95 + 4 + 1 = 103
	// Latency Count: 103

	snap := mc.SnapshotAndReset()

	if snap.OpsCreateInode != 2 {
		t.Errorf("expected 2 create ops, got %d", snap.OpsCreateInode)
	}
	if snap.OpsUpdateInode != 1 {
		t.Errorf("expected 1 update op, got %d", snap.OpsUpdateInode)
	}
	if snap.OpsCommitBatch != 100 {
		t.Errorf("expected 100 batch ops, got %d", snap.OpsCommitBatch)
	}

	if snap.LatencyFSMCount != 103 {
		t.Errorf("expected 103 total latency samples, got %d", snap.LatencyFSMCount)
	}

	// 3. Test Percentiles
	// Buckets:
	// [0] <= 100us: 1 (Create 100us) + 95 (Batch 100us) = 96
	// [1] <= 250us: 1 (Create 200us)
	// [3] <= 1ms: 1 (Update 1ms)
	// [6] <= 10ms: 4 (Batch 10ms)
	// [12] <= 1s: 1 (Batch 1s)

	// Targets (integer truncation):
	// P50: 103 * 0.50 = 51.
	// P95: 103 * 0.95 = 97.
	// P99: 103 * 0.99 = 101.

	// Cumulative:
	// B0: 96 (>= 51). P50 = 100us.
	// B1: 96+1 = 97 (>= 97). P95 = 250us.
	// ...
	// B3: 97+1 = 98.
	// B4-B5: 98.
	// B6: 98+4 = 102 (>= 101). P99 = 10ms.

	expectedP50 := int64(100 * 1000)
	expectedP95 := int64(250 * 1000)
	expectedP99 := int64(10 * 1000 * 1000)

	if snap.LatencyP50 != expectedP50 {
		t.Errorf("expected P50 %d, got %d", expectedP50, snap.LatencyP50)
	}
	if snap.LatencyP95 != expectedP95 {
		t.Errorf("expected P95 %d, got %d", expectedP95, snap.LatencyP95)
	}
	if snap.LatencyP99 != expectedP99 {
		t.Errorf("expected P99 %d, got %d", expectedP99, snap.LatencyP99)
	}
}
