//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"runtime"
	"sync/atomic"
	"time"
)

// MetricSnapshot represents a point-in-time snapshot of system performance.
type MetricSnapshot struct {
	Timestamp int64 `json:"ts"` // Unix Nano

	// Metadata Operations Counts
	OpsCreateInode uint64 `json:"ops_create_inode"`
	OpsUpdateInode uint64 `json:"ops_update_inode"`
	OpsDeleteInode uint64 `json:"ops_delete_inode"`
	OpsCommitBatch uint64 `json:"ops_commit_batch"`

	// Latency (Cumulative Nano / Count)
	LatencyFSMTotal int64 `json:"lat_fsm_total_ns"`
	LatencyFSMCount int64 `json:"lat_fsm_count"`

	// Latency Percentiles (Approximate, Upper Bound of Bucket)
	LatencyP50 int64 `json:"lat_p50_ns"`
	LatencyP95 int64 `json:"lat_p95_ns"`
	LatencyP99 int64 `json:"lat_p99_ns"`

	// System Resources
	GoRoutines int    `json:"goroutines"`
	HeapAlloc  uint64 `json:"heap_alloc"`
	HeapSys    uint64 `json:"heap_sys"`
}

// Latency Buckets (Upper bounds in Nanoseconds)
var latencyBounds = []int64{
	100 * 1000,             // 100µs
	250 * 1000,             // 250µs
	500 * 1000,             // 500µs
	1 * 1000 * 1000,        // 1ms
	2500 * 1000,            // 2.5ms
	5 * 1000 * 1000,        // 5ms
	10 * 1000 * 1000,       // 10ms
	25 * 1000 * 1000,       // 25ms
	50 * 1000 * 1000,       // 50ms
	100 * 1000 * 1000,      // 100ms
	250 * 1000 * 1000,      // 250ms
	500 * 1000 * 1000,      // 500ms
	1000 * 1000 * 1000,     // 1s
	5 * 1000 * 1000 * 1000, // 5s
}

// MetricsCollector accumulates metrics in memory.
// It uses atomic operations for lock-free recording on the hot path.
type MetricsCollector struct {
	opsCreateInode uint64
	opsUpdateInode uint64
	opsDeleteInode uint64
	opsCommitBatch uint64

	latencyFSMTotal int64
	latencyFSMCount int64

	// Buckets: len(latencyBounds) + 1 (for overflow)
	latencyBuckets [15]uint64
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

func (mc *MetricsCollector) RecordOp(opType CommandType, duration time.Duration) {
	switch opType {
	case CmdCreateInode:
		atomic.AddUint64(&mc.opsCreateInode, 1)
	case CmdUpdateInode:
		atomic.AddUint64(&mc.opsUpdateInode, 1)
	case CmdDeleteInode:
		atomic.AddUint64(&mc.opsDeleteInode, 1)
	case CmdBatch:
		atomic.AddUint64(&mc.opsCommitBatch, 1)
	}

	d := int64(duration)
	atomic.AddInt64(&mc.latencyFSMTotal, d)
	atomic.AddInt64(&mc.latencyFSMCount, 1)

	// Determine Bucket
	bucketIdx := len(latencyBounds) // Default to overflow
	for i, bound := range latencyBounds {
		if d <= bound {
			bucketIdx = i
			break
		}
	}
	atomic.AddUint64(&mc.latencyBuckets[bucketIdx], 1)
}

// SnapshotAndReset returns the current state and resets counters to zero.
// This is not strictly atomic across all fields (a write could happen between reading CreateInode and UpdateInode),
// but sufficiently consistent for metrics.
func (mc *MetricsCollector) SnapshotAndReset() MetricSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	snap := MetricSnapshot{
		Timestamp: time.Now().UnixNano(),

		OpsCreateInode: atomic.SwapUint64(&mc.opsCreateInode, 0),
		OpsUpdateInode: atomic.SwapUint64(&mc.opsUpdateInode, 0),
		OpsDeleteInode: atomic.SwapUint64(&mc.opsDeleteInode, 0),
		OpsCommitBatch: atomic.SwapUint64(&mc.opsCommitBatch, 0),

		LatencyFSMTotal: atomic.SwapInt64(&mc.latencyFSMTotal, 0),
		LatencyFSMCount: atomic.SwapInt64(&mc.latencyFSMCount, 0),

		GoRoutines: runtime.NumGoroutine(),
		HeapAlloc:  m.Alloc,
		HeapSys:    m.Sys,
	}

	// Capture Buckets
	var buckets [15]uint64
	var totalCounts uint64
	for i := range mc.latencyBuckets {
		buckets[i] = atomic.SwapUint64(&mc.latencyBuckets[i], 0)
		totalCounts += buckets[i]
	}

	if totalCounts > 0 {
		snap.LatencyP50 = calculatePercentile(buckets, totalCounts, 0.50)
		snap.LatencyP95 = calculatePercentile(buckets, totalCounts, 0.95)
		snap.LatencyP99 = calculatePercentile(buckets, totalCounts, 0.99)
	}

	return snap
}

func calculatePercentile(buckets [15]uint64, total uint64, percentile float64) int64 {
	if total == 0 {
		return 0
	}
	target := uint64(float64(total) * percentile)
	if target == 0 && total > 0 {
		target = 1 // At least the first one
	}
	var current uint64
	for i, count := range buckets {
		current += count
		if current >= target {
			if i < len(latencyBounds) {
				return latencyBounds[i]
			}
			// Overflow bucket, return a representative "large" value or the previous bound + 1
			return latencyBounds[len(latencyBounds)-1] + 1
		}
	}
	return 0
}
