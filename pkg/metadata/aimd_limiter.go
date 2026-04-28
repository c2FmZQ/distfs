// Copyright 2026 The DistFS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metadata

import (
	"log"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConcurrencyLimiter implements an Adaptive Concurrency Limit (ACL) using AIMD.
// It monitors request latency and dynamically adjusts the maximum number of
// concurrent requests permitted to ensure the server remains responsive.
type ConcurrencyLimiter struct {
	mu sync.Mutex

	// Configuration
	minLimit       int32
	maxLimit       int32
	latencyTarget  time.Duration
	decreaseFactor float64

	// State
	currentLimit      int32
	inFlight          int32
	lastAdjustedNanos int64
	latencies         []time.Duration
	latencyIndex      int
	windowSize        int
}

// NewConcurrencyLimiter initializes a new AIMD limiter.
func NewConcurrencyLimiter(min, max int32, target time.Duration) *ConcurrencyLimiter {
	windowSize := 100
	return &ConcurrencyLimiter{
		minLimit:          min,
		maxLimit:          max,
		currentLimit:      max, // Start at max, let it degrade
		latencyTarget:     target,
		decreaseFactor:    0.5,
		lastAdjustedNanos: time.Now().UnixNano(),
		latencies:         make([]time.Duration, windowSize),
		windowSize:        windowSize,
	}
}

// Wrap returns an http.Handler that enforces the concurrency limit.
func (l *ConcurrencyLimiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := atomic.LoadInt32(&l.currentLimit)
		inFlight := atomic.AddInt32(&l.inFlight, 1)
		defer atomic.AddInt32(&l.inFlight, -1)

		if inFlight > limit {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Too Many Requests: Adaptive Concurrency Limit Exceeded\n"))
			return
		}

		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)

		l.recordLatency(duration)
	})
}

func (l *ConcurrencyLimiter) recordLatency(d time.Duration) {
	// Optimization: Check if we need to adjust before acquiring the lock
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&l.lastAdjustedNanos)
	if now-last < int64(time.Second) {
		// Just record latency if we're in the same window (best effort under lock)
		l.mu.Lock()
		l.latencies[l.latencyIndex] = d
		l.latencyIndex = (l.latencyIndex + 1) % l.windowSize
		l.mu.Unlock()
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.latencies[l.latencyIndex] = d
	l.latencyIndex = (l.latencyIndex + 1) % l.windowSize

	// Re-check under lock
	if now-l.lastAdjustedNanos < int64(time.Second) {
		return
	}

	// Calculate P95 latency
	var samples []time.Duration
	for _, lat := range l.latencies {
		if lat > 0 {
			samples = append(samples, lat)
		}
	}

	if len(samples) < 10 {
		return // Not enough data
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p95 := samples[int(float64(len(samples))*0.95)]

	oldLimit := atomic.LoadInt32(&l.currentLimit)
	newLimit := oldLimit
	if p95 > l.latencyTarget {
		// Multiplicative Decrease
		newLimit = int32(float64(oldLimit) * l.decreaseFactor)
		if newLimit < l.minLimit {
			newLimit = l.minLimit
		}
	} else {
		// Additive Increase
		if oldLimit < l.maxLimit {
			newLimit = oldLimit + 1
		}
	}

	if oldLimit != newLimit {
		atomic.StoreInt32(&l.currentLimit, newLimit)
		log.Printf("ACL: Latency P95=%v (Target=%v), adjusting concurrency limit: %d -> %d", p95, l.latencyTarget, oldLimit, newLimit)
	}
	atomic.StoreInt64(&l.lastAdjustedNanos, now)
}

