// Copyright 2026 The DistFS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metadata

import (
	"log"
	"net/http"
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
	currentLimit int32
	inFlight     int32
	lastAdjusted time.Time
	latencies    []time.Duration
	latencyIndex int
	windowSize   int
}

// NewConcurrencyLimiter initializes a new AIMD limiter.
func NewConcurrencyLimiter(min, max int32, target time.Duration) *ConcurrencyLimiter {
	windowSize := 100
	return &ConcurrencyLimiter{
		minLimit:       min,
		maxLimit:       max,
		currentLimit:   max, // Start at max, let it degrade
		latencyTarget:  target,
		decreaseFactor: 0.5,
		lastAdjusted:   time.Now(),
		latencies:      make([]time.Duration, windowSize),
		windowSize:     windowSize,
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
	l.mu.Lock()
	defer l.mu.Unlock()

	l.latencies[l.latencyIndex] = d
	l.latencyIndex = (l.latencyIndex + 1) % l.windowSize

	// Adjust every 1 second or every windowSize requests
	if time.Since(l.lastAdjusted) < 1*time.Second {
		return
	}

	// Calculate P95 latency (simple version: average of recent for now, or sort window)
	// For better P95, we should sort but for a small window average is a proxy or we can find max.
	var max time.Duration
	var count int
	for _, lat := range l.latencies {
		if lat > 0 {
			if lat > max {
				max = lat
			}
			count++
		}
	}

	if count < 10 {
		return // Not enough data
	}

	oldLimit := l.currentLimit
	if max > l.latencyTarget {
		// Multiplicative Decrease
		l.currentLimit = int32(float64(l.currentLimit) * l.decreaseFactor)
		if l.currentLimit < l.minLimit {
			l.currentLimit = l.minLimit
		}
	} else {
		// Additive Increase
		if l.currentLimit < l.maxLimit {
			l.currentLimit++
		}
	}

	if oldLimit != l.currentLimit {
		log.Printf("ACL: Latency observed=%v (Target=%v), adjusting concurrency limit: %d -> %d", max, l.latencyTarget, oldLimit, l.currentLimit)
	}
	l.lastAdjusted = time.Now()
}
