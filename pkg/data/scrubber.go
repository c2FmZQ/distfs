// Copyright 2026 TTBT Enterprises LLC
// ... License ...

package data

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"time"
)

// IntegrityScrubber periodically checks all chunks for corruption.
type IntegrityScrubber struct {
	store  Store
	period time.Duration
	stopCh chan struct{}
}

// NewIntegrityScrubber creates a new scrubber that runs at the specified period.
func NewIntegrityScrubber(store Store, period time.Duration) *IntegrityScrubber {
	return &IntegrityScrubber{
		store:  store,
		period: period,
		stopCh: make(chan struct{}),
	}
}

// Start starts the background scrubbing process.
func (s *IntegrityScrubber) Start() {
	go s.loop()
}

// Stop stops the background scrubbing process.
func (s *IntegrityScrubber) Stop() {
	close(s.stopCh)
}

func (s *IntegrityScrubber) loop() {
	ticker := time.NewTicker(s.period)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scrub()
		}
	}
}

func (s *IntegrityScrubber) scrub() {
	// Go 1.23 Iterator loop
	for id, err := range s.store.ListChunks() {
		// Responsive shutdown
		select {
		case <-s.stopCh:
			return
		default:
		}

		if err != nil {
			log.Printf("Scrubber: list error: %v", err)
			continue // WalkDir might return error but continue? Or stop?
			// My ListChunks implementation yields error at end usually if WalkDir fails.
			// But let's log and continue.
		}

		// If ID is empty (error case yielded empty string), skip.
		if id == "" {
			continue
		}

		if err := s.verifyChunk(id); err != nil {
			log.Printf("CORRUPTION DETECTED: Chunk %s: %v", id, err)
			// TODO: Quarantine or report to leader
		}
	}
}

func (s *IntegrityScrubber) verifyChunk(id string) error {
	rc, err := s.store.ReadChunk(id)
	if err != nil {
		return err
	}
	defer rc.Close()

	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return err
	}

	sum := hex.EncodeToString(h.Sum(nil))
	if sum != id {
		return fmt.Errorf("hash mismatch: expected %s, got %s", id, sum)
	}
	return nil
}
