//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metadata

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

// KeyRotationWorker periodically rotates the cluster encryption keys (Epoch Keys).
type KeyRotationWorker struct {
	server   *Server
	stopChan chan struct{}
	interval time.Duration

	// Progress tracking for background scanning
	lastKeys map[string][]byte

	rotating   bool
	rotatingMu sync.Mutex
}

// NewKeyRotationWorker creates a new key rotation worker.
func NewKeyRotationWorker(s *Server) *KeyRotationWorker {
	interval := s.keyRotationInterval
	if interval == 0 {
		interval = 24 * time.Hour
	}
	return &KeyRotationWorker{
		server:   s,
		stopChan: make(chan struct{}),
		interval: interval,
		lastKeys: make(map[string][]byte),
	}
}

// Start starts the rotation worker.
func (w *KeyRotationWorker) Start() {
	go w.run()
}

// Stop stops the rotation worker.
func (w *KeyRotationWorker) Stop() {
	close(w.stopChan)
}

func (w *KeyRotationWorker) run() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	reencryptTicker := time.NewTicker(10 * time.Second)
	defer reencryptTicker.Stop()

	// Initial check
	w.checkAndRotate()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			w.checkAndRotate()
		case <-reencryptTicker.C:
			if w.server.raft.State() == raft.Leader {
				w.reencryptSlowly()
			}
		}
	}
}

func (w *KeyRotationWorker) checkAndRotate() {
	if w.interval < 0 {
		return
	}
	if w.server.raft.State() != raft.Leader {
		return
	}

	// 1. Epoch Keys
	active, err := w.server.fsm.GetActiveKey()
	if err == ErrNotFound {
		w.rotate()
	} else if err == nil {
		if time.Since(time.Unix(active.CreatedAt, 0)) > w.interval {
			w.rotate()
		}
	}

	// 2. FSM Keys (e.g. rotate every 30 days if not otherwise specified)
	// For now, we only rotate FSM key if explicitly triggered or if we want to
	// implement automatic rotation here too.
}

func (w *KeyRotationWorker) reencryptSlowly() {
	buckets := [][]byte{
		[]byte("inodes"),
		[]byte("users"),
		[]byte("groups"),
		[]byte("keysync"),
		[]byte("admins"),
	}

	_, activeGen := w.server.fsm.keyRing.Current()

	for _, bucket := range buckets {
		var candidates [][]byte
		var lastKey []byte
		finished := false

		err := w.server.fsm.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucket)
			if b == nil {
				return nil
			}
			c := b.Cursor()
			count := 0

			// Start from the last scanned key
			startK := w.lastKeys[string(bucket)]
			for k, v := c.Seek(startK); k != nil; k, v = c.Next() {
				count++
				if count > 1000 {
					lastKey = k
					return nil // Pause scan for this bucket
				}
				if len(v) < 4 {
					continue
				}
				gen := binary.BigEndian.Uint32(v[:4])
				if gen != activeGen {
					candidates = append(candidates, append([]byte{}, k...))
					if len(candidates) >= 50 { // Limit candidates per tick
						lastKey = k
						return nil
					}
				}
			}
			finished = true
			return nil
		})

		if err != nil {
			continue
		}

		// Process candidates found in this bucket
		if len(candidates) > 0 {
			for _, k := range candidates {
				w.reencryptRecord(bucket, k)
			}
		}

		if finished {
			delete(w.lastKeys, string(bucket))
		} else if lastKey != nil {
			w.lastKeys[string(bucket)] = lastKey
			break // Limit to one bucket scan per tick if paused
		}
	}
}

func (w *KeyRotationWorker) reencryptRecord(bucket, key []byte) {
	req := ReencryptRequest{
		Bucket: bucket,
		Key:    key,
	}
	data, _ := json.Marshal(req)
	// Use background context for system tasks
	w.server.ApplyRaftCommandInternal(CmdReencryptValue, data, "")
}

func (w *KeyRotationWorker) rotate() {
	w.rotatingMu.Lock()
	if w.rotating {
		w.rotatingMu.Unlock()
		return
	}
	w.rotating = true
	w.rotatingMu.Unlock()

	defer func() {
		w.rotatingMu.Lock()
		w.rotating = false
		w.rotatingMu.Unlock()
	}()

	key, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return
	}

	id := fmt.Sprintf("%d", time.Now().UnixNano())

	// Phase 53.1: Store private key in-memory only.
	w.server.RegisterEpochKey(id, key)

	clusterKey := ClusterKey{
		ID:        id,
		EncKey:    key.EncapsulationKey().Bytes(),
		DecKey:    nil, // DO NOT store private key in Raft/FSM
		CreatedAt: time.Now().Unix(),
	}

	data, _ := json.Marshal(clusterKey)
	cmd := LogCommand{Type: CmdRotateKey, Data: data}
	b, _ := json.Marshal(cmd)
	w.server.raft.Apply(b, 5*time.Second)
}
