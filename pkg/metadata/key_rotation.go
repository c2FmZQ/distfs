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
	"encoding/json"
	"fmt"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
)

// KeyRotationWorker periodically rotates the cluster encryption keys (Epoch Keys).
type KeyRotationWorker struct {
	server   *Server
	stopChan chan struct{}
	interval time.Duration
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

	// Initial check
	w.checkAndRotate()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			w.checkAndRotate()
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

	active, err := w.server.fsm.GetActiveKey()
	if err == ErrNotFound {
		w.rotate()
		return
	} else if err != nil {
		return
	}

	if time.Since(time.Unix(active.CreatedAt, 0)) > w.interval {
		w.rotate()
	}
}

func (w *KeyRotationWorker) rotate() {
	key, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return
	}

	clusterKey := ClusterKey{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		EncKey:    key.EncapsulationKey().Bytes(),
		DecKey:    key.Bytes(),
		CreatedAt: time.Now().Unix(),
	}

	data, _ := json.Marshal(clusterKey)
	cmd := LogCommand{Type: CmdRotateKey, Data: data}
	b, _ := json.Marshal(cmd)
	w.server.raft.Apply(b, 5*time.Second)
}
