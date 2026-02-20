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
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

// GCWorker processes the garbage collection queue to delete unreferenced chunks.
type GCWorker struct {
	server *Server
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewGCWorker creates a new GC worker.
func NewGCWorker(s *Server) *GCWorker {
	return &GCWorker{
		server: s,
		stopCh: make(chan struct{}),
	}
}

// Start starts the background GC process.
func (g *GCWorker) Start() {
	g.wg.Add(1)
	go g.loop()
}

// Stop stops the background GC process.
func (g *GCWorker) Stop() {
	close(g.stopCh)
	g.wg.Wait()
}

func (g *GCWorker) loop() {
	defer g.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
			g.runGC()
		}
	}
}

func (g *GCWorker) runGC() {
	if g.server.raft.State() != raft.Leader {
		return
	}

	// 1. Scan for garbage
	var items map[string][]string // ChunkID -> Nodes
	err := g.server.fsm.db.View(func(tx *bolt.Tx) error {
		items = make(map[string][]string)
		count := 0
		return g.server.fsm.ForEach(tx, []byte("garbage_collection"), func(k, v []byte) error {
			var nodes []string
			if err := json.Unmarshal(v, &nodes); err == nil {
				items[string(k)] = nodes
			}
			count++
			if count > 100 { // Batch size
				return fmt.Errorf("batch_limit") // Hack to break ForEach early
			}
			return nil
		})
	})

	if err != nil && err.Error() != "batch_limit" {
		log.Printf("GC: scan error: %v", err)
		return
	}
	if len(items) == 0 {
		return
	}

	// 2. Process Deletions
	for chunkID, nodeIDs := range items {
		g.processDeletion(chunkID, nodeIDs)
	}
}

func (g *GCWorker) processDeletion(chunkID string, nodeIDs []string) {
	// Generate Admin Token
	token, err := g.server.generateSelfToken([]string{chunkID}, "D")
	if err != nil {
		log.Printf("GC: Failed to generate token: %v", err)
		return
	}

	// Resolve Nodes
	var nodes []Node
	err = g.server.fsm.db.View(func(tx *bolt.Tx) error {
		for _, nid := range nodeIDs {
			plain, err := g.server.fsm.Get(tx, []byte("nodes"), []byte(nid))
			if err != nil {
				continue
			}
			if plain != nil {
				var n Node
				if err := json.Unmarshal(plain, &n); err == nil {
					nodes = append(nodes, n)
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("GC: Failed to resolve nodes: %v\n", err)
		return
	}

	success := true
	for _, node := range nodes {
		if err := g.deleteFromNode(node.Address, chunkID, token); err != nil {
			fmt.Printf("GC: Failed to delete chunk %s from %s: %v\n", chunkID, node.ID, err)
			success = false
		}
	}

	// If successfully deleted from all known locations, remove from the persistent GC queue via Raft.
	if success {
		g.server.ApplyRaftCommandInternal(CmdGCRemove, []byte(chunkID))
	}
}

func (g *GCWorker) deleteFromNode(address, chunkID, token string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/v1/data/%s", address, chunkID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
