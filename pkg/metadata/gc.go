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
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

type GCWorker struct {
	server *Server
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewGCWorker(s *Server) *GCWorker {
	return &GCWorker{
		server: s,
		stopCh: make(chan struct{}),
	}
}

func (g *GCWorker) Start() {
	g.wg.Add(1)
	go g.loop()
}

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
		b := tx.Bucket([]byte("garbage_collection"))
		c := b.Cursor()
		items = make(map[string][]string)
		count := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var nodes []string
			if err := json.Unmarshal(v, &nodes); err == nil {
				items[string(k)] = nodes
			}
			count++
			if count > 100 { // Batch size
				break
			}
		}
		return nil
	})

	if err != nil || len(items) == 0 {
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
		fmt.Printf("GC: Failed to generate token: %v\n", err)
		return
	}

	// Resolve Nodes
	var nodes []Node
	err = g.server.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		for _, nid := range nodeIDs {
			v := b.Get([]byte(nid))
			if v != nil {
				var n Node
				if err := json.Unmarshal(v, &n); err == nil {
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

	// If successfully deleted from all known locations (or best effort), remove from GC queue
	// We might want to keep it if deletion failed, but if node is dead, we might be stuck.
	// For now, if at least one deletion succeeded or nodes are gone, we remove?
	// Design decision: If a node is unreachable, we keep it in queue?
	// Ideally yes. But for simplicity in Phase 10, we remove if we attempted.
	// Real-world: Separate "failed" queue or retry count.
	
	if success {
		// Remove from DB via Raft (Wait, GC table is part of FSM state!)
		// We shouldn't modify DB directly in worker. We must apply a Command.
		// But we don't have a CmdDeleteGC.
		// `CmdDeleteInode` triggers GC enqueue.
		// We need `CmdGCRemove` or similar.
		// Or we can just use `db.Update`?
		// NO! Only FSM.Apply can modify DB if we want consistency across followers.
		// However, GC queue is internal state. Does it need to be replicated?
		// Yes, if leader fails, new leader needs to know what to GC.
		// So we need a new Raft command: CmdGCRemove.
		g.server.applyCommandRaw(nil, CmdGCRemove, []byte(chunkID), 0)
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
