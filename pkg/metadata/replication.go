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
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

type ReplicationMonitor struct {
	server *Server
	stopCh chan struct{}
	wg     sync.WaitGroup
	sem    chan struct{} // Limit concurrent repairs
}

func NewReplicationMonitor(s *Server) *ReplicationMonitor {
	return &ReplicationMonitor{
		server: s,
		stopCh: make(chan struct{}),
		sem:    make(chan struct{}, 10), // Max 10 concurrent repairs
	}
}

func (rm *ReplicationMonitor) Start() {
	rm.wg.Add(1)
	go rm.loop()
}

func (rm *ReplicationMonitor) Stop() {
	close(rm.stopCh)
	rm.wg.Wait()
}

func (rm *ReplicationMonitor) loop() {
	defer rm.wg.Done()
	// Run every minute (TBD)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rm.stopCh:
			return
		case <-ticker.C:
			rm.Scan()
		}
	}
}

func (rm *ReplicationMonitor) Scan() {
	if rm.server.raft.State() != raft.Leader {
		return
	}

	// 1. Get Active Nodes
	activeNodes := make(map[string]Node)
	var activeNodeIDs []string
	err := rm.server.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err != nil {
				continue
			}
			if n.Status == NodeStatusActive && time.Since(time.Unix(n.LastHeartbeat, 0)) < 5*time.Minute {
				activeNodes[n.ID] = n
				activeNodeIDs = append(activeNodeIDs, n.ID)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("ReplicationMonitor: failed to list nodes: %v", err)
		return
	}

	if len(activeNodeIDs) < 2 {
		// Need at least 2 nodes to replicate if one is missing?
		// Or if we have 1 node and want 3, we can't do much if only 1 is active.
		return
	}

	// 2. Scan Inodes
	// Iterate efficiently? accessing bolt bucket directly.
	err = rm.server.fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		return b.ForEach(func(k, v []byte) error {
			// Check for stop
			select {
			case <-rm.stopCh:
				return fmt.Errorf("stopped")
			default:
			}

			var inode Inode
			if err := json.Unmarshal(v, &inode); err != nil {
				return nil // skip corrupt
			}

			if inode.Type == DirType {
				return nil
			}

			rm.checkReplication(&inode, activeNodes, activeNodeIDs)
			return nil
		})
	})
	if err != nil {
		log.Printf("ReplicationMonitor: scan error: %v", err)
	}
}

func (rm *ReplicationMonitor) checkReplication(inode *Inode, activeNodes map[string]Node, activeNodeIDs []string) {
	for _, chunk := range inode.ChunkManifest {
		validReplicas := 0
		var sourceNode Node
		foundSource := false
		existingHolders := make(map[string]bool)

		for _, nodeID := range chunk.Nodes {
			existingHolders[nodeID] = true
			if n, ok := activeNodes[nodeID]; ok {
				validReplicas++
				if !foundSource {
					sourceNode = n
					foundSource = true
				}
			}
		}

		if validReplicas < 3 && foundSource {
			// Need repair
			needed := 3 - validReplicas
			var targets []string

			// Find candidates efficiently
			// We need 'needed' unique nodes from activeNodeIDs that are NOT in existingHolders.
			// Random selection.
			
			// Copy activeNodeIDs to candidates to avoid modifying original?
			// No, assume we can just pick random.
			// Simple attempt: try 10 times to pick random.
			// Or full scan if activeNodeIDs is small.
			// If activeNodeIDs is large, random is better.
			// Let's do a simple shuffle of indices if small, or random pick if large.
			// For simplicity and correctness: iterate all active nodes (random offset?)
			
			startIndex := rand.Intn(len(activeNodeIDs))
			for i := 0; i < len(activeNodeIDs); i++ {
				idx := (startIndex + i) % len(activeNodeIDs)
				candidateID := activeNodeIDs[idx]
				
				if len(targets) >= needed {
					break
				}
				if !existingHolders[candidateID] {
					targets = append(targets, candidateID)
				}
			}

			if len(targets) > 0 {
				// Launch repair in background with semaphore
				select {
				case rm.sem <- struct{}{}:
					go func(inodeID, chunkID string, src Node, tgts []string) {
						defer func() { <-rm.sem }()
						rm.executeRepair(inodeID, chunkID, src, tgts, activeNodes)
					}(inode.ID, chunk.ID, sourceNode, targets)
				default:
					// Semaphore full, skip this repair cycle
				}
			}
		}
	}
}

func (rm *ReplicationMonitor) triggerRepair(chunkID string, source Node, targetIDs []string, nodes map[string]Node) error {
	// Construct targets URL list
	var targetURLs []string
	for _, id := range targetIDs {
		if n, ok := nodes[id]; ok {
			targetURLs = append(targetURLs, n.Address)
		}
	}

	reqBody := map[string]interface{}{
		"targets": targetURLs,
	}
	body, _ := json.Marshal(reqBody)

	resp, err := http.Post(source.Address+"/v1/data/"+chunkID+"/replicate", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (rm *ReplicationMonitor) executeRepair(inodeID, chunkID string, source Node, targetIDs []string, nodes map[string]Node) {
	// 1. Trigger
	if err := rm.triggerRepair(chunkID, source, targetIDs, nodes); err != nil {
		log.Printf("Repair failed for chunk %s: %v", chunkID, err)
		return
	}

	// 2. Update Metadata (Atomic Add)
	req := AddReplicaRequest{
		InodeID: inodeID,
		ChunkID: chunkID,
		NodeIDs: targetIDs,
	}
	body, _ := json.Marshal(req)
	
	cmd := LogCommand{Type: CmdAddChunkReplica, Data: body}
	b, _ := json.Marshal(cmd)
	
	// Fire and forget (eventual consistency) or wait?
	// We are in background. Wait is fine.
	f := rm.server.raft.Apply(b, 5*time.Second)
	if err := f.Error(); err != nil {
		log.Printf("Failed to apply AddReplica: %v", err)
	}
}