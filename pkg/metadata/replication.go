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
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/logger"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

// ReplicationMonitor periodically scans for under-replicated chunks and initiates repair.
type ReplicationMonitor struct {
	server *Server
	stopCh chan struct{}
	wg     sync.WaitGroup
	sem    chan struct{} // Limit concurrent repairs
}

// NewReplicationMonitor creates a new replication monitor.
func NewReplicationMonitor(s *Server) *ReplicationMonitor {
	return &ReplicationMonitor{
		server: s,
		stopCh: make(chan struct{}),
		sem:    make(chan struct{}, 10), // Max 10 concurrent repairs
	}
}

// Start starts the background monitor.
func (rm *ReplicationMonitor) Start() {
	rm.wg.Add(1)
	go rm.loop()
}

// Stop stops the background monitor.
func (rm *ReplicationMonitor) Stop() {
	select {
	case <-rm.stopCh:
	default:
		close(rm.stopCh)
	}
	rm.wg.Wait()
}

func (rm *ReplicationMonitor) loop() {
	defer rm.wg.Done()
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

// Scan performs a full scan of all inodes to detect under-replicated chunks.
func (rm *ReplicationMonitor) Scan() {
	logger.Debugf("REPL: Starting manual scan (Leader=%v)", rm.server.raft.State() == raft.Leader)
	if rm.server.raft.State() != raft.Leader {
		return
	}

	// 1. Get Active Nodes
	activeNodes := make(map[string]Node)
	var activeNodeIDs []string
	err := rm.server.fsm.db.View(func(tx *bolt.Tx) error {
		return rm.server.fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err != nil {
				return nil // Skip corrupt
			}
			age := time.Since(time.Unix(n.LastHeartbeat, 0))
			logger.Debugf("REPL Scan: checking node %s status=%s age=%v", n.ID, n.Status, age)
			if n.Status == NodeStatusActive && age < 15*time.Minute {
				activeNodes[n.ID] = n
				activeNodeIDs = append(activeNodeIDs, n.ID)
				logger.Debugf("REPL Scan: node %s is ACTIVE", n.ID)
			} else {
				logger.Debugf("REPL Scan: node %s is NOT active (status=%s, age=%v)", n.ID, n.Status, age)
			}
			return nil
		})
	})
	if err != nil {
		log.Printf("ReplicationMonitor: failed to list nodes: %v", err)
		return
	}

	if len(activeNodeIDs) < 2 {
		return
	}

	logger.Debugf("REPL: activeNodes=%v", activeNodeIDs)

	// 2. Scan Inodes
	err = rm.server.fsm.db.View(func(tx *bolt.Tx) error {
		return rm.server.fsm.ForEach(tx, []byte("inodes"), func(k, v []byte) error {
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

const TargetReplication = 3

func (rm *ReplicationMonitor) checkReplication(inode *Inode, activeNodes map[string]Node, activeNodeIDs []string) {
	for _, chunk := range inode.ChunkManifest {
		validReplicas := 0
		var sourceNode Node
		foundSource := false
		existingHolders := make(map[string]bool)
		var healthyNodeIDs []string
		var deadNodeIDs []string

		for _, nodeID := range chunk.Nodes {
			existingHolders[nodeID] = true
			if n, ok := activeNodes[nodeID]; ok {
				validReplicas++
				healthyNodeIDs = append(healthyNodeIDs, nodeID)
				if !foundSource {
					sourceNode = n
					foundSource = true
				}
			} else {
				deadNodeIDs = append(deadNodeIDs, nodeID)
			}
		}

		// Calculate actual target for this cluster size
		target := TargetReplication
		if len(activeNodeIDs) < target {
			target = len(activeNodeIDs)
		}

		logger.Debugf("REPL: Inode %s Chunk %s: valid=%d healthy=%v dead=%v target=%d sourceFound=%v", inode.ID, chunk.ID, validReplicas, healthyNodeIDs, deadNodeIDs, target, foundSource)

		// 1. Repair if under-replicated
		if validReplicas < target && foundSource {
			// ... (rest of repair logic)
			needed := target - validReplicas
			var targets []string

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
				select {
				case rm.sem <- struct{}{}:
					go func(inodeID, chunkID string, src Node, tgts []string) {
						defer func() { <-rm.sem }()
						rm.executeRepair(inodeID, chunkID, src, tgts, activeNodes)
					}(inode.ID, chunk.ID, sourceNode, targets)
				default:
				}
			}
		}

		// 2. Prune if over-replicated OR contains dead nodes
		var toRemove []string
		if validReplicas > TargetReplication {
			toRemove = append(toRemove, healthyNodeIDs[TargetReplication:]...)
		}
		if len(deadNodeIDs) > 0 {
			toRemove = append(toRemove, deadNodeIDs...)
		}

		if len(toRemove) > 0 {
			select {
			case rm.sem <- struct{}{}:
				go func(inodeID, chunkID string, remIDs []string) {
					defer func() { <-rm.sem }()
					rm.executePrune(inodeID, chunkID, remIDs, activeNodes)
				}(inode.ID, chunk.ID, toRemove)
			default:
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

	req, err := http.NewRequest("POST", source.Address+"/v1/data/"+chunkID+"/replicate", bytes.NewReader(body))
	if err != nil {
		return err
	}

	// Add Auth Token (System Token)
	token, err := rm.server.generateSelfToken([]string{chunkID}, "RW")
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
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
	logger.Debugf("REPL: Repairing chunk %s for inode %s: source=%s targets=%v", chunkID, inodeID, source.ID, targetIDs)
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

	f := rm.server.raft.Apply(b, 5*time.Second)
	if err := f.Error(); err != nil {
		log.Printf("Failed to apply AddReplica: %v", err)
	} else {
		logger.Debugf("REPL: Successfully applied AddReplica for chunk %s", chunkID)
	}
}

func (rm *ReplicationMonitor) executePrune(inodeID, chunkID string, targetIDs []string, nodes map[string]Node) {
	// 1. Trigger deletion from data nodes (best effort)
	token, err := rm.server.generateSelfToken([]string{chunkID}, "D")
	if err == nil {
		for _, nid := range targetIDs {
			if n, ok := nodes[nid]; ok {
				if err := rm.deleteFromNode(n.Address, chunkID, token); err != nil {
					log.Printf("Prune: failed to delete chunk %s from active node %s: %v", chunkID, nid, err)
				}
			}
		}
	} else {
		log.Printf("Prune: failed to generate token for deletion: %v", err)
	}

	// 2. Update Metadata (Atomic Remove) - ALWAYS do this for all targetIDs
	req := AddReplicaRequest{
		InodeID: inodeID,
		ChunkID: chunkID,
		NodeIDs: targetIDs,
	}
	body, _ := json.Marshal(req)

	cmd := LogCommand{Type: CmdRemoveChunkReplica, Data: body}
	b, _ := json.Marshal(cmd)

	f := rm.server.raft.Apply(b, 5*time.Second)
	if err := f.Error(); err != nil {
		log.Printf("Failed to apply RemoveReplica: %v", err)
	} else {
		logger.Debugf("REPL: Successfully applied RemoveReplica for chunk %s (nodes=%v)", chunkID, targetIDs)
	}
}

func (rm *ReplicationMonitor) deleteFromNode(address, chunkID, token string) error {
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
