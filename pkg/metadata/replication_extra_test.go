// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"encoding/json"
	"testing"
)

func TestReplication_Misc(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	
	// 1. Force Scan
	server.ForceReplicationScan()
	
	// 2. Stop Monitor
	server.replMonitor.Stop()
}

func TestGC_Misc(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	
	// 1. Force Scan
	server.ForceGCScan()
	
	// 2. Stop Worker
	server.gcWorker.Stop()
}

func TestReplication_Scan_Types(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Directory (should be skipped)
	d := Inode{ID: "dir1", Type: DirType, OwnerID: "u1"}
	db, _ := json.Marshal(d)
	server.ApplyRaftCommandInternal(CmdCreateInode, db)

	// 2. Symlink (should be skipped)
	s := Inode{ID: "sym1", Type: SymlinkType, OwnerID: "u1"}
	sb, _ := json.Marshal(s)
	server.ApplyRaftCommandInternal(CmdCreateInode, sb)

	// 3. Empty file (should be skipped)
	f := Inode{ID: "empty", Type: FileType, OwnerID: "u1"}
	fb, _ := json.Marshal(f)
	server.ApplyRaftCommandInternal(CmdCreateInode, fb)

	server.replMonitor.Scan()
}

func TestReplication_Repair_Fail(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Trigger executeRepair with failing source node
	source := Node{ID: "n1", Address: "http://invalid"}
	nodes := map[string]Node{"n2": {ID: "n2", Address: "http://n2"}}
	server.replMonitor.executeRepair("f1", "c1", source, []string{"n2"}, nodes)
	// Should log failure and return
}

func TestReplication_Repair_RaftFail(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	// Don't defer shutdown yet
	
	source := Node{ID: "n1", Address: ts.URL} // Valid URL but Raft will be gone
	nodes := map[string]Node{"n2": {ID: "n2", Address: "http://n2"}}
	
	// Shutdown Raft to force Apply failure
	node.Raft.Shutdown().Error()
	
	server.replMonitor.executeRepair("f1", "c1", source, []string{"n2"}, nodes)
	// Should log "Failed to apply AddReplica"
	ts.Close()
}

func TestGC_DeleteFail(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// 1. Manually add a fake node that will fail
	nodeInfo := Node{ID: "fail-node", Address: "http://invalid", Status: NodeStatusActive}
	nb, _ := json.Marshal(nodeInfo)
	server.ApplyRaftCommandInternal(CmdRegisterNode, nb)

	// 2. Trigger processDeletion
	server.gcWorker.processDeletion("chunk1", []string{"fail-node"})
	// Should log error and continue
}

func TestKeyRotation_Misc(t *testing.T) {
	node, ts, _, _, server := SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	
	// 1. Trigger Rotation branch
	server.keyWorker.checkAndRotate()
	
	// 2. Stop Worker
	server.keyWorker.Stop()
}

func TestMetrics_CalculatePercentile(t *testing.T) {
	// Empty samples
	var emptyBuckets [15]uint64
	p := calculatePercentile(emptyBuckets, 0, 95)
	if p != 0 {
		t.Errorf("Expected 0 for 0 total, got %v", p)
	}
	
	// Single sample in first bucket
	buckets := [15]uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	p = calculatePercentile(buckets, 1, 0.50)
	if p != latencyBounds[0] {
		t.Errorf("Expected %d, got %d", latencyBounds[0], p)
	}

	// Sample in overflow bucket
	bucketsOverflow := [15]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	p = calculatePercentile(bucketsOverflow, 1, 0.99)
	if p <= latencyBounds[len(latencyBounds)-1] {
		t.Errorf("Expected value > %d, got %d", latencyBounds[len(latencyBounds)-1], p)
	}
}
