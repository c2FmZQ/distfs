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
	"io"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func createTestFSM(t *testing.T) *MetadataFSM {
	tmpDir, _ := os.MkdirTemp("", "fsm_test")
	fsm, err := NewMetadataFSM("node1", tmpDir+"/fsm.db", []byte("test-cluster-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return fsm
}

func TestFSM_AddChunkReplica_Success(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Create Inode
	inode := Inode{
		ID:   "00000000000000000000000000000001",
		Type: FileType,
		ChunkManifest: []ChunkEntry{
			{ID: "c1", Nodes: []string{"n1"}},
		},
	}
	ib, _ := json.Marshal(inode)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: ib}.Marshal()})

	// 2. Add Replica
	req := AddReplicaRequest{
		InodeID: "00000000000000000000000000000001",
		ChunkID: "c1",
		NodeIDs: []string{"n2"},
	}
	rb, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAddChunkReplica, Data: rb}.Marshal()})

	err := fsm.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm.Get(tx, []byte("inodes"), []byte("00000000000000000000000000000001"))
		var res Inode
		json.Unmarshal(v, &res)
		if len(res.ChunkManifest[0].Nodes) != 2 {
			return fmt.Errorf("AddChunkReplica failed: %+v", res)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_AddChild_Success(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	p1 := Inode{ID: "p1", Type: DirType}
	pb1, _ := json.Marshal(p1)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: pb1}.Marshal()})

	c1 := Inode{ID: "c1", Type: FileType}
	cb1, _ := json.Marshal(c1)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: cb1}.Marshal()})

	// Add path lease for file1
	lReq := LeaseRequest{
		InodeIDs:  []string{"path:p1:file1"},
		Duration:  int64(time.Hour),
		SessionID: "s1",
		Type:      LeaseExclusive,
	}
	lb, _ := json.Marshal(lReq)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAcquireLeases, Data: lb}.Marshal()})

	p1.NLink = 1
	p1.Children = map[string]string{"file1": "c1"}
	p1.Version = 2
	pb2, _ := json.Marshal(p1)

	c1.NLink = 2
	c1.Links = map[string]bool{"p1:file1": true}
	c1.Version = 2
	cb2, _ := json.Marshal(c1)

	cmds := []LogCommand{
		{Type: CmdUpdateInode, Data: cb2, SessionID: "s1"},
		{Type: CmdUpdateInode, Data: pb2, SessionID: "s1", LeaseBindings: map[string]string{"file1": "path:p1:file1"}},
	}
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdBatch, Data: json.RawMessage(LogCommand{Type: CmdBatch}.Marshal())}.Marshal()}) // Wait, recursive batching?
	// Actually, just execute them manually via applyBatchTx or similar.
	// But let's use the simplest way: fsm.Apply with a batch command.
	batch := LogCommand{
		Type:   CmdBatch,
		Data:   json.RawMessage(mustMarshal(cmds)),
		Atomic: true,
	}
	fsm.Apply(&raft.Log{Data: batch.Marshal()})

	err := fsm.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm.Get(tx, []byte("inodes"), []byte("p1"))
		var res Inode
		if err := json.Unmarshal(v, &res); err != nil {
			return fmt.Errorf("Unmarshal failed: %v, raw=%s", err, string(v))
		}
		if res.Children["file1"] != "c1" {
			return fmt.Errorf("AddChild failed: %+v", res)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_SetGroupQuota_Success(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Create Group
	g1 := Group{ID: "g1", GID: 5000, QuotaEnabled: true}
	gb1, _ := json.Marshal(g1)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateGroup, Data: gb1}.Marshal()})

	// 2. Set Quota
	req := SetGroupQuotaRequest{
		GroupID:   "g1",
		MaxInodes: ptr(uint64(100)),
		MaxBytes:  ptr(uint64(1000)),
	}
	rb, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdSetGroupQuota, Data: rb}.Marshal()})

	err := fsm.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm.Get(tx, []byte("groups"), []byte("g1"))
		var res Group
		json.Unmarshal(v, &res)
		if res.Quota.MaxInodes != 100 || res.Quota.MaxBytes != 1000 {
			return fmt.Errorf("Quota failed: %+v", res)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_SetGroupQuota_Errors(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Malformed
	res := fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdSetGroupQuota, Data: MustMarshalJSON("invalid")}.Marshal()})
	if _, ok := res.(error); !ok {
		t.Error("Expected error for malformed SetGroupQuota")
	}

	// 2. Group not found
	req := SetGroupQuotaRequest{GroupID: "missing"}
	rb, _ := json.Marshal(req)
	res = fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdSetGroupQuota, Data: rb}.Marshal()})
	if res != ErrNotFound {
		t.Errorf("Expected ErrNotFound for missing group, got %v", res)
	}
}

func TestFSM_StoreKeySync_Success(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	req := KeySyncRequest{
		UserID: "u1",
		Blob:   KeySyncBlob{KDF: "argon2", Salt: []byte("salt"), Ciphertext: []byte("ct")},
	}
	rb, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdStoreKeySync, Data: rb}.Marshal()})

	err := fsm.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm.Get(tx, []byte("keysync"), []byte("u1"))
		var res KeySyncBlob
		json.Unmarshal(v, &res)
		if res.KDF != "argon2" {
			return fmt.Errorf("KeySync failed: %+v", res)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_StoreKeySync_Errors(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Malformed
	res := fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdStoreKeySync, Data: MustMarshalJSON("invalid")}.Marshal()})
	if _, ok := res.(error); !ok {
		t.Error("Expected error for malformed StoreKeySync")
	}
}

func TestFSM_Leases_Full(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Acquire
	req := LeaseRequest{
		UserID:    "u1",
		InodeIDs:  []string{"00000000000000000000000000000001", "00000000000000000000000000000002"},
		Duration:  int64(time.Hour),
		Type:      LeaseExclusive,
		SessionID: "session1",
	}
	rb, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAcquireLeases, Data: rb}.Marshal()})

	// 2. Release
	req2 := LeaseRequest{
		UserID:    "u1",
		InodeIDs:  []string{"00000000000000000000000000000001"},
		SessionID: "session1",
	}
	rb2, _ := json.Marshal(req2)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdReleaseLeases, Data: rb2}.Marshal()})
}

func TestFSM_KeyRotation_Full(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Rotate FSM Key
	req := RotateFSMKeyRequest{
		NewKey: []byte("newsecret"),
		Gen:    2,
	}
	rb, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdRotateFSMKey, Data: rb}.Marshal()})

	// 2. Reencrypt Value
	req2 := ReencryptRequest{
		Bucket: []byte("system"),
		Key:    []byte("cluster_secret"),
	}
	rb2, _ := json.Marshal(req2)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdReencryptValue, Data: rb2}.Marshal()})
}

func TestFSM_NodeMgmt_Extra(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	node := Node{ID: "n1", Address: "http://n1:8080", RaftAddress: "127.0.0.1:9090", Status: NodeStatusActive}
	nb, _ := json.Marshal(node)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdRegisterNode, Data: nb}.Marshal()})

	// 1. ValidateNode
	if err := fsm.ValidateNode("http://n1:8080"); err != nil {
		t.Errorf("ValidateNode failed: %v", err)
	}
	if err := fsm.ValidateNode("http://missing"); err == nil {
		t.Error("ValidateNode should have failed for missing address")
	}

	// 2. GetNode
	n, err := fsm.GetNode("n1")
	if err != nil || n.Address != "http://n1:8080" {
		t.Errorf("GetNode failed: %v", err)
	}
	if _, err := fsm.GetNode("missing"); err != ErrNotFound {
		t.Errorf("GetNode should return ErrNotFound, got %v", err)
	}

	// 3. GetNodeByRaftAddress
	n2, err := fsm.GetNodeByRaftAddress("127.0.0.1:9090")
	if err != nil || n2.ID != "n1" {
		t.Errorf("GetNodeByRaftAddress failed: %v", err)
	}
}

func TestFSM_FSMKey(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	k := fsm.FSMKey()
	if len(k) != 32 {
		t.Errorf("Expected 32 byte key, got %d", len(k))
	}
}

func TestFSM_GCMgmt_Extra(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	inode := Inode{
		ID:   "00000000000000000000000000000001",
		Type: FileType,
		ChunkManifest: []ChunkEntry{
			{ID: "c1", Nodes: []string{"n1"}},
		},
	}
	ib, _ := json.Marshal(inode)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: ib}.Marshal()})

	// Acquire exclusive lease for update
	lReq := LeaseRequest{
		InodeIDs:  []string{inode.ID},
		Duration:  int64(time.Hour),
		SessionID: "s1",
		Type:      LeaseExclusive,
	}
	lb, _ := json.Marshal(lReq)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAcquireLeases, Data: lb}.Marshal()})

	// 1. enqueueGC (via UpdateInode with NLink=0)
	inode.NLink = 0
	inode.Version = 2
	ib2, _ := json.Marshal(inode)
	cmdUpdate := LogCommand{
		Type:      CmdUpdateInode,
		Data:      ib2,
		SessionID: "s1",
	}
	fsm.Apply(&raft.Log{Data: cmdUpdate.Marshal()})

	// 2. Release lease to trigger final deletion
	relReq := LeaseRequest{
		InodeIDs:  []string{inode.ID},
		SessionID: "s1",
	}
	relB, _ := json.Marshal(relReq)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdReleaseLeases, Data: relB}.Marshal()})

	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("garbage_collection"))
		v := b.Get([]byte("c1"))
		if v == nil {
			return fmt.Errorf("chunk c1 not in GC bucket")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_AdminChmod_Success(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Create Inode
	inode := Inode{ID: "00000000000000000000000000000001", Type: FileType, Mode: 0644}
	ib, _ := json.Marshal(inode)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: ib}.Marshal()})

	// 2. AdminChmod
	req := AdminChmodRequest{InodeID: "00000000000000000000000000000001", Mode: 0777}
	rb, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAdminChmod, Data: rb}.Marshal()})

	err := fsm.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm.Get(tx, []byte("inodes"), []byte("00000000000000000000000000000001"))
		var res Inode
		json.Unmarshal(v, &res)
		if res.Mode != 0775 { // 0777 sanitized to 0775
			return fmt.Errorf("AdminChmod failed: %o", res.Mode)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_GetLeases_Extra(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	id1 := "00000000000000000000000000000001"
	// 1. Acquire Lease
	req := LeaseRequest{
		UserID:    "u1",
		InodeIDs:  []string{id1},
		Duration:  int64(time.Hour),
		SessionID: "session1",
		Type:      LeaseExclusive,
	}
	rb, _ := json.Marshal(req)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdAcquireLeases, Data: rb}.Marshal()})

	// 2. GetLeases
	leases, err := fsm.GetLeases()
	if err != nil {
		t.Fatalf("GetLeases failed: %v", err)
	}
	if len(leases) != 1 || leases[0].InodeID != id1 {
		t.Errorf("GetLeases failed: %+v", leases)
	}
}

func TestFSM_SetAttr_Extra(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Create Inode
	inode := Inode{ID: "00000000000000000000000000000001", Type: FileType, Mode: 0600, OwnerID: "u1"}
	ib, _ := json.Marshal(inode)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: ib}.Marshal()})

	// 2. SetAttr via UpdateInode
	inode.NLink = 1
	inode.Mode = 0644
	inode.Version = 2
	ib2, _ := json.Marshal(inode)
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdUpdateInode, Data: ib2}.Marshal()})

	err := fsm.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm.Get(tx, []byte("inodes"), []byte("00000000000000000000000000000001"))
		var res Inode
		json.Unmarshal(v, &res)
		if res.Mode != 0644 {
			return fmt.Errorf("SetAttr failed: expected 0644, got %o", res.Mode)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

type mockSink struct {
	io.Writer
	canceled bool
	closed   bool
}

func (m *mockSink) ID() string    { return "mock" }
func (m *mockSink) Cancel() error { m.canceled = true; return nil }
func (m *mockSink) Close() error  { m.closed = true; return nil }

func TestFSM_Restore_Full(t *testing.T) {
	fsm := createTestFSM(t)
	defer fsm.Close()

	// 1. Add some data
	ib, _ := json.Marshal(Inode{ID: "00000000000000000000000000000001", Type: FileType})
	fsm.Apply(&raft.Log{Data: LogCommand{Type: CmdCreateInode, Data: ib}.Marshal()})

	// 2. Snapshot
	snap, _ := fsm.Snapshot()
	var buf bytes.Buffer
	ms := &mockSink{Writer: &buf}
	snap.Persist(ms)

	// 3. Restore into new FSM
	tmpDir2, _ := os.MkdirTemp("", "fsm_test_restore")
	fsm2, _ := NewMetadataFSM("node2", tmpDir2+"/fsm.db", []byte("test-cluster-secret"))
	defer fsm2.Close()

	err := fsm2.Restore(io.NopCloser(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// 4. Verify data
	err = fsm2.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm2.Get(tx, []byte("inodes"), []byte("00000000000000000000000000000001"))
		if v == nil {
			return fmt.Errorf("00000000000000000000000000000001 not found after restore")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}
