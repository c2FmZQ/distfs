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
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

func setupCluster(t *testing.T) (*RaftNode, *httptest.Server) {
	tmpDir := t.TempDir()
	key := make([]byte, 32)
	nodeKey, _ := crypto.GenerateIdentityKey()

	node, err := NewRaftNode("node1", "127.0.0.1:0", "", tmpDir, key, nodeKey)
	if err != nil {
		t.Fatalf("NewRaftNode failed: %v", err)
	}

	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:      raft.ServerID("node1"),
				Address: node.Transport.LocalAddr(),
			},
		},
	}
	f := node.Raft.BootstrapCluster(cfg)
	if err := f.Error(); err != nil {
		node.Shutdown()
		t.Fatalf("Bootstrap failed: %v", err)
	}

	leader := false
	for i := 0; i < 50; i++ {
		if node.Raft.State() == raft.Leader {
			leader = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !leader {
		node.Shutdown()
		t.Fatalf("Node did not become leader")
	}

	server := NewServer(node.Raft, node.FSM, "", nil, nil, "")
	ts := httptest.NewServer(server)
	return node, ts
}

func TestMetadataCluster(t *testing.T) {
	node, ts := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Test Create Inode
	inode := Inode{
		ID:      "inode-1",
		OwnerID: "user-1",
		Type:    FileType,
	}
	body, _ := json.Marshal(inode)

	resp, err := http.Post(ts.URL+"/v1/meta/inode", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("POST status %d: %s", resp.StatusCode, body)
	}

	// Test Get Inode
	resp, err = http.Get(ts.URL + "/v1/meta/inode/inode-1")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status %d", resp.StatusCode)
	}

	var got Inode
	json.NewDecoder(resp.Body).Decode(&got)
	if got.ID != "inode-1" {
		t.Errorf("GET ID mismatch")
	}

	// Test Delete Inode
	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/meta/inode/inode-1", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE status %d", resp.StatusCode)
	}

	// Verify Deleted
	resp, err = http.Get(ts.URL + "/v1/meta/inode/inode-1")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestIdentityRegistry(t *testing.T) {
	node, ts := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Create User
	user := User{ID: "u1", Name: "Alice"}
	body, _ := json.Marshal(user)
	resp, err := http.Post(ts.URL+"/v1/user", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("User Create failed: %d", resp.StatusCode)
	}

	// Create Group
	group := Group{ID: "g1", OwnerID: "u1"}
	body, _ = json.Marshal(group)
	resp, err = http.Post(ts.URL+"/v1/group", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Group Create failed: %d", resp.StatusCode)
	}

	// Register Node
	n := Node{ID: "node-data-1", Status: NodeStatusActive}
	body, _ = json.Marshal(n)
	resp, err = http.Post(ts.URL+"/v1/node", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Node Register failed: %d", resp.StatusCode)
	}
}

func TestFSMRestore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "fsm.bolt")
	fsm, err := NewMetadataFSM(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer fsm.Close()

	inode := Inode{ID: "restore-test"}
	data, _ := json.Marshal(inode)
	resp := fsm.applyCreateInode(data)
	if err, ok := resp.(error); ok {
		t.Fatalf("applyCreateInode failed: %v", err)
	}

	// Snapshot
	snap, _ := fsm.Snapshot()
	var buf bytes.Buffer
	sink := &MockSink{buf: &buf}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// New FSM
	fsm2, err := NewMetadataFSM(filepath.Join(tmpDir, "fsm2.bolt"))
	if err != nil {
		t.Fatal(err)
	}
	defer fsm2.Close()

	// Restore
	if err := fsm2.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify fsm2 has data
	err = fsm2.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte("restore-test"))
		if v == nil {
			return fmt.Errorf("key not found")
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestFSM_Errors(t *testing.T) {
	tmpDir := t.TempDir()
	fsm, _ := NewMetadataFSM(filepath.Join(tmpDir, "fsm.bolt"))
	defer fsm.Close()

	// Invalid JSON
	l := &raft.Log{Data: []byte(`{bad`)}
	if err := fsm.Apply(l); err == nil {
		t.Error("Expected error on invalid json")
	}

	// Unknown Command
	cmd := LogCommand{Type: 99}
	b, _ := json.Marshal(cmd)
	l = &raft.Log{Data: b}
	resp := fsm.Apply(l)
	if resp == nil {
		t.Error("Expected error on unknown command")
	} else if err, ok := resp.(error); !ok || err.Error() != "unknown command" {
		t.Errorf("Expected 'unknown command', got %v", resp)
	}
}

type MockSink struct {
	buf *bytes.Buffer
}

func (m *MockSink) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m *MockSink) Close() error                { return nil }
func (m *MockSink) ID() string                  { return "mock" }
func (m *MockSink) Cancel() error               { return nil }

func TestChunkPagination(t *testing.T) {
	node, ts := setupCluster(t)
	defer node.Shutdown()
	defer ts.Close()

	// Create Inode with many chunks
	chunkCount := ChunkPageSize + 50 // 1050
	manifest := make([]ChunkEntry, chunkCount)
	for i := 0; i < chunkCount; i++ {
		manifest[i] = ChunkEntry{ID: fmt.Sprintf("chunk-%d", i), Nodes: []string{"n1"}}
	}

	inode := Inode{
		ID:            "paginated-file",
		Type:          FileType,
		ChunkManifest: manifest,
	}
	body, _ := json.Marshal(inode)

	// POST /v1/meta/inode
	resp, err := http.Post(ts.URL+"/v1/meta/inode", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST status %d", resp.StatusCode)
	}

	// Verify via API (Transparent Reconstruction)
	resp, err = http.Get(ts.URL + "/v1/meta/inode/paginated-file")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status %d", resp.StatusCode)
	}

	var got Inode
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if len(got.ChunkManifest) != chunkCount {
		t.Errorf("Expected %d chunks, got %d", chunkCount, len(got.ChunkManifest))
	}
	if got.ChunkManifest[chunkCount-1].ID != fmt.Sprintf("chunk-%d", chunkCount-1) {
		t.Errorf("Last chunk ID mismatch")
	}

	// Verify Internal Storage (BoltDB)
	// We need to access FSM directly
	err = node.FSM.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte("paginated-file"))
		var stored Inode
		json.Unmarshal(v, &stored)

		if stored.ChunkManifest != nil {
			return fmt.Errorf("Stored manifest should be nil")
		}
		if len(stored.ChunkPages) == 0 {
			return fmt.Errorf("Stored chunk_pages should not be empty")
		}

		// Check pages bucket
		pb := tx.Bucket([]byte("chunk_pages"))
		for _, pid := range stored.ChunkPages {
			if pb.Get([]byte(pid)) == nil {
				return fmt.Errorf("Page %s not found", pid)
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("Internal verification failed: %v", err)
	}
}

