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

package client

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestClientIntegration(t *testing.T) {
	// 1. Setup Metadata Node
	metaDir := t.TempDir()
	metaKey := make([]byte, 32)
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", metaDir, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	// Bootstrap
	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})

	// Wait for leader
	time.Sleep(2 * time.Second)

	metaServer := metadata.NewServer(metaNode.Raft, metaNode.FSM)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()

	// 2. Setup Data Node
	dataDir := t.TempDir()
	dataStore, err := data.NewDiskStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	dataServer := data.NewServer(dataStore)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	// 3. Client
	c := NewClient(tsMeta.URL, tsData.URL)

	// 4. Write File (Raw)
	content := []byte("hello distributed filesystem world")
	fileID := "file-1"
	key, err := c.WriteFile(fileID, content)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 5. Read File (Raw)
	readBack, err := c.ReadFile(fileID, key)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(readBack) != string(content) {
		t.Errorf("Content mismatch: got %s, want %s", readBack, content)
	}

	// 6. FS Integration (With Identity)
	dk, _ := crypto.GenerateEncryptionKey()
	c = c.WithIdentity("user-1", dk)

	fileID2 := "file-2"
	_, err = c.WriteFile(fileID2, content)
	if err != nil {
		t.Fatalf("WriteFile2 failed: %v", err)
	}

	dfs := c.FS()
	f, err := dfs.Open(fileID2)
	if err != nil {
		t.Fatalf("FS Open failed: %v", err)
	}
	defer f.Close()

	buf := make([]byte, len(content))
	if _, err := f.Read(buf); err != nil {
		t.Fatalf("FS Read failed: %v", err)
	}
	if string(buf) != string(content) {
		t.Error("FS Read mismatch")
	}

	info, _ := f.Stat()
	if info.Size() != int64(len(content)) {
		t.Error("Stat size mismatch")
	}
}