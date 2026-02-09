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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb"
)

type RaftNode struct {
	Raft      *raft.Raft
	FSM       *MetadataFSM
	Transport raft.Transport
	LogStore  *raftboltdb.BoltStore
}

func NewRaftNode(nodeID, addr, baseDir string, masterKey []byte) (*RaftNode, error) {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(nodeID)
	config.NoSnapshotRestoreOnStart = true

	// Transport
	addrTCP, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}
	transport, err := raft.NewTCPTransport(addr, addrTCP, 3, 10*time.Second, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	// Stores
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, err
	}

	// Log Store (Encrypted with KeyRing)
	keyRingPath := filepath.Join(baseDir, "keyring.bin")
	var kr *crypto.KeyRing
	if b, err := os.ReadFile(keyRingPath); err == nil {
		kr, _ = crypto.UnmarshalKeyRing(b)
	} else {
		kr = crypto.NewKeyRing(masterKey)
		os.WriteFile(keyRingPath, kr.Marshal(), 0600)
	}

	boltStore, err := raftboltdb.NewBoltStore(filepath.Join(baseDir, "raft-log.bolt"))
	if err != nil {
		return nil, fmt.Errorf("bolt store: %w", err)
	}

	logStore := NewEncryptedLogStore(boltStore, kr)

	// Stable Store (Plain BoltStore)
	stableStore := boltStore

	// Snapshot Store (File)
	snapStore, err := raft.NewFileSnapshotStore(baseDir, 3, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("snapshot store: %w", err)
	}

	// FSM (BoltDB)
	dbPath := filepath.Join(baseDir, "fsm.bolt")
	fsm, err := NewMetadataFSM(dbPath)
	if err != nil {
		return nil, fmt.Errorf("new fsm: %w", err)
	}

	fsm.OnSnapshot = func() {
		kr.Rotate()
		os.WriteFile(keyRingPath, kr.Marshal(), 0600)
	}

	r, err := raft.NewRaft(config, fsm, logStore, stableStore, snapStore, transport)
	if err != nil {
		fsm.Close()
		boltStore.Close()
		return nil, fmt.Errorf("new raft: %w", err)
	}

	return &RaftNode{Raft: r, FSM: fsm, Transport: transport, LogStore: boltStore}, nil
}

func (n *RaftNode) Shutdown() error {
	f := n.Raft.Shutdown()
	if err := f.Error(); err != nil {
		return err
	}
	n.LogStore.Close()
	return n.FSM.Close()
}
