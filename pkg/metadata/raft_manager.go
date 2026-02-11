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
	"crypto/ed25519"
	"crypto/x509"
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

func NewRaftNode(nodeID, bindAddr, advertiseAddr, baseDir string, masterKey []byte, nodeKey *crypto.IdentityKey) (*RaftNode, error) {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(nodeID)
	config.NoSnapshotRestoreOnStart = true

	// 1. Generate Self-Signed Cert
	cert, err := GenerateSelfSignedCert(nodeKey)
	if err != nil {
		return nil, fmt.Errorf("generate cert: %w", err)
	}

	// 2. Setup FSM (Needed for verification closure)
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(baseDir, "fsm.bolt")
	fsm, err := NewMetadataFSM(dbPath)
	if err != nil {
		return nil, fmt.Errorf("new fsm: %w", err)
	}

	// 3. Transport (mTLS)
	verifyPeer := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates presented")
		}
		// Parse peer cert
		peerCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer cert: %w", err)
		}

		// Extract Public Key (Ed25519)
		edPub, ok := peerCert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("peer key is not Ed25519")
		}

		// TOFU / Strict Mode Logic
		if !fsm.IsInitialized() {
			// TOFU Mode: Accept anyone (typically Leader)
			return nil
		}

		if !fsm.IsTrusted(edPub) {
			return fmt.Errorf("peer not authorized")
		}

		return nil
	}

	var advertise net.Addr
	if advertiseAddr != "" {
		advertise, err = net.ResolveTCPAddr("tcp", advertiseAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve advertise: %w", err)
		}
	}

	tlsConfig := NewServerTLSConfig(cert, verifyPeer)
	streamLayer, err := NewTLSStreamLayer(bindAddr, advertise, tlsConfig)
	if err != nil {
		fsm.Close()
		return nil, fmt.Errorf("tls listener: %w", err)
	}

	transport := raft.NewNetworkTransport(streamLayer, 3, 10*time.Second, os.Stderr)

	// 4. Stores
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
		streamLayer.Close()
		fsm.Close()
		return nil, fmt.Errorf("bolt store: %w", err)
	}

	logStore := NewEncryptedLogStore(boltStore, kr)

	// Stable Store (Plain BoltStore)
	stableStore := boltStore

	// Snapshot Store (File)
	snapStore, err := raft.NewFileSnapshotStore(baseDir, 3, os.Stderr)
	if err != nil {
		boltStore.Close()
		streamLayer.Close()
		fsm.Close()
		return nil, fmt.Errorf("snapshot store: %w", err)
	}

	fsm.OnSnapshot = func() {
		kr.Rotate()
		os.WriteFile(keyRingPath, kr.Marshal(), 0600)
	}

	r, err := raft.NewRaft(config, fsm, logStore, stableStore, snapStore, transport)
	if err != nil {
		fsm.Close()
		boltStore.Close()
		streamLayer.Close() // Close listener if raft fails
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
