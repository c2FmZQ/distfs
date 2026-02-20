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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

const (
	stableKeyName = "raft_stable.key"
)

// RaftNode wraps the Hashicorp Raft instance and its dependencies.
type RaftNode struct {
	Raft            *raft.Raft
	FSM             *MetadataFSM
	Transport       raft.Transport
	LogStore        *raftboltdb.BoltStore
	Storage         *storage.Storage
	ClientTLSConfig *tls.Config
	ServerTLSConfig *tls.Config
}

// NewRaftNode creates and bootstraps a new Raft node with mTLS and encryption.
func NewRaftNode(nodeID, bindAddr, advertiseAddr, baseDir string, st *storage.Storage, nodeKey *crypto.IdentityKey) (*RaftNode, error) {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(nodeID)
	// NoSnapshotRestoreOnStart default is false.

	// 1. Generate Self-Signed Cert
	cert, err := GenerateSelfSignedCert(nodeKey)
	if err != nil {
		return nil, fmt.Errorf("generate cert: %w", err)
	}

	// 2. Setup FSM
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(baseDir, "fsm.bolt")
	os.Remove(dbPath)
	fsm, err := NewMetadataFSM(dbPath, st)
	if err != nil {
		return nil, fmt.Errorf("metadata fsm initialization: %w", err)
	}

	// 3. Transport (mTLS)
	var r *raft.Raft

	verifyPeer := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates presented")
		}
		peerCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer cert: %w", err)
		}

		edPub, ok := peerCert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("peer key is not Ed25519")
		}

		if !fsm.IsInitialized() {
			return nil
		}

		if fsm.IsTrusted(edPub) {
			return nil
		}

		// Check if peer is in Raft Configuration (bootstrap/join scenario)
		if r != nil {
			derivedID := NodeIDFromPublicKey(edPub)
			future := r.GetConfiguration()
			if err := future.Error(); err == nil {
				for _, s := range future.Configuration().Servers {
					if string(s.ID) == derivedID {
						return nil
					}
				}
			}
		}

		return fmt.Errorf("peer not authorized")
	}

	tlsConfig := NewServerTLSConfig(cert, verifyPeer)
	clientTLSConfig := NewClientTLSConfig(cert, verifyPeer)

	var advertise net.Addr
	if advertiseAddr != "" {
		var err error
		advertise, err = net.ResolveTCPAddr("tcp", advertiseAddr)
		if err != nil {
			fsm.Close()
			return nil, fmt.Errorf("resolve advertise: %w", err)
		}
	}

	streamLayer, err := NewTLSStreamLayer(bindAddr, advertise, tlsConfig)
	if err != nil {
		fsm.Close()
		return nil, fmt.Errorf("tls listener: %w", err)
	}

	transport := raft.NewNetworkTransport(streamLayer, 3, 10*time.Second, os.Stderr)

	// 4. Stores
	keyRingName := "keyring.bin"
	var kr *crypto.KeyRing

	var krData KeyRingData
	if err := st.ReadDataFile(keyRingName, &krData); err == nil {
		kr, _ = crypto.UnmarshalKeyRing(krData.Bytes)
	} else {
		k := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, k); err != nil {
			return nil, err
		}
		kr = crypto.NewKeyRing(k)
		krData.Bytes = kr.Marshal()
		if err := st.SaveDataFile(keyRingName, krData); err != nil {
			return nil, err
		}
	}

	boltStore, err := raftboltdb.NewBoltStore(filepath.Join(baseDir, "raft-log.bolt"))
	if err != nil {
		streamLayer.Close()
		fsm.Close()
		return nil, fmt.Errorf("bolt store: %w", err)
	}

	// 5. Stable Store Key (Node-Local)
	var stableKey KeyData
	err = st.ReadDataFile(stableKeyName, &stableKey)
	if os.IsNotExist(err) {
		k := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, k); err != nil {
			return nil, err
		}
		stableKey.Bytes = k
		if err := st.SaveDataFile(stableKeyName, stableKey); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to read stable key: %w", err)
	}

	logStore := NewEncryptedLogStore(boltStore, kr)
	stableStore := NewEncryptedStableStore(boltStore, stableKey.Bytes)
	snapStore := NewStorageSnapshotStore(st)

	fsm.OnSnapshot = func() {
		kr.Rotate()
		st.SaveDataFile(keyRingName, KeyRingData{Bytes: kr.Marshal()})
		// Note: Trust state is persisted only during snapshots to optimize I/O performance.
		// Newly registered nodes are trusted in-memory until then.
		fsm.saveTrustState()
	}

	r, err = raft.NewRaft(config, fsm, logStore, stableStore, snapStore, transport)
	if err != nil {
		fsm.Close()
		boltStore.Close()
		streamLayer.Close()
		return nil, fmt.Errorf("new raft: %w", err)
	}

	return &RaftNode{
		Raft:            r,
		FSM:             fsm,
		Transport:       transport,
		LogStore:        boltStore,
		Storage:         st,
		ClientTLSConfig: clientTLSConfig,
		ServerTLSConfig: tlsConfig,
	}, nil
}

// Shutdown stops the Raft node.
func (n *RaftNode) Shutdown() error {
	f := n.Raft.Shutdown()
	if err := f.Error(); err != nil {
		return err
	}
	n.LogStore.Close()
	return n.FSM.Close()
}

type KeyRingData struct {
	Bytes []byte `json:"bytes"`
}
