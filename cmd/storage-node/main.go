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

package main

import (
	"bytes"
	"crypto/mlkem"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
)

func main() {
	var (
		nodeID           = flag.String("id", "", "Node ID")
		raftBind         = flag.String("raft-bind", "127.0.0.1:8081", "Raft internal bind address")
		raftAdvertise    = flag.String("raft-advertise", "", "Public Raft address (host:port)")
		apiAddr          = flag.String("api-addr", "127.0.0.1:8080", "Public HTTP API address")
		apiURL           = flag.String("api-url", "", "Reachable API URL for this node")
		clusterAddr      = flag.String("cluster-addr", "127.0.0.1:9090", "Internal Cluster API address")
		clusterAdvertise = flag.String("cluster-advertise", "", "Public Cluster API address (host:port)")
		dataDir          = flag.String("data-dir", "data", "Directory for storage")
		masterKey        = flag.String("master-key", "", "Master passphrase (overrides env)")
		bootstrap        = flag.Bool("bootstrap", false, "Bootstrap a new cluster")
		jwksURL          = flag.String("jwks-url", "", "JWKS URL for auth")
		raftSecret       = flag.String("raft-secret", "", "Shared secret for cluster operations")
	)
	flag.Parse()

	// Adjust baseDir logic
	var baseDir string
	if flag.Lookup("id").Value.String() == "" {
		baseDir = *dataDir
	} else {
		baseDir = filepath.Join(*dataDir, *nodeID)
	}
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		log.Fatal(err)
	}

	// 0. Initialize Encryption
	passphrase := *masterKey
	if passphrase == "" {
		passphrase = os.Getenv("DISTFS_MASTER_KEY")
	}
	if passphrase == "" {
		log.Fatal("-master-key or DISTFS_MASTER_KEY environment variable is required")
	}

	// Load or Create Master Key
	mkPath := filepath.Join(baseDir, "master.key")
	var mk storage_crypto.MasterKey
	var err error

	if _, err := os.Stat(mkPath); err == nil {
		mk, err = storage_crypto.ReadMasterKey([]byte(passphrase), mkPath)
		if err != nil {
			log.Fatalf("failed to read master key: %v", err)
		}
	} else {
		mk, err = storage_crypto.CreateMasterKey()
		if err != nil {
			log.Fatalf("failed to create master key: %v", err)
		}
		if err := mk.Save([]byte(passphrase), mkPath); err != nil {
			log.Fatalf("failed to save master key: %v", err)
		}
	}

	// Open Storage
	st := storage.New(baseDir, mk)

	// 1. Load Node Identity Key (Ed25519)
	raftKey, err := metadata.LoadOrGenerateNodeKey(st, "node.key")
	if err != nil {
		log.Fatalf("failed to load node key: %v", err)
	}

	// Finalize ID
	derivedID := metadata.NodeIDFromKey(raftKey)
	if *nodeID == "" {
		*nodeID = derivedID
	} else {
		if *nodeID != derivedID {
			log.Printf("Warning: Provided Node ID %s does not match derived ID %s", *nodeID, derivedID)
		}
	}

	if *raftAdvertise == "" {
		*raftAdvertise = *raftBind
	}
	if *clusterAdvertise == "" {
		*clusterAdvertise = *clusterAddr
	}
	if *apiURL == "" {
		*apiURL = "http://" + *apiAddr
	}

	// 2. Initialize Metadata Role (Raft)
	rn, err := metadata.NewRaftNode(*nodeID, *raftBind, *raftAdvertise, baseDir, st, raftKey)
	if err != nil {
		log.Fatalf("failed to init raft node: %v", err)
	}

	if *bootstrap {
		log.Printf("Bootstrapping cluster with node %s at %s", *nodeID, *raftAdvertise)
		rn.Raft.BootstrapCluster(raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      raft.ServerID(*nodeID),
					Address: raft.ServerAddress(*raftAdvertise),
				},
			},
		})
	}

	// 3. Initialize Keys for API
	nodeKey, signKey, err := loadOrGenerateKeys(st)
	if err != nil {
		log.Fatalf("failed to init keys: %v", err)
	}

	// 4. Initialize Servers
	metaServer := metadata.NewServer(rn.Raft, rn.FSM, *jwksURL, nodeKey, signKey, *raftSecret)

	// DiskStore uses separate storage instance rooted at chunks/
	chunkDir := filepath.Join(baseDir, "chunks")
	if err := os.MkdirAll(chunkDir, 0700); err != nil {
		log.Fatal(err)
	}
	stChunks := storage.New(chunkDir, mk)

	store, err := data.NewDiskStore(stChunks)
	if err != nil {
		log.Fatalf("failed to init disk store: %v", err)
	}

	dataServer := data.NewServer(store, signKey.Public(), rn.FSM)

	// 5. Combined Router (Public)
	publicMux := http.NewServeMux()
	publicMux.Handle("/v1/meta/", metaServer) // Meta reads/writes
	publicMux.Handle("/v1/meta/key", metaServer)
	publicMux.Handle("/v1/user/", metaServer)
	publicMux.Handle("/v1/group/", metaServer)
	publicMux.Handle("/v1/data/", dataServer)    // Data access
	publicMux.Handle("/api/cluster", metaServer) // Dashboard & Management
	publicMux.Handle("/api/cluster/", metaServer)

	// 6. Internal Router (Cluster)
	clusterMux := http.NewServeMux()
	clusterMux.Handle("/v1/node", metaServer)     // Registration
	clusterMux.Handle("/v1/cluster/", metaServer) // Management
	clusterMux.Handle("/v1/meta/", metaServer)
	clusterMux.Handle("/v1/user/", metaServer)  // Forwarded writes
	clusterMux.Handle("/v1/group/", metaServer) // Forwarded writes

	// 7. Registration & Heartbeat
	go func() {
		clusterURL := *clusterAdvertise
		if !strings.HasPrefix(clusterURL, "http") {
			clusterURL = "http://" + clusterURL
		}

		node := metadata.Node{
			ID:             *nodeID,
			Address:        *apiURL, // Public address for clients
			ClusterAddress: clusterURL,
			RaftAddress:    *raftAdvertise, // Raft address
			Status:         metadata.NodeStatusActive,
		}

		// Wait for cluster ready
		time.Sleep(2 * time.Second)
		ticker := time.NewTicker(30 * time.Second)
		for {
			if rn.Raft.Leader() != "" {
				node.LastHeartbeat = time.Now().Unix()
				body, _ := json.Marshal(node)
				target := "http://localhost:" + strings.Split(*clusterAddr, ":")[1] + "/v1/node"
				req, _ := http.NewRequest("POST", target, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if *raftSecret != "" {
					req.Header.Set("X-Raft-Secret", *raftSecret)
				}

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					log.Printf("Heartbeat failed: %v", err)
				} else {
					resp.Body.Close()
				}
			}
			<-ticker.C
		}
	}()

	log.Printf("Storage Node %s starting Public API on %s, Cluster API on %s", *nodeID, *apiAddr, *clusterAddr)

	// Start Public Server
	publicSrv := &http.Server{Addr: *apiAddr, Handler: publicMux}
	go func() {
		if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("public listen: %s\n", err)
		}
	}()

	// Start Cluster Server
	clusterSrv := &http.Server{Addr: *clusterAddr, Handler: clusterMux}
	go func() {
		if err := clusterSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("cluster listen: %s\n", err)
		}
	}()

	// Wait for interrupt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down...")
	metaServer.Shutdown()
	rn.Shutdown()
	publicSrv.Close()
	clusterSrv.Close()
}

func loadOrGenerateKeys(st *storage.Storage) (*mlkem.DecapsulationKey768, *crypto.IdentityKey, error) {
	kemKeyName := "kem.key"
	signKeyName := "sign.key"

	var nodeKey *mlkem.DecapsulationKey768
	var signKey *crypto.IdentityKey

	// Load KEM Key
	var kemData KeyData
	if err := st.ReadDataFile(kemKeyName, &kemData); err == nil {
		nodeKey, _ = crypto.UnmarshalDecapsulationKey(kemData.Bytes)
	} else {
		nodeKey, _ = crypto.GenerateEncryptionKey()
		st.SaveDataFile(kemKeyName, KeyData{Bytes: crypto.MarshalDecapsulationKey(nodeKey)})
	}

	// Load Sign Key
	var signData KeyData
	if err := st.ReadDataFile(signKeyName, &signData); err == nil {
		signKey = crypto.UnmarshalIdentityKey(signData.Bytes)
	} else {
		signKey, _ = crypto.GenerateIdentityKey()
		st.SaveDataFile(signKeyName, KeyData{Bytes: signKey.MarshalPrivate()})
	}

	return nodeKey, signKey, nil
}

type KeyData struct {
	Bytes []byte `json:"bytes"`
}
