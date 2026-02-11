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
	"encoding/hex"
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
		masterKey        = flag.String("master-key", "", "32-byte hex master key")
		bootstrap        = flag.Bool("bootstrap", false, "Bootstrap a new cluster")
		jwksURL          = flag.String("jwks-url", "", "JWKS URL for auth")
		raftSecret       = flag.String("raft-secret", "", "Shared secret for cluster operations")
	)
	flag.Parse()

	baseDir := filepath.Join(*dataDir, "default") // Temp default if ID unknown
	if *nodeID != "" {
		baseDir = filepath.Join(*dataDir, *nodeID)
	}
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		log.Fatal(err)
	}

	// 0. Load Node Identity Key (Ed25519)
	raftKey, err := metadata.LoadOrGenerateNodeKey(filepath.Join(baseDir, "node.key"))
	if err != nil {
		log.Fatalf("failed to load node key: %v", err)
	}

	if *nodeID == "" {
		*nodeID = metadata.NodeIDFromKey(raftKey)
		// Re-evaluate baseDir with derived ID?
		// If we used "default", we might want to move it or just use the derived ID for logical ID.
		// For simplicity, let's stick to the directory we created, or maybe we should have derived ID before creating directory?
		// But we need directory to store the key. Chicken and egg.
		// "Upon a node's first startup, if it doesn't already exist, a persistent Ed25519 private key (node.key) is generated."
		// "in the node's data directory".
		// Ideally `data-dir` is the root, and we don't necessarily need a subdirectory named after ID if ID is derived from key inside it.
		// But existing logic uses `filepath.Join(*dataDir, *nodeID)`.
		// If ID is not provided, we can't form the path.
		// Let's assume if ID is missing, we look in `*dataDir` directly?
		// Or we require ID for directory structure but key derives ID?
		// "The node's unique Raft Node ID is then automatically derived".
		// Let's change behavior: if -id is not provided, use `data-dir` as the node's base.
		// If -id IS provided, use `data-dir/id`.
	}

	// Adjust baseDir logic
	if flag.Lookup("id").Value.String() == "" { // Check if flag was actually set
		// ID derived, use dataDir directly?
		// Or creates a subfolder based on derived ID?
		// If we use dataDir directly, multiple nodes on same FS needs different data-dirs.
		// Let's assume data-dir IS the node's dir if ID is omitted.
		baseDir = *dataDir
	} else {
		baseDir = filepath.Join(*dataDir, *nodeID)
	}
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		log.Fatal(err)
	}

	// Reload key from correct dir
	raftKey, err = metadata.LoadOrGenerateNodeKey(filepath.Join(baseDir, "node.key"))
	if err != nil {
		log.Fatalf("failed to load node key: %v", err)
	}

	// Finalize ID
	derivedID := metadata.NodeIDFromKey(raftKey)
	if *nodeID == "" {
		*nodeID = derivedID
	} else {
		// Optional: Verify provided ID matches derived?
		// For now, trust flag if provided, but maybe warn.
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

	mKeyStr := *masterKey
	if mKeyStr == "" {
		mKeyStr = os.Getenv("DISTFS_MASTER_KEY")
	}
	if mKeyStr == "" {
		log.Fatal("-master-key or DISTFS_MASTER_KEY environment variable is required")
	}

	mKey, err := hex.DecodeString(mKeyStr)
	if err != nil || len(mKey) != 32 {
		log.Fatal("master-key must be a 32-byte hex string")
	}

	// 1. Initialize Metadata Role (Raft)
	rn, err := metadata.NewRaftNode(*nodeID, *raftBind, *raftAdvertise, baseDir, mKey, raftKey)
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

	// 2. Initialize Keys for API
	nodeKey, signKey, err := loadOrGenerateKeys(baseDir)
	if err != nil {
		log.Fatalf("failed to init keys: %v", err)
	}

	// 3. Initialize Servers
	metaServer := metadata.NewServer(rn.Raft, rn.FSM, *jwksURL, nodeKey, signKey, *raftSecret)

	chunkDir := filepath.Join(baseDir, "chunks")
	store, err := data.NewDiskStore(chunkDir)
	if err != nil {
		log.Fatalf("failed to init data store: %v", err)
	}
	dataServer := data.NewServer(store, signKey.Public(), rn.FSM)

	// 4. Combined Router (Public)
	publicMux := http.NewServeMux()
	publicMux.Handle("/v1/meta/", metaServer) // Meta reads/writes
	publicMux.Handle("/v1/meta/key", metaServer)
	publicMux.Handle("/v1/user/", metaServer)
	publicMux.Handle("/v1/group/", metaServer)
	publicMux.Handle("/v1/data/", dataServer)    // Data access
	publicMux.Handle("/api/cluster", metaServer) // Dashboard & Management
	publicMux.Handle("/api/cluster/", metaServer)

	// 5. Internal Router (Cluster)
	clusterMux := http.NewServeMux()
	clusterMux.Handle("/v1/node", metaServer)     // Registration
	clusterMux.Handle("/v1/cluster/", metaServer) // Management
	// Forwarding endpoints are currently on /v1/meta, so we might need to expose them here too?
	// Ideally forwarding happens to the internal API.
	// For now, exposing meta on internal too for forwarding.
	clusterMux.Handle("/v1/meta/", metaServer)
	clusterMux.Handle("/v1/user/", metaServer)  // Forwarded writes
	clusterMux.Handle("/v1/group/", metaServer) // Forwarded writes

	// 6. Registration & Heartbeat
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
				// Use internal loopback for registration (will forward if needed)
				// Actually we should use the Cluster API address if possible, or loopback to cluster port.
				// Assuming localhost access to cluster port is fine.
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

func loadOrGenerateKeys(baseDir string) (*mlkem.DecapsulationKey768, *crypto.IdentityKey, error) {
	kemKeyPath := filepath.Join(baseDir, "kem.key")
	signKeyPath := filepath.Join(baseDir, "sign.key")

	var nodeKey *mlkem.DecapsulationKey768
	var signKey *crypto.IdentityKey

	if b, err := os.ReadFile(kemKeyPath); err == nil {
		nodeKey, _ = crypto.UnmarshalDecapsulationKey(b)
	} else {
		nodeKey, _ = crypto.GenerateEncryptionKey()
		os.WriteFile(kemKeyPath, crypto.MarshalDecapsulationKey(nodeKey), 0600)
	}

	if b, err := os.ReadFile(signKeyPath); err == nil {
		signKey = crypto.UnmarshalIdentityKey(b)
	} else {
		signKey, _ = crypto.GenerateIdentityKey()
		os.WriteFile(signKeyPath, signKey.MarshalPrivate(), 0600)
	}

	return nodeKey, signKey, nil
}
