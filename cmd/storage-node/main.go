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
		nodeID     = flag.String("id", "", "Node ID")
		raftAddr   = flag.String("raft-addr", "127.0.0.1:5000", "Raft internal address")
		apiAddr    = flag.String("api-addr", "127.0.0.1:8080", "HTTP API address")
		apiURL     = flag.String("api-url", "", "Reachable API URL for this node")
		dataDir    = flag.String("data-dir", "data", "Directory for storage")
		masterKey  = flag.String("master-key", "", "32-byte hex master key")
		bootstrap  = flag.Bool("bootstrap", false, "Bootstrap a new cluster")
		jwksURL    = flag.String("jwks-url", "", "JWKS URL for auth")
		raftSecret = flag.String("raft-secret", "", "Shared secret for cluster operations")
	)
	flag.Parse()

	if *nodeID == "" {
		log.Fatal("-id is required")
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

	baseDir := filepath.Join(*dataDir, *nodeID)
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		log.Fatal(err)
	}

	// 1. Initialize Metadata Role (Raft)
	rn, err := metadata.NewRaftNode(*nodeID, *raftAddr, baseDir, mKey)
	if err != nil {
		log.Fatalf("failed to init raft node: %v", err)
	}

	if *bootstrap {
		log.Printf("Bootstrapping cluster with node %s at %s", *nodeID, *raftAddr)
		rn.Raft.BootstrapCluster(raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      raft.ServerID(*nodeID),
					Address: raft.ServerAddress(*raftAddr),
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

	// 4. Combined Router
	mux := http.NewServeMux()
	// Meta handlers are registered in metadata.Server.ServeHTTP
	// We'll wrap them.
	mux.Handle("/v1/meta/", metaServer)
	mux.Handle("/v1/meta/key", metaServer)
	mux.Handle("/v1/cluster/", metaServer)
	mux.Handle("/v1/user/", metaServer)
	mux.Handle("/v1/group/", metaServer)
	mux.Handle("/v1/node", metaServer)

	// Data handlers
	mux.Handle("/v1/data/", dataServer)

	// 5. Registration & Heartbeat
	go func() {
		node := metadata.Node{
			ID:          *nodeID,
			Address:     *apiURL,
			RaftAddress: *raftAddr,
			Status:      metadata.NodeStatusActive,
		}

		// Wait for cluster ready
		time.Sleep(2 * time.Second)
		ticker := time.NewTicker(30 * time.Second)
		for {
			if rn.Raft.Leader() != "" {
				node.LastHeartbeat = time.Now().Unix()
				body, _ := json.Marshal(node)
				// Use internal loopback for registration (will forward if needed)
				req, _ := http.NewRequest("POST", "http://localhost:"+strings.Split(*apiAddr, ":")[1]+"/v1/node", bytes.NewReader(body))
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
	log.Printf("Storage Node %s starting API on %s", *nodeID, *apiAddr)
	srv := &http.Server{Addr: *apiAddr, Handler: mux}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down...")
	metaServer.Shutdown()
	rn.Shutdown()
	srv.Close()
}

func loadOrGenerateKeys(baseDir string) (*mlkem.DecapsulationKey768, *crypto.IdentityKey, error) {
	nodeKeyPath := filepath.Join(baseDir, "node.key")
	signKeyPath := filepath.Join(baseDir, "sign.key")

	var nodeKey *mlkem.DecapsulationKey768
	var signKey *crypto.IdentityKey

	if b, err := os.ReadFile(nodeKeyPath); err == nil {
		nodeKey, _ = crypto.UnmarshalDecapsulationKey(b)
	} else {
		nodeKey, _ = crypto.GenerateEncryptionKey()
		os.WriteFile(nodeKeyPath, crypto.MarshalDecapsulationKey(nodeKey), 0600)
	}

	if b, err := os.ReadFile(signKeyPath); err == nil {
		signKey = crypto.UnmarshalIdentityKey(b)
	} else {
		signKey, _ = crypto.GenerateIdentityKey()
		os.WriteFile(signKeyPath, signKey.MarshalPrivate(), 0600)
	}

	return nodeKey, signKey, nil
}
