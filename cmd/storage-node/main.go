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
	"crypto/rand"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
		bootstrap        = flag.Bool("bootstrap", false, "Bootstrap a new cluster")
		oidcURL          = flag.String("oidc-discovery-url", "", "OIDC Discovery URL")
		raftSecret       = flag.String("raft-secret", "", "Shared secret for cluster operations")

		tlsCert = flag.String("tls-cert", "", "TLS certificate for public API")
		tlsKey  = flag.String("tls-key", "", "TLS key for public API")
	)
	flag.Parse()

	// Default and Validate Advertise Addresses
	if *raftAdvertise == "" {
		*raftAdvertise = *raftBind
	}
	if *clusterAdvertise == "" {
		*clusterAdvertise = "https://" + *clusterAddr
	}

	// Validate Raft advertise address (host:port)
	if _, _, err := net.SplitHostPort(*raftAdvertise); err != nil {
		log.Fatalf("invalid raft-advertise %q: %v (expected host:port)", *raftAdvertise, err)
	}

	// Validate Cluster advertise address (https://host:port)
	if u, err := url.Parse(*clusterAdvertise); err != nil {
		log.Fatalf("invalid cluster-advertise %q: %v", *clusterAdvertise, err)
	} else if u.Scheme != "https" {
		log.Fatalf("cluster-advertise %q MUST use https:// scheme", *clusterAdvertise)
	}

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
	passphrase := os.Getenv("DISTFS_MASTER_KEY")
	if passphrase == "" {
		log.Fatal("DISTFS_MASTER_KEY environment variable is required")
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

	// 1.1 Load Sign Key (PQC)
	signKey, err := loadOrGenerateSignKey(st)
	if err != nil {
		log.Fatalf("failed to init keys: %v", err)
	}

	// Finalize ID
	derivedID := metadata.NodeIDFromKey(raftKey)
	if *nodeID != "" && *nodeID != derivedID {
		log.Printf("Overriding provided Node ID %s with derived ID %s to ensure mTLS compatibility", *nodeID, derivedID)
	}
	*nodeID = derivedID

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
		f := rn.Raft.BootstrapCluster(raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      raft.ServerID(*nodeID),
					Address: raft.ServerAddress(*raftAdvertise),
				},
			},
		})
		if err := f.Error(); err != nil {
			log.Fatalf("bootstrap failed: %v", err)
		}

		// Initialize Cluster Secret
		// Wait for leader election to finalize
		timeout := time.After(30 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

	SecretInitLoop:
		for {
			select {
			case <-timeout:
				log.Println("Warning: Timed out waiting for leader state during bootstrap; skipping secret init.")
				break SecretInitLoop
			case <-ticker.C:
				if rn.Raft.State() == raft.Leader {
					// 1. Initialize Secret if needed
					_, err := rn.FSM.GetClusterSecret()
					if err != nil {
						log.Println("Initializing Cluster Secret...")
						secret := make([]byte, 32)
						if _, err := io.ReadFull(rand.Reader, secret); err != nil {
							log.Fatalf("failed to generate secret: %v", err)
						}
						cmd := metadata.LogCommand{Type: metadata.CmdInitSecret, Data: secret}
						b, _ := json.Marshal(cmd)
						if err := rn.Raft.Apply(b, 5*time.Second).Error(); err != nil {
							log.Fatalf("failed to apply secret: %v", err)
						}
					}

					// 2. Register self in FSM (seeds discovery for heartbeats)
					log.Println("Registering bootstrap node in FSM...")
					node := metadata.Node{
						ID:             *nodeID,
						Address:        *apiURL,
						ClusterAddress: *clusterAdvertise,
						RaftAddress:    *raftAdvertise,
						Status:         metadata.NodeStatusActive,
						PublicKey:      raftKey.Public(),
						SignKey:        signKey.Public(),
					}
					nodeBytes, _ := json.Marshal(node)
					cmd := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nodeBytes}
					if err := rn.Raft.Apply(cmd.Marshal(), 5*time.Second).Error(); err != nil {
						log.Fatalf("failed to register bootstrap node: %v", err)
					}

					break SecretInitLoop
				}
			}
		}
	}

	// 4. Initialize Servers
	metaServer := metadata.NewServer(*nodeID, rn.Raft, rn.FSM, *oidcURL, signKey, *raftSecret, rn.ClientTLSConfig, 24*time.Hour)
	metaServer.SetRaftAddress(*raftAdvertise)
	metaServer.SetAPIURL(*apiURL)
	metaServer.SetTLSPublicKey(raftKey.Public())
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
	publicMux.Handle("/v1/health", metaServer)

	publicMux.Handle("/v1/user/", metaServer)
	publicMux.Handle("/v1/group/", metaServer)
	publicMux.Handle("/v1/cluster/", metaServer)
	publicMux.Handle("/v1/auth/", metaServer)
	publicMux.Handle("/v1/login", metaServer)
	publicMux.Handle("/v1/admin/", metaServer)
	publicMux.Handle("/v1/system/", metaServer)
	publicMux.Handle("/v1/data/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/replicate") {
			http.NotFound(w, r)
			return
		}
		dataServer.ServeHTTP(w, r)
	}))
	publicMux.Handle("/api/debug/", metaServer)

	// 6. Internal Router (Cluster)
	clusterMux := http.NewServeMux()
	clusterMux.Handle("/v1/node", metaServer) // Registration
	clusterMux.Handle("/v1/node/info", metaServer)
	clusterMux.Handle("/v1/health", metaServer)
	clusterMux.Handle("/v1/admin/", metaServer)
	clusterMux.Handle("/v1/cluster/", metaServer) // Management
	clusterMux.Handle("/v1/meta/", metaServer)
	clusterMux.Handle("/v1/user/", metaServer)  // Forwarded writes
	clusterMux.Handle("/v1/group/", metaServer) // Forwarded writes
	clusterMux.Handle("/v1/auth/", metaServer)
	clusterMux.Handle("/v1/login", metaServer)
	clusterMux.Handle("/api/debug/", metaServer)

	// 7. Registration & Heartbeat
	go func() {
		node := metadata.Node{
			ID:             *nodeID,
			Address:        *apiURL, // Public address for clients
			ClusterAddress: *clusterAdvertise,
			RaftAddress:    *raftAdvertise, // Raft address
			Status:         metadata.NodeStatusActive,
			PublicKey:      raftKey.Public(),
			SignKey:        signKey.Public(),
		}

		// Wait for cluster ready
		time.Sleep(2 * time.Second)

		// Persistent heartbeat client
		var hbClient *http.Client
		if rn.ClientTLSConfig != nil {
			hbClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: rn.ClientTLSConfig,
				},
				Timeout: 60 * time.Second,
			}
		} else {
			hbClient = &http.Client{
				Timeout: 60 * time.Second,
			}
		}

		ticker := time.NewTicker(30 * time.Second)
		for {
			leaderAddr, _ := rn.Raft.LeaderWithID()
			if leaderAddr != "" {
				node.LastHeartbeat = time.Now().Unix()
				if c, u, err := store.Stats(); err == nil {
					node.Capacity = c
					node.Used = u
				}
				body, _ := json.Marshal(node)

				// Find Leader's Cluster Address from FSM
				var target string
				if n, err := rn.FSM.GetNodeByRaftAddress(string(leaderAddr)); err == nil {
					target = n.ClusterAddress
				}

				if target != "" {
					target = strings.TrimSuffix(target, "/") + "/v1/node"
					req, _ := http.NewRequest("POST", target, bytes.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					if *raftSecret != "" {
						req.Header.Set("X-Raft-Secret", *raftSecret)
					}

					resp, err := hbClient.Do(req)
					if err != nil {
						log.Printf("Heartbeat failed to %s: %v", target, err)
					} else if resp != nil {
						resp.Body.Close()
					}
				}
			}
			<-ticker.C
		}
	}()

	log.Printf("Storage Node %s starting Public API on %s, Cluster API on %s", *nodeID, *apiAddr, *clusterAddr)

	// Start Public Server
	publicSrv := &http.Server{Addr: *apiAddr, Handler: publicMux}
	go func() {
		var err error
		if *tlsCert != "" && *tlsKey != "" {
			err = publicSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = publicSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("public listen: %s\n", err)
		}
	}()

	// Start Cluster Server (mTLS if configured)
	clusterSrv := &http.Server{
		Addr:      *clusterAddr,
		Handler:   clusterMux,
		TLSConfig: rn.ServerTLSConfig,
	}

	go func() {
		if err := clusterSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
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

func loadOrGenerateSignKey(st *storage.Storage) (*crypto.IdentityKey, error) {
	signKeyName := "sign.key"

	var signKey *crypto.IdentityKey

	// Load Sign Key
	var signData KeyData
	if err := st.ReadDataFile(signKeyName, &signData); err == nil {
		signKey = crypto.UnmarshalIdentityKey(signData.Bytes)
	} else {
		signKey, _ = crypto.GenerateIdentityKey()
		st.SaveDataFile(signKeyName, KeyData{Bytes: signKey.MarshalPrivate()})
	}

	return signKey, nil
}

type KeyData struct {
	Bytes []byte `json:"bytes"`
}
