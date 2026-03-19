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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
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
	"github.com/c2FmZQ/tpm"
	"github.com/hashicorp/raft"
)

func loadOrGenerateClusterSecret(st *storage.Storage, bootstrap bool) ([]byte, error) {
	vault := metadata.NewNodeVault(st)
	if vault.HasClusterSecret() {
		return vault.LoadClusterSecret()
	}

	if !bootstrap {
		// Non-bootstrap nodes must receive the secret from the leader during join.
		// We'll return nil for now and let the join process handle it.
		// WARNING: This allows the FSM to start with a nil secret. The node must
		// receive a bootstrap push before it can safely apply any Raft logs.
		return nil, nil
	}

	// Generate new secret for initial bootstrap
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, err
	}

	if err := vault.SaveClusterSecret(secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func loadOrGenerateEncryptionKey(st *storage.Storage) (*mlkem.DecapsulationKey768, error) {
	encKeyName := "enc.key"
	var encData KeyData
	if err := st.ReadDataFile(encKeyName, &encData); err == nil {
		return mlkem.NewDecapsulationKey768(encData.Bytes)
	}

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	encData.Bytes = dk.Bytes()
	if err := st.SaveDataFile(encKeyName, encData); err != nil {
		return nil, err
	}

	return dk, nil
}

type KeyData struct {
	Bytes []byte `json:"bytes"`
}

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

		tlsCert       = flag.String("tls-cert", "", "TLS certificate for public API")
		tlsKey        = flag.String("tls-key", "", "TLS key for public API")
		useTPM        = flag.Bool("use-tpm", false, "Use TPM for hardware-bound security")
		disableDoH    = flag.Bool("disable-doh", false, "Disable DNS-over-HTTPS and use system resolver")
		allowInsecure = flag.Bool("allow-insecure", false, "Allow plaintext HTTP for node-to-node communication (tests only)")
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
	passphraseStr := os.Getenv("DISTFS_MASTER_KEY")
	if passphraseStr == "" {
		log.Fatal("DISTFS_MASTER_KEY environment variable is required")
	}

	var tpmDev *tpm.TPM
	if *useTPM {
		var err error
		tpmDev, err = tpm.New()
		if err != nil {
			log.Fatalf("failed to initialize TPM: %v", err)
		}
		defer tpmDev.Close()
	}

	passphrase := []byte(passphraseStr)

	// Hardware-bind the passphrase using TPM HMAC
	if tpmDev != nil {
		hmacKeyPath := filepath.Join(baseDir, "tpm_hmac.key")
		var hmacKey *tpm.Key
		if b, err := os.ReadFile(hmacKeyPath); err == nil {
			hmacKey, err = tpmDev.UnmarshalKey(b)
			if err != nil {
				log.Fatalf("failed to unmarshal TPM HMAC key: %v", err)
			}
		} else {
			hmacKey, err = tpmDev.CreateKey(tpm.WithHMAC(256))
			if err != nil {
				log.Fatalf("failed to create TPM HMAC key: %v", err)
			}
			marshaled, err := hmacKey.Marshal()
			if err != nil {
				log.Fatalf("failed to marshal TPM HMAC key: %v", err)
			}
			if err := os.WriteFile(hmacKeyPath, marshaled, 0600); err != nil {
				log.Fatalf("failed to save TPM HMAC key: %v", err)
			}
		}

		boundHash, err := hmacKey.HMAC(passphrase)
		if err != nil {
			log.Fatalf("failed to compute TPM HMAC: %v", err)
		}
		passphrase = []byte(hex.EncodeToString(boundHash))
		log.Println("Hardware security enabled: Master key is bound to TPM")
	}

	// Load or Create Master Key
	mkPath := filepath.Join(baseDir, "master.key")
	var mk storage_crypto.MasterKey
	var err error

	if _, err := os.Stat(mkPath); err == nil {
		mk, err = storage_crypto.ReadMasterKey(passphrase, mkPath)
		if err != nil {
			log.Fatalf("failed to read master key: %v", err)
		}
	} else {
		mk, err = storage_crypto.CreateMasterKey()
		if err != nil {
			log.Fatalf("failed to create master key: %v", err)
		}
		if err := mk.Save(passphrase, mkPath); err != nil {
			log.Fatalf("failed to save master key: %v", err)
		}
	}

	// Open Storage
	st := storage.New(baseDir, mk)

	// 1. Load Node Identity Key (Ed25519)
	raftKey, err := metadata.LoadOrGenerateNodeKey(st, "node.key", tpmDev)
	if err != nil {
		log.Fatalf("failed to load node key: %v", err)
	}

	// 1.1 Load Sign Key (PQC)
	signKey, err := loadOrGenerateSignKey(st)
	if err != nil {
		log.Fatalf("failed to init keys: %v", err)
	}

	// 1.2 Load Encryption Key (PQC)
	decKey, err := loadOrGenerateEncryptionKey(st)
	if err != nil {
		log.Fatalf("failed to init encryption key: %v", err)
	}

	// 1.3 Load Cluster Secret (Root of Trust)
	clusterSecret, err := loadOrGenerateClusterSecret(st, *bootstrap)
	if err != nil {
		log.Fatalf("failed to load cluster secret: %v", err)
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
	rn, err := metadata.NewRaftNode(*nodeID, *raftBind, *raftAdvertise, baseDir, st, raftKey, clusterSecret)
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

		// Initialize Cluster Anchors (Signing Key)
		// Wait for leader election to finalize
		timeout := time.After(30 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

	AnchorInitLoop:
		for {
			select {
			case <-timeout:
				log.Println("Warning: Timed out waiting for leader state during bootstrap; skipping anchor init.")
				break AnchorInitLoop
			case <-ticker.C:
				if rn.Raft.State() == raft.Leader {
					// 1. Initialize Cluster Signing Key if needed
					if _, err := rn.FSM.GetClusterSignPublicKey(); err != nil {
						log.Println("Initializing Cluster Signing Key...")
						csk, err := crypto.GenerateIdentityKey()
						if err != nil {
							log.Fatalf("failed to generate cluster sign key: %v", err)
						}
						keyData := metadata.ClusterSignKey{
							Public:           csk.Public(),
							EncryptedPrivate: csk.MarshalPrivate(),
						}
						data, _ := json.Marshal(keyData)
						cmd := metadata.LogCommand{Type: metadata.CmdSetClusterSignKey, Data: data}
						b, err := cmd.Marshal()
						if err != nil {
							log.Fatalf("failed to marshal cluster sign key command: %v", err)
						}
						if err := rn.Raft.Apply(b, 5*time.Second).Error(); err != nil {
							log.Fatalf("failed to apply cluster sign key: %v", err)
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
						LastHeartbeat:  time.Now().Unix(),
					}
					nodeBytes, _ := json.Marshal(node)
					cmd := metadata.LogCommand{Type: metadata.CmdRegisterNode, Data: nodeBytes}
					b, err := cmd.Marshal()
					if err != nil {
						log.Fatalf("failed to marshal register bootstrap node command: %v", err)
					}
					if err := rn.Raft.Apply(b, 5*time.Second).Error(); err != nil {
						log.Fatalf("failed to register bootstrap node: %v", err)
					}

					// 3. Initialize Active Epoch Key
					if _, err := rn.FSM.GetActiveKey(); err != nil {
						log.Println("Initializing Active Epoch Key...")
						key, err := crypto.GenerateEncryptionKey()
						if err == nil {
							clusterKey := metadata.ClusterKey{
								ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
								EncKey:    key.EncapsulationKey().Bytes(),
								DecKey:    key.Bytes(),
								CreatedAt: time.Now().Unix(),
							}
							data, _ := json.Marshal(clusterKey)
							cmd := metadata.LogCommand{Type: metadata.CmdRotateKey, Data: data}
							b, err := cmd.Marshal()
							if err != nil {
								log.Printf("ERROR: failed to marshal rotation command: %v", err)
							} else {
								rn.Raft.Apply(b, 5*time.Second)
							}
						}
					}

					break AnchorInitLoop
				}
			}
		}
	}

	// 4. Initialize Servers
	metaServer := metadata.NewServer(*nodeID, rn.Raft, rn.FSM, *oidcURL, signKey, *raftSecret, rn.ClientTLSConfig, 24*time.Hour, metadata.NewNodeVault(st), decKey, *disableDoH)
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

	metaPubKey := signKey.Public()
	if pub, err := rn.FSM.GetClusterSignPublicKey(); err == nil {
		metaPubKey = pub
	}
	dataServer := data.NewServer(store, metaPubKey, rn.FSM, rn.FSM, *disableDoH, *allowInsecure)

	// 5. Combined Router (Public)
	publicMux := http.NewServeMux()
	publicMux.Handle("/v1/meta/", metaServer) // Meta reads/writes
	publicMux.Handle("/v1/meta/key", metaServer)
	publicMux.Handle("/v1/health", metaServer)
	publicMux.Handle("/v1/node", metaServer)

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

	registerDebugHandlers(publicMux)

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
	if len(clusterSecret) == 0 {
		clusterMux.Handle("/v1/system/bootstrap", metaServer)
	}
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
	corsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Session-Token, X-DistFS-Sealed, X-DistFS-Admin-Bypass")
		w.Header().Set("Access-Control-Expose-Headers", "X-DistFS-Sealed")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		publicMux.ServeHTTP(w, r)
	})

	publicSrv := &http.Server{Addr: *apiAddr, Handler: corsHandler}
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
		if err := st.SaveDataFile(signKeyName, KeyData{Bytes: signKey.MarshalPrivate()}); err != nil {
			return nil, err
		}
	}

	return signKey, nil
}
