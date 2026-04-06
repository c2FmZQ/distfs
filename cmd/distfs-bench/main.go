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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/urfave/cli/v3"
)

type stats struct {
	mu                sync.Mutex
	ops               int
	bytes             int64
	failures          int
	latencies         []time.Duration
	operationCounts   map[string]int
	operationFailures map[string]int
}

func (s *stats) record(d time.Duration, bytes int64, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops++
	s.bytes += bytes
	if !success {
		s.failures++
	}
	s.latencies = append(s.latencies, d)
}

func (s *stats) report(totalDuration time.Duration, mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.latencies) == 0 {
		fmt.Println("No operations recorded.")
		return
	}

	sortLatencies(s.latencies)
	avg := totalDuration / time.Duration(s.ops)
	p50 := s.latencies[len(s.latencies)*50/100]
	p95 := s.latencies[len(s.latencies)*95/100]
	p99 := s.latencies[len(s.latencies)*99/100]

	fmt.Printf("\n--- Benchmark Report (%s) ---\n", mode)
	fmt.Printf("Total Ops:    %d\n", s.ops)
	fmt.Printf("Total Bytes:  %s\n", client.FormatBytes(s.bytes))
	fmt.Printf("Failures:     %d\n", s.failures)
	fmt.Printf("Duration:     %v\n", totalDuration)
	fmt.Printf("Latency (avg): %v\n", avg)
	fmt.Printf("Latency (p50): %v\n", p50)
	fmt.Printf("Latency (p95): %v\n", p95)
	fmt.Printf("Latency (p99): %v\n", p99)

	opsSec := float64(s.ops) / totalDuration.Seconds()
	fmt.Printf("Throughput:   %.2f ops/s\n", opsSec)

	if mode == "put" || mode == "get" {
		throughput := float64(s.bytes) / 1024 / 1024 / totalDuration.Seconds()
		fmt.Printf("Data Rate:    %.2f MB/s (aggregate)\n", throughput)
	}
}

func sortLatencies(l []time.Duration) {
	for i := 0; i < len(l); i++ {
		for j := i + 1; j < len(l); j++ {
			if l[i] > l[j] {
				l[i], l[j] = l[j], l[i]
			}
		}
	}
}

func loadConfigWithPassword(path string, password string) (*config.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var blob metadata.KeySyncBlob
	if err := json.Unmarshal(b, &blob); err != nil {
		return nil, err
	}
	return config.Decrypt(blob, []byte(password))
}

func main() {
	cmd := &cli.Command{
		Name:  "distfs-bench",
		Usage: "DistFS Performance Benchmarking Tool",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Value: config.DefaultPath(), Usage: "Path to client config"},
			&cli.StringFlag{Name: "mode", Value: "put", Usage: "Benchmark mode: put, get, ls, mkdir"},
			&cli.IntFlag{Name: "concurrency", Value: 1, Usage: "Number of concurrent workers"},
			&cli.IntFlag{Name: "count", Value: 100, Usage: "Total number of operations to perform"},
			&cli.IntFlag{Name: "size", Value: 1024 * 1024, Usage: "Size of file for put/get modes (bytes)"},
			&cli.StringFlag{Name: "path", Value: "/bench", Usage: "Target directory in DistFS"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			configPath := cmd.String("config")
			mode := cmd.String("mode")
			concurrency := int(cmd.Int("concurrency"))
			count := int(cmd.Int("count"))
			size := cmd.Int("size")
			targetPath := cmd.String("path")

			passphrase := os.Getenv("DISTFS_PASSWORD")
			if passphrase == "" {
				passphrase = "benchpass" // Default for testing
			}

			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				log.Fatalf("Config file %s not found. Run 'distfs init' first.", configPath)
			}

			conf, err := loadConfigWithPassword(configPath, passphrase)
			if err != nil {
				log.Fatalf("failed to load config: %v", err)
			}

			c := client.NewClient(conf.ServerURL)
			dkBytes, _ := hex.DecodeString(conf.EncKey)
			skBytes, _ := hex.DecodeString(conf.SignKey)
			svKeyBytes, _ := hex.DecodeString(conf.ServerKey)

			rid := conf.DefaultRootID
			if rid == "" {
				rid = metadata.RootID
			}
			var rowner string
			var rpk, rek []byte
			var rver uint64
			if anchor, ok := conf.Roots[rid]; ok {
				rowner = anchor.RootOwner
				rpk = anchor.RootOwnerPublicKey
				rek = anchor.RootOwnerEncryptionKey
				rver = anchor.RootVersion
			}

			c, err = c.WithIdentityBytes(conf.UserID, dkBytes)
			if err != nil {
				log.Fatalf("failed to set identity: %v", err)
			}
			c, err = c.WithSignKeyBytes(skBytes)
			if err != nil {
				log.Fatalf("failed to set sign key: %v", err)
			}
			c, err = c.WithServerKeyBytes(svKeyBytes)
			if err != nil {
				log.Fatalf("failed to set server key: %v", err)
			}
			c = c.WithRootAnchorBytes(rid, rowner, rpk, rek, rver)

			s := &stats{
				operationCounts:   make(map[string]int),
				operationFailures: make(map[string]int),
			}

			fmt.Printf("Starting benchmark: mode=%s, concurrency=%d, count=%d, size=%s\n", mode, concurrency, count, client.FormatBytes(int64(size)))

			start := time.Now()
			var wg sync.WaitGroup
			opsPerWorker := count / concurrency

			// Ensure target path exists
			if mode == "put" || mode == "mkdir" {
				c.MkdirAll(ctx, targetPath)
			}

			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					for j := 0; j < opsPerWorker; j++ {
						opStart := time.Now()
						var err error
						var bytesTransferred int64

						name := fmt.Sprintf("bench-%d-%d", workerID, j)
						path := filepath.Join(targetPath, name)

						switch mode {
						case "put":
							data := make([]byte, size)
							rand.Read(data)
							err = c.CreateFile(ctx, path, bytes.NewReader(data), int64(size))
							bytesTransferred = int64(size)
						case "get":
							rc, getErr := c.OpenBlobRead(ctx, path)
							if getErr == nil {
								n, _ := io.Copy(io.Discard, rc)
								bytesTransferred = n
								rc.Close()
							} else {
								err = getErr
							}
						case "ls":
							_, err = c.ReadDir(ctx, targetPath)
						case "mkdir":
							err = c.Mkdir(ctx, path, 0700)
						}

						s.record(time.Since(opStart), bytesTransferred, err == nil)
						if err != nil {
							log.Printf("Operation failed: %v", err)
						}
					}
				}(i)
			}

			wg.Wait()
			totalTime := time.Since(start)

			s.report(totalTime, mode)
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
