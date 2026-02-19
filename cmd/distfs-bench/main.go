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
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
)

var (
	serverURL = flag.String("server", "http://localhost:8080", "Metadata Server URL")
	jwt       = flag.String("jwt", "", "OIDC JWT for authentication")
	mode      = flag.String("mode", "put", "Bench mode: put, get, mkdir")
	workers   = flag.Int("workers", 10, "Number of concurrent workers")
	count     = flag.Int("count", 100, "Total number of operations to perform")
	size      = flag.Int64("size", 1024, "Size of files for put mode (in bytes)")
	adminFlag = flag.Bool("admin", false, "Enable admin bypass mode")
)

type stats struct {
	durations []time.Duration
	mu        sync.Mutex
	failures  uint64
	bytes     uint64
}

func (s *stats) record(d time.Duration, bytes uint64, success bool) {
	if !success {
		atomic.AddUint64(&s.failures, 1)
		return
	}
	s.mu.Lock()
	s.durations = append(s.durations, d)
	s.mu.Unlock()
	atomic.AddUint64(&s.bytes, bytes)
}

func (s *stats) report(totalDuration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.durations) == 0 {
		fmt.Printf("No successful operations.\nFailures: %d\n", s.failures)
		return
	}

	sort.Slice(s.durations, func(i, j int) bool {
		return s.durations[i] < s.durations[j]
	})

	n := len(s.durations)
	p50 := s.durations[n*50/100]
	p95 := s.durations[n*95/100]
	p99 := s.durations[n*99/100]

	fmt.Printf("\n--- Benchmark Results (%s) ---\n", *mode)
	fmt.Printf("Total Ops:    %d\n", n+int(s.failures))
	fmt.Printf("Success:      %d\n", n)
	fmt.Printf("Failures:     %d\n", s.failures)
	fmt.Printf("P50 (Median): %v\n", p50)
	fmt.Printf("P95:          %v\n", p95)
	fmt.Printf("P99:          %v\n", p99)
	fmt.Printf("Max:          %v\n", s.durations[n-1])

	opsSec := float64(n) / totalDuration.Seconds()
	fmt.Printf("Throughput:   %.2f ops/s\n", opsSec)

	if *mode == "put" || *mode == "get" {
		throughput := float64(s.bytes) / 1024 / 1024 / totalDuration.Seconds()
		fmt.Printf("Data Rate:    %.2f MB/s (aggregate)\n", throughput)
	}
}

func main() {
	flag.Parse()

	if *jwt == "" {
		log.Fatal("-jwt flag is required for benchmark")
	}

	configPath := "/tmp/bench-config.json"
	os.Setenv("DISTFS_PASSWORD", "benchpass")
	defer os.Unsetenv("DISTFS_PASSWORD")

	ctx := context.Background()
	opts := client.OnboardingOptions{
		ConfigPath: configPath,
		ServerURL:  *serverURL,
		JWT:        *jwt,
		IsNew:      true,
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("Initializing identity...")
		if err := client.PerformUnifiedOnboarding(ctx, opts); err != nil {
			log.Fatalf("onboarding failed: %v", err)
		}
		fmt.Println(" OK")
	}

	// Load Client
	conf, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	c := client.NewClient(conf.ServerURL)
	dkBytes, err := hex.DecodeString(conf.EncKey)
	if err != nil {
		log.Fatalf("invalid EncKey: %v", err)
	}
	dk, err := crypto.UnmarshalDecapsulationKey(dkBytes)
	if err != nil {
		log.Fatalf("failed to unmarshal decapsulation key: %v", err)
	}
	skBytes, err := hex.DecodeString(conf.SignKey)
	if err != nil {
		log.Fatalf("invalid SignKey: %v", err)
	}
	sk := crypto.UnmarshalIdentityKey(skBytes)
	svKeyBytes, err := hex.DecodeString(conf.ServerKey)
	if err != nil {
		log.Fatalf("invalid ServerKey: %v", err)
	}
	svKey, err := crypto.UnmarshalEncapsulationKey(svKeyBytes)
	if err != nil {
		log.Fatalf("failed to unmarshal server key: %v", err)
	}

	c = c.WithIdentity(conf.UserID, dk).WithSignKey(sk).WithServerKey(svKey).WithAdmin(*adminFlag)

	// Ensure we are logged in
	if err := c.Login(); err != nil {
		log.Fatalf("initial login failed: %v", err)
	}

	// Create bench root
	benchDir := fmt.Sprintf("/bench-%d", time.Now().UnixNano())
	if err := c.Mkdir(benchDir); err != nil {
		log.Fatalf("failed to create bench dir: %v", err)
	}
	defer func() {
		if err := c.Remove(benchDir); err != nil {
			log.Printf("failed to cleanup bench dir: %v", err)
		}
	}()

	// Pre-create file for GET mode
	if *mode == "get" {
		fmt.Printf("Pre-creating %s/bench-target for READ test...", benchDir)
		if err := c.CreateFile(benchDir+"/bench-target", io.LimitReader(rand.Reader, *size), *size); err != nil {
			log.Fatalf("failed to pre-create target: %v", err)
		}
		fmt.Println(" OK")
	}

	s := &stats{durations: make([]time.Duration, 0, *count)}
	var wg sync.WaitGroup

	opChan := make(chan int, *count)
	for i := 0; i < *count; i++ {
		opChan <- i
	}
	close(opChan)

	fmt.Printf("Running benchmark with %d workers and %d total ops...\n", *workers, *count)
	start := time.Now()
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Create worker sub-directory to avoid parent contention
			workerDir := fmt.Sprintf("%s/worker-%d", benchDir, workerID)
			if err := c.Mkdir(workerDir); err != nil {
				log.Printf("Worker %d failed to create subdir: %v", workerID, err)
				return
			}

			for range opChan {
				opStart := time.Now()
				var err error
				var bytesTransferred uint64 = 0

				switch *mode {
				case "mkdir":
					path := fmt.Sprintf("%s/dir-%d-%d", workerDir, workerID, time.Now().UnixNano())
					err = c.Mkdir(path)
				case "put":
					path := fmt.Sprintf("%s/file-%d-%d", workerDir, workerID, time.Now().UnixNano())
					// Stream data to avoid OOM
					err = c.CreateFile(path, io.LimitReader(rand.Reader, *size), *size)
					bytesTransferred = uint64(*size)
				case "get":
					// High level Open uses io.fs interface
					f, ferr := c.FS().Open(benchDir + "/bench-target")
					if ferr != nil {
						err = ferr
					} else {
						n, _ := io.Copy(io.Discard, f)
						f.Close()
						bytesTransferred = uint64(n)
					}
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

	s.report(totalTime)
}
