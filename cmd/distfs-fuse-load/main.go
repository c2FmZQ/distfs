// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	mountPath = flag.String("mount", "", "FUSE mount point")
	duration  = flag.Duration("duration", 15*time.Minute, "Test duration")
	workers   = flag.Int("workers", 8, "Number of concurrent workers")
	maxSize   = flag.Int64("max-total-size", 1024*1024*1024, "Max total data size (1GB)")
)

type fileInfo struct {
	path string
	hash [32]byte
	size int64
}

type metrics struct {
	ops      uint64
	bytes    int64
	failures uint64
	files    sync.Map // path -> fileInfo
}

func main() {
	flag.Parse()
	if *mountPath == "" {
		fmt.Println("-mount is required")
		os.Exit(1)
	}

	m := &metrics{}
	start := time.Now()
	ctx_done := make(chan struct{})
	time.AfterFunc(*duration, func() { close(ctx_done) })

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			worker(id, *mountPath, ctx_done, m)
		}(i)
	}

	// Status reporter
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(start)
				ops := atomic.LoadUint64(&m.ops)
				throughput := float64(atomic.LoadInt64(&m.bytes)) / 1024 / 1024 / elapsed.Seconds()
				fmt.Printf("[%v] Ops: %d, Failures: %d, Speed: %.2f MB/s\n", elapsed.Truncate(time.Second), ops, atomic.LoadUint64(&m.failures), throughput)
			case <-ctx_done:
				return
			}
		}
	}()

	wg.Wait()
	fmt.Printf("\n--- Final Report ---\n")
	fmt.Printf("Total Time: %v\n", time.Since(start))
	fmt.Printf("Total Ops:  %d\n", atomic.LoadUint64(&m.ops))
	fmt.Printf("Failures:   %d\n", atomic.LoadUint64(&m.failures))
	fmt.Printf("Avg Speed:  %.2f MB/s\n", float64(atomic.LoadInt64(&m.bytes))/1024/1024/time.Since(start).Seconds())
}

func worker(id int, base string, done chan struct{}, m *metrics) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
	workerDir := filepath.Join(base, fmt.Sprintf("worker-%d", id))
	os.MkdirAll(workerDir, 0755)

	for {
		select {
		case <-done:
			return
		default:
			op := rng.Intn(100)
			performed := false
			switch {
			case op < 40: // Write (40%)
				// Check total size
				if atomic.LoadInt64(&m.bytes) < *maxSize {
					doWrite(rng, workerDir, m)
					performed = true
				} else {
					// Size limit reached, use randomized sleep to prevent synchronized wake-ups
					time.Sleep(time.Duration(rng.Intn(500)) * time.Millisecond)
				}
			case op < 70: // Read & Verify (30%)
				doRead(rng, m)
				performed = true
			case op < 85: // Rename/Link (15%)
				doMetadata(rng, workerDir, m)
				performed = true
			default: // Delete (15%)
				doDelete(rng, m)
				performed = true
			}
			if performed {
				atomic.AddUint64(&m.ops, 1)
			}
		}
	}
}

func doWrite(rng *rand.Rand, base string, m *metrics) {
	name := fmt.Sprintf("file-%d", rng.Int63())
	path := filepath.Join(base, name)
	size := rng.Int63n(10 * 1024 * 1024) // Up to 10MB
	data := make([]byte, size)
	rng.Read(data)

	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Printf("WRITE FAILURE: %v\n", err)
		atomic.AddUint64(&m.failures, 1)
		return
	}

	hash := sha256.Sum256(data)
	m.files.Store(path, fileInfo{path: path, hash: hash, size: size})
	atomic.AddInt64(&m.bytes, size)
}

func doRead(rng *rand.Rand, m *metrics) {
	var target fileInfo
	found := false
	m.files.Range(func(key, value interface{}) bool {
		target = value.(fileInfo)
		found = true
		return false // pick first
	})

	if !found {
		return
	}

	data, err := os.ReadFile(target.path)
	if err != nil {
		fmt.Printf("READ FAILURE: %s: %v\n", target.path, err)
		atomic.AddUint64(&m.failures, 1)
		return
	}

	if sha256.Sum256(data) != target.hash {
		fmt.Printf("INTEGRITY FAILURE: %s\n", target.path)
		atomic.AddUint64(&m.failures, 1)
	}
}

func doMetadata(rng *rand.Rand, base string, m *metrics) {
	var target fileInfo
	found := false
	m.files.Range(func(key, value interface{}) bool {
		target = value.(fileInfo)
		found = true
		return false
	})

	if !found {
		return
	}

	op := rng.Intn(2)
	newName := fmt.Sprintf("new-%d", rng.Int63())
	newPath := filepath.Join(base, newName)

	if op == 0 { // Rename
		if err := os.Rename(target.path, newPath); err == nil {
			m.files.Delete(target.path)
			target.path = newPath
			m.files.Store(newPath, target)
		} else {
			fmt.Printf("RENAME FAILURE: %v\n", err)
			atomic.AddUint64(&m.failures, 1)
		}
	} else { // Link
		if err := os.Link(target.path, newPath); err == nil {
			m.files.Store(newPath, fileInfo{path: newPath, hash: target.hash, size: target.size})
		} else {
			fmt.Printf("LINK FAILURE: %v\n", err)
			atomic.AddUint64(&m.failures, 1)
		}
	}
}

func doDelete(rng *rand.Rand, m *metrics) {
	var path string
	found := false
	m.files.Range(func(key, value interface{}) bool {
		path = key.(string)
		found = true
		return false
	})

	if !found {
		return
	}

	var sz int64
	fi, err := os.Stat(path)
	if err == nil {
		sz = fi.Size()
	}
	if err := os.Remove(path); err == nil {
		m.files.Delete(path)
		atomic.AddInt64(&m.bytes, -sz)
	} else {
		if !os.IsNotExist(err) {
			atomic.AddUint64(&m.failures, 1)
		}
	}
}
