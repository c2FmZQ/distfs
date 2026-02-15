// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
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
	bytes    uint64
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
				throughput := float64(atomic.LoadUint64(&m.bytes)) / 1024 / 1024 / elapsed.Seconds()
				fmt.Printf("[%v] Ops: %d, Failures: %d, Speed: %.2f MB/s
", elapsed.Truncate(time.Second), ops, atomic.LoadUint64(&m.failures), throughput)
			case <-ctx_done:
				return
			}
		}
	}()

	wg.Wait()
	fmt.Printf("
--- Final Report ---
")
	fmt.Printf("Total Time: %v
", time.Since(start))
	fmt.Printf("Total Ops:  %d
", atomic.LoadUint64(&m.ops))
	fmt.Printf("Failures:   %d
", atomic.LoadUint64(&m.failures))
	fmt.Printf("Avg Speed:  %.2f MB/s
", float64(atomic.LoadUint64(&m.bytes))/1024/1024/time.Since(start).Seconds())
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
			switch {
			case op < 40: // Write (40%)
				doWrite(rng, workerDir, m)
			case op < 70: // Read & Verify (30%)
				doRead(rng, m)
			case op < 85: // Rename/Link (15%)
				doMetadata(rng, workerDir, m)
			default: // Delete (15%)
				doDelete(rng, m)
			}
			atomic.AddUint64(&m.ops, 1)
		}
	}
}

func doWrite(rng *rand.Rand, base string, m *metrics) {
	// Check total size
	if atomic.LoadUint64(&m.bytes) >= uint64(*maxSize) {
		return
	}

	name := fmt.Sprintf("file-%d", rng.Int63())
	path := filepath.Join(base, name)
	size := rng.Int63n(10 * 1024 * 1024) // Up to 10MB
	data := make([]byte, size)
	rng.Read(data)

	if err := os.WriteFile(path, data, 0644); err != nil {
		atomic.AddUint64(&m.failures, 1)
		return
	}

	hash := sha256.Sum256(data)
	m.files.Store(path, fileInfo{path: path, hash: hash, size: size})
	atomic.AddUint64(&m.bytes, uint64(size))
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
		atomic.AddUint64(&m.failures, 1)
		return
	}

	if sha256.Sum256(data) != target.hash {
		fmt.Printf("INTEGRITY FAILURE: %s
", target.path)
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
			atomic.AddUint64(&m.failures, 1)
		}
	} else { // Link
		if err := os.Link(target.path, newPath); err == nil {
			m.files.Store(newPath, fileInfo{path: newPath, hash: target.hash, size: target.size})
		} else {
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

	if err := os.Remove(path); err == nil {
		m.files.Delete(path)
	} else {
		// Might be a directory if mkdir was used, or already deleted
		if !os.IsNotExist(err) {
			atomic.AddUint64(&m.failures, 1)
		}
	}
}
