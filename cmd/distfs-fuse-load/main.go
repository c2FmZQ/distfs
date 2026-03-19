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
	workDir   = flag.String("workdir", "", "Subdirectory within mount point to perform operations")
	duration  = flag.Duration("duration", 15*time.Minute, "Test duration")
	workers   = flag.Int("workers", 8, "Number of concurrent workers")
	maxSize   = flag.Int64("max-total-size", 1024*1024*1024, "Max total data size (1GB)")
)

type FileType int

const (
	TypeFile FileType = iota
	// TypeDir // Directory renaming logic is complex to track safely, skipping for this iteration
)

type Item struct {
	Path string
	Hash [32]byte
	Size int64
}

type State struct {
	mu    sync.Mutex
	items map[string]*Item // Path -> Item
	busy  map[string]bool  // Path -> IsBusy (checked out by a worker)
}

func NewState() *State {
	return &State{
		items: make(map[string]*Item),
		busy:  make(map[string]bool),
	}
}

// Checkout attempts to lock a random file.
func (s *State) Checkout(rng *rand.Rand) *Item {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reservoir sampling to pick random item efficiently-ish
	var candidates []*Item
	for path, item := range s.items {
		if !s.busy[path] {
			candidates = append(candidates, item)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	item := candidates[rng.Intn(len(candidates))]
	s.busy[item.Path] = true
	return item
}

func (s *State) Checkin(item *Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, item.Path)
}

func (s *State) Add(item *Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[item.Path] = item
}

func (s *State) Remove(item *Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, item.Path)
	delete(s.busy, item.Path)
}

// Rename updates the path in the state map. The item MUST be checked out.
func (s *State) Rename(item *Item, newPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldPath := item.Path
	delete(s.items, oldPath)
	delete(s.busy, oldPath)

	item.Path = newPath
	s.items[newPath] = item
	s.busy[newPath] = true
}

type metrics struct {
	ops         uint64
	bytes       int64 // Current usage
	transferred int64 // Total I/O bytes
	failures    uint64
}

func main() {
	flag.Parse()

	startPprofServer()

	if *mountPath == "" {
		fmt.Println("-mount is required")
		os.Exit(1)
	}

	state := NewState()
	m := &metrics{}
	start := time.Now()
	ctx_done := make(chan struct{})
	time.AfterFunc(*duration, func() { close(ctx_done) })

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			worker(id, filepath.Join(*mountPath, *workDir), ctx_done, m, state)
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
				throughput := float64(atomic.LoadInt64(&m.transferred)) / 1024 / 1024 / elapsed.Seconds()
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
	fmt.Printf("Avg Speed:  %.2f MB/s\n", float64(atomic.LoadInt64(&m.transferred))/1024/1024/time.Since(start).Seconds())
}

func worker(id int, base string, done chan struct{}, m *metrics, state *State) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
	workerDir := filepath.Join(base, fmt.Sprintf("worker-%d", id))
	// Create deep hierarchy
	subDirs := []string{"", "a", "a/b", "c", "d/e"}
	for _, d := range subDirs {
		if err := os.MkdirAll(filepath.Join(workerDir, d), 0755); err != nil {
			fmt.Printf("Worker %d SETUP FAILURE: MkdirAll %s: %v\n", id, d, err)
			os.Exit(1)
		}
	}

	for {
		select {
		case <-done:
			return
		default:
			op := rng.Intn(100)
			performed := false

			switch {
			case op < 40: // Write (Create)
				if atomic.LoadInt64(&m.bytes) < *maxSize {
					subDir := subDirs[rng.Intn(len(subDirs))]
					targetDir := filepath.Join(workerDir, subDir)
					doWrite(rng, targetDir, m, state)
					performed = true
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			case op < 70: // Read
				doRead(rng, m, state)
				performed = true
			case op < 85: // Rename
				subDir := subDirs[rng.Intn(len(subDirs))]
				targetDir := filepath.Join(workerDir, subDir)
				doRename(rng, targetDir, m, state)
				performed = true
			default: // Delete
				doDelete(rng, m, state)
				performed = true
			}

			if performed {
				atomic.AddUint64(&m.ops, 1)
			}
		}
	}
}

func doWrite(rng *rand.Rand, base string, m *metrics, state *State) {
	name := fmt.Sprintf("file-%d-%d", time.Now().UnixNano(), rng.Int63())
	path := filepath.Join(base, name)
	size := rng.Int63n(5*1024*1024) + 1024 // 1KB to 5MB
	data := make([]byte, size)
	rng.Read(data)

	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Printf("WRITE FAILURE: %v\n", err)
		atomic.AddUint64(&m.failures, 1)
		return
	}

	hash := sha256.Sum256(data)
	state.Add(&Item{Path: path, Hash: hash, Size: size})
	atomic.AddInt64(&m.bytes, size)
	atomic.AddInt64(&m.transferred, size)
}

func doRead(rng *rand.Rand, m *metrics, state *State) {
	item := state.Checkout(rng)
	if item == nil {
		return
	}
	defer state.Checkin(item)

	data, err := os.ReadFile(item.Path)
	if err != nil {
		fmt.Printf("READ FAILURE: %s: %v\n", item.Path, err)
		atomic.AddUint64(&m.failures, 1)
		return
	}

	atomic.AddInt64(&m.transferred, int64(len(data)))

	if sha256.Sum256(data) != item.Hash {
		fmt.Printf("INTEGRITY FAILURE: %s\n", item.Path)
		atomic.AddUint64(&m.failures, 1)
	}
}

func doRename(rng *rand.Rand, destDir string, m *metrics, state *State) {
	item := state.Checkout(rng)
	if item == nil {
		return
	}
	// Note: We don't defer Checkin here because Rename modifies the item/map
	// and handles checkin logic or we call it explicitly.
	// But to be safe, if we fail, we must Checkin.
	success := false
	defer func() {
		if !success {
			state.Checkin(item)
		}
	}()

	newName := fmt.Sprintf("renamed-%d-%d", time.Now().UnixNano(), rng.Int63())
	newPath := filepath.Join(destDir, newName)

	if err := os.Rename(item.Path, newPath); err == nil {
		state.Rename(item, newPath)
		state.Checkin(item) // Check in with new path
		success = true
	} else {
		fmt.Printf("RENAME FAILURE: %v\n", err)
		atomic.AddUint64(&m.failures, 1)
	}
}

func doDelete(rng *rand.Rand, m *metrics, state *State) {
	item := state.Checkout(rng)
	if item == nil {
		return
	}
	// If delete succeeds, we Remove (which clears busy).
	// If fail, we Checkin.

	if err := os.Remove(item.Path); err == nil {
		state.Remove(item)
		atomic.AddInt64(&m.bytes, -item.Size)
	} else {
		fmt.Printf("DELETE FAILURE: %s: %v\n", item.Path, err)
		atomic.AddUint64(&m.failures, 1)
		state.Checkin(item)
	}
}
