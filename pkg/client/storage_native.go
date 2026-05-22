//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.etcd.io/bbolt"
)

type NativeStore struct {
	baseDir  string
	maxBytes int64
	db       *bbolt.DB
	mu       sync.RWMutex

	// Phase 76.3: Throttled & estimated cache pruning.
	// estimatedBytes tracks the approximate on-disk chunk usage atomically,
	// updated on every put/delete so we can skip Prune when under the limit.
	estimatedBytes atomic.Int64
	// pruning is a single-flight flag: 0=idle, 1=running.
	pruning atomic.Int32
	// lastPrune records when the last prune completed (guarded by mu).
	lastPrune time.Time
	// pruneInterval is the rate-limit interval for auto-pruning.
	pruneInterval time.Duration
}

func NewNativeStore(baseDir string, maxBytes int64) (*NativeStore, error) {
	if err := os.MkdirAll(filepath.Join(baseDir, "chunks"), 0700); err != nil {
		return nil, err
	}

	db, err := bbolt.Open(filepath.Join(baseDir, "metadata.db"), 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata db: %w", err)
	}

	s := &NativeStore{
		baseDir:       baseDir,
		maxBytes:      maxBytes,
		db:            db,
		pruneInterval: 30 * time.Second,
	}

	// Phase 76.3: Initialise the byte estimate in the background to avoid
	// blocking NewNativeStore on potentially large directory walks.
	go s.initEstimatedBytes()

	return s, nil
}

// initEstimatedBytes performs a one-time directory walk to seed estimatedBytes.
func (s *NativeStore) initEstimatedBytes() {
	var total int64
	chunksDir := filepath.Join(s.baseDir, "chunks")
	_ = filepath.WalkDir(chunksDir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	s.estimatedBytes.Store(total)
}

func (s *NativeStore) Get(bucket, key string) ([]byte, error) {
	if bucket == "chunks" {
		return s.getChunk(key)
	}

	var val []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return ErrNotFound
		}
		v := b.Get([]byte(key))
		if v == nil {
			return ErrNotFound
		}
		val = make([]byte, len(v))
		copy(val, v)
		return nil
	})
	return val, err
}

func (s *NativeStore) Put(bucket, key string, value []byte) error {
	if bucket == "chunks" {
		return s.putChunk(key, value)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), value)
	})
}

func (s *NativeStore) Delete(bucket, key string) error {
	if bucket == "chunks" {
		return s.deleteChunk(key)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

func (s *NativeStore) Close() error {
	return s.db.Close()
}

func (s *NativeStore) getChunkPath(key string) string {
	key = filepath.Base(key)
	if len(key) < 4 {
		return filepath.Join(s.baseDir, "chunks", key)
	}
	return filepath.Join(s.baseDir, "chunks", key[:2], key[2:4], key)
}

func (s *NativeStore) getChunk(key string) ([]byte, error) {
	path := s.getChunkPath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// Update access time for LRU
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	return data, nil
}

func (s *NativeStore) putChunk(key string, value []byte) error {
	path := s.getChunkPath(key)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Ensure atomic write via temporary file and rename
	tmp, err := os.CreateTemp(dir, key+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(value); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	// Phase 76.3: Update estimated byte count and conditionally prune.
	s.estimatedBytes.Add(int64(len(value)))
	if s.maxBytes > 0 && s.estimatedBytes.Load() > s.maxBytes {
		s.maybeSchedulePrune()
	}

	return nil
}

func (s *NativeStore) deleteChunk(key string) error {
	path := s.getChunkPath(key)

	// Phase 76.3: Stat before removal so we can update the byte estimate.
	if info, err := os.Stat(path); err == nil {
		s.estimatedBytes.Add(-info.Size())
	}

	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SetPruneInterval sets the rate-limit interval for background auto-pruning.
// Set to 0 to run auto-pruning on every limit breach without rate-limiting.
func (s *NativeStore) SetPruneInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneInterval = d
}

// maybeSchedulePrune schedules a single background Prune run if:
//   - No prune is already running (single-flight via atomic CAS), and
//   - At least pruneInterval has elapsed since the last prune run.
func (s *NativeStore) maybeSchedulePrune() {
	// Single-flight: only one prune goroutine at a time.
	if !s.pruning.CompareAndSwap(0, 1) {
		return
	}
	s.mu.RLock()
	since := time.Since(s.lastPrune)
	interval := s.pruneInterval
	s.mu.RUnlock()
	if interval > 0 && since < interval {
		s.pruning.Store(0)
		return
	}
	go func() {
		defer s.pruning.Store(0)
		s.mu.Lock()
		s.lastPrune = time.Now()
		s.mu.Unlock()
		_ = s.Prune()
	}()
}

type chunkInfo struct {
	path  string
	size  int64
	atime time.Time
}

func (s *NativeStore) Prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var chunks []chunkInfo
	var totalSize int64

	chunksDir := filepath.Join(s.baseDir, "chunks")
	err := filepath.WalkDir(chunksDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return nil
			}
			chunks = append(chunks, chunkInfo{
				path:  path,
				size:  info.Size(),
				atime: info.ModTime(), // Using ModTime as proxy for Atime (updated by Chtimes)
			})
			totalSize += info.Size()
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Phase 76.3: Refresh the atomic estimate from the actual walk result.
	s.estimatedBytes.Store(totalSize)

	if totalSize <= s.maxBytes {
		return nil
	}

	// Sort by access time (oldest first)
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].atime.Before(chunks[j].atime)
	})

	// Delete until under limit
	for _, c := range chunks {
		if totalSize <= s.maxBytes {
			break
		}
		if err := os.Remove(c.path); err == nil {
			totalSize -= c.size
		}
	}

	// Refresh estimate one final time after deletions.
	s.estimatedBytes.Store(totalSize)

	return nil
}
