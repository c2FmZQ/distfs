//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

type NativeStore struct {
	baseDir  string
	maxBytes int64
	db       *bbolt.DB
	mu       sync.RWMutex
}

func NewNativeStore(baseDir string, maxBytes int64) (*NativeStore, error) {
	if err := os.MkdirAll(filepath.Join(baseDir, "chunks"), 0700); err != nil {
		return nil, err
	}

	db, err := bbolt.Open(filepath.Join(baseDir, "metadata.db"), 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata db: %w", err)
	}

	return &NativeStore{
		baseDir:  baseDir,
		maxBytes: maxBytes,
		db:       db,
	}, nil
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

	// Trigger pruning if limit is set
	if s.maxBytes > 0 {
		go s.Prune()
	}

	return nil
}

func (s *NativeStore) deleteChunk(key string) error {
	path := s.getChunkPath(key)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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

	return nil
}
