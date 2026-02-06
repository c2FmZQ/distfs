// Copyright 2026 TTBT Enterprises LLC
// ... License ...

package data

import (
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"strings"
)

// DiskStore implements Store using the local filesystem.
type DiskStore struct {
	baseDir string
	root    *os.Root // Used for safe reads
}

func NewDiskStore(baseDir string) (*DiskStore, error) {
	if err := os.MkdirAll(baseDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create base dir: %w", err)
	}
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root: %w", err)
	}
	return &DiskStore{baseDir: baseDir, root: root}, nil
}

func (s *DiskStore) Close() error {
	return s.root.Close()
}

func (s *DiskStore) relPath(id string) (string, error) {
	if !validChunkID.MatchString(id) {
		return "", fmt.Errorf("invalid chunk id format")
	}
	// Sharding: 2 levels: ab/cd/abcdef...
	return filepath.Join(id[:2], id[2:4], id), nil
}

func (s *DiskStore) WriteChunk(id string, data io.Reader) error {
	rel, err := s.relPath(id)
	if err != nil {
		return err
	}
	
	// Absolute path for Write/Rename (since os.Root doesn't support Rename easily)
	absPath := filepath.Join(s.baseDir, rel)
	dir := filepath.Dir(absPath)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	// Create unique temp file in the same directory to ensure same filesystem for Rename
	f, err := os.CreateTemp(dir, "tmp-*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
    
    // Clean up temp file on failure (or success if rename fails)
    // If rename succeeds, file is gone (moved), Remove fails (ignore).
    // If we defer Remove, it runs after Rename.
    defer os.Remove(tmpName) 

	if _, err := io.Copy(f, data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	return os.Rename(tmpName, absPath)
}

func (s *DiskStore) ReadChunk(id string) (io.ReadCloser, error) {
	rel, err := s.relPath(id)
	if err != nil {
		return nil, err
	}
	// Use os.Root for safe open
	return s.root.Open(rel)
}

func (s *DiskStore) HasChunk(id string) (bool, error) {
	rel, err := s.relPath(id)
	if err != nil {
		return false, err
	}
	_, err = s.root.Stat(rel)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (s *DiskStore) GetChunkSize(id string) (int64, error) {
	rel, err := s.relPath(id)
	if err != nil {
		return 0, err
	}
	fi, err := s.root.Stat(rel)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (s *DiskStore) DeleteChunk(id string) error {
	rel, err := s.relPath(id)
	if err != nil {
		return err
	}
	return s.root.Remove(rel)
}

// ListChunks returns an iterator.
func (s *DiskStore) ListChunks() iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		err := filepath.WalkDir(s.baseDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, "tmp-") { // Ignore temp files
				return nil
			}
			// Only yield if name looks like a chunk ID?
			// Since we shard, the filename IS the ID (e.g. abcdef...)
			if validChunkID.MatchString(name) {
				if !yield(name, nil) {
					return fs.SkipAll
				}
			}
			return nil
		})
		if err != nil {
			yield("", err)
		}
	}
}