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

package data

import (
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/c2FmZQ/storage"
)

// DiskStore implements Store using github.com/c2FmZQ/storage for encryption at rest.
type DiskStore struct {
	st *storage.Storage
	mu sync.Mutex // Serialize writes to avoid potential concurrency issues in storage lib
}

// NewDiskStore creates a new DiskStore backed by the provided encrypted storage.
func NewDiskStore(st *storage.Storage) (*DiskStore, error) {
	return &DiskStore{st: st}, nil
}

// Close closes the store. Currently a no-op for DiskStore.
func (s *DiskStore) Close() error {
	return nil
}

func (s *DiskStore) WriteChunk(id string, data io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !validChunkID.MatchString(id) {
		return fmt.Errorf("invalid chunk id format")
	}

	// Idempotency: If chunk exists, don't overwrite.
	// This avoids race conditions with concurrent uploads of identical chunks (e.g. zeros).
	if exists, _ := s.HasChunk(id); exists {
		return nil
	}

	wc, err := s.st.OpenBlobWrite(id, id)
	if err != nil {
		return err
	}

	if _, err := io.Copy(wc, data); err != nil {
		wc.Close()
		return err
	}
	return wc.Close()
}

func (s *DiskStore) ReadChunk(id string) (io.ReadCloser, error) {
	if !validChunkID.MatchString(id) {
		return nil, fmt.Errorf("invalid chunk id format")
	}
	return s.st.OpenBlobRead(id)
}

func (s *DiskStore) HasChunk(id string) (bool, error) {
	rc, err := s.st.OpenBlobRead(id)
	if err == nil {
		rc.Close()
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (s *DiskStore) GetChunkSize(id string) (int64, error) {
	rc, err := s.st.OpenBlobRead(id)
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	size, err := rc.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	return size, nil
}

func (s *DiskStore) DeleteChunk(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	var path string

	err := filepath.WalkDir(s.st.Dir(), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == id {
			found = true
			path = p
			return fmt.Errorf("stop")
		}
		return nil
	})

	if found && path != "" {
		return os.Remove(path)
	}
	if err != nil && err.Error() != "stop" {
		return err
	}

	return os.ErrNotExist
}

// ListChunks returns an iterator.
func (s *DiskStore) ListChunks() iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		err := filepath.WalkDir(s.st.Dir(), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if strings.HasSuffix(name, ".tmp") {
				return nil
			}
			if validChunkID.MatchString(name) {
				if !yield(name, nil) {
					return fmt.Errorf("stop")
				}
			}
			return nil
		})
		if err != nil && err.Error() != "stop" {
			yield("", err)
		}
	}
}

func (s *DiskStore) Stats() (int64, int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.st.Dir(), &stat); err != nil {
		return 0, 0, err
	}
	capacity := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bfree) * int64(stat.Bsize)
	return capacity, capacity - free, nil
}
