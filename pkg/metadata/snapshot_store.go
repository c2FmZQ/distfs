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

package metadata

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/c2FmZQ/storage"
	"github.com/hashicorp/raft"
)

// StorageSnapshotStore implements raft.SnapshotStore using github.com/c2FmZQ/storage.
type StorageSnapshotStore struct {
	st *storage.Storage
}

func NewStorageSnapshotStore(st *storage.Storage) *StorageSnapshotStore {
	return &StorageSnapshotStore{st: st}
}

func (s *StorageSnapshotStore) Create(version raft.SnapshotVersion, index, term uint64, configuration raft.Configuration, configurationIndex uint64, trans raft.Transport) (raft.SnapshotSink, error) {
	// Generate ID: snapshot-term-index
	id := fmt.Sprintf("snapshot-%d-%d", term, index)

	// Create Sink
	return &StorageSnapshotSink{
		st: s.st,
		id: id,
		meta: raft.SnapshotMeta{
			Version:            version,
			ID:                 id,
			Index:              index,
			Term:               term,
			Configuration:      configuration,
			ConfigurationIndex: configurationIndex,
		},
	}, nil
}

func (s *StorageSnapshotStore) List() ([]*raft.SnapshotMeta, error) {
	var snapshots []*raft.SnapshotMeta

	err := filepath.WalkDir(s.st.Dir(), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "snapshot-meta-") {
			rc, err := s.st.OpenBlobRead(name)
			if err != nil {
				return nil // Skip if open fails
			}
			defer rc.Close()
			var meta raft.SnapshotMeta
			if err := json.NewDecoder(rc).Decode(&meta); err == nil {
				snapshots = append(snapshots, &meta)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort (reverse index)
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Index > snapshots[j].Index
	})

	return snapshots, nil
}

func (s *StorageSnapshotStore) Open(id string) (*raft.SnapshotMeta, io.ReadCloser, error) {
	// Read Meta
	metaName := "snapshot-meta-" + id
	rc, err := s.st.OpenBlobRead(metaName)
	if err != nil {
		return nil, nil, err
	}
	var meta raft.SnapshotMeta
	err = json.NewDecoder(rc).Decode(&meta)
	rc.Close()
	if err != nil {
		return nil, nil, err
	}

	// Read Data
	dataName := "snapshot-data-" + id
	dataRc, err := s.st.OpenBlobRead(dataName)
	if err != nil {
		return nil, nil, err
	}

	return &meta, dataRc, nil
}

type StorageSnapshotSink struct {
	st     *storage.Storage
	id     string
	meta   raft.SnapshotMeta
	wc     io.WriteCloser
	closed bool
}

func (s *StorageSnapshotSink) Write(p []byte) (int, error) {
	if s.wc == nil {
		var err error
		finalName := "snapshot-data-" + s.id
		tempName := finalName + ".tmp"
		s.wc, err = s.st.OpenBlobWrite(tempName, finalName)
		if err != nil {
			return 0, err
		}
	}
	return s.wc.Write(p)
}

func (s *StorageSnapshotSink) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.wc != nil {
		if err := s.wc.Close(); err != nil {
			return err
		}
	}

	// Save Meta
	finalName := "snapshot-meta-" + s.id
	tempName := finalName + ".tmp"
	wc, err := s.st.OpenBlobWrite(tempName, finalName)
	if err != nil {
		return err
	}
	defer wc.Close()
	if err := json.NewEncoder(wc).Encode(s.meta); err != nil {
		return err
	}
	return wc.Close()
}

func (s *StorageSnapshotSink) ID() string {
	return s.id
}

func (s *StorageSnapshotSink) Cancel() error {
	s.closed = true
	if s.wc != nil {
		s.wc.Close()
	}
	// Attempt cleanup
	os.Remove(filepath.Join(s.st.Dir(), "snapshot-data-"+s.id))
	os.Remove(filepath.Join(s.st.Dir(), "snapshot-meta-"+s.id))
	return nil
}
