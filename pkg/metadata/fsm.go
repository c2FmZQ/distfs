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

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

type MetadataFSM struct {
	db   *bolt.DB
	path string
}

func NewMetadataFSM(path string) (*MetadataFSM, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("inodes"))
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &MetadataFSM{db: db, path: path}, nil
}

func (fsm *MetadataFSM) Close() error {
	if fsm.db != nil {
		return fsm.db.Close()
	}
	return nil
}

type CommandType uint8

const (
	CmdCreateInode CommandType = 1
	CmdUpdateInode CommandType = 2
	CmdDeleteInode CommandType = 3
)

type LogCommand struct {
	Type CommandType `json:"type"`
	Data []byte      `json:"data"`
}

func (fsm *MetadataFSM) Apply(l *raft.Log) interface{} {
	var cmd LogCommand
	if err := json.Unmarshal(l.Data, &cmd); err != nil {
		return err
	}

	switch cmd.Type {
	case CmdCreateInode, CmdUpdateInode:
		return fsm.applyUpdateInode(cmd.Data)
	case CmdDeleteInode:
		return fsm.applyDeleteInode(cmd.Data)
	}
	return fmt.Errorf("unknown command")
}

func (fsm *MetadataFSM) applyUpdateInode(data []byte) interface{} {
	var inode Inode
	if err := json.Unmarshal(data, &inode); err != nil {
		return err
	}

	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		encoded, err := json.Marshal(inode)
		if err != nil {
			return err
		}
		return b.Put([]byte(inode.ID), encoded)
	})
}

func (fsm *MetadataFSM) applyDeleteInode(data []byte) interface{} {
	id := string(data)
	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		return b.Delete([]byte(id))
	})
}

func (fsm *MetadataFSM) Snapshot() (raft.FSMSnapshot, error) {
	return &MetadataSnapshot{db: fsm.db}, nil
}

func (fsm *MetadataFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()

	// Close current DB to release lock
	if err := fsm.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}

	// Write snapshot to temp file
	tmpPath := fsm.path + ".restore.tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		fsm.reopen()
		return err
	}

	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		os.Remove(tmpPath)
		fsm.reopen()
		return err
	}
	f.Close()

	// Atomic replace
	if err := os.Rename(tmpPath, fsm.path); err != nil {
		os.Remove(tmpPath)
		fsm.reopen()
		return err
	}

	// Reopen
	return fsm.reopen()
}

func (fsm *MetadataFSM) reopen() error {
	db, err := bolt.Open(fsm.path, 0600, nil)
	if err != nil {
		return err
	}
	fsm.db = db
	return nil
}

type MetadataSnapshot struct {
	db *bolt.DB
}

func (s *MetadataSnapshot) Persist(sink raft.SnapshotSink) error {
	err := s.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(sink)
		return err
	})
	if err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *MetadataSnapshot) Release() {}