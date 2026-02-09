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
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrExists   = errors.New("already exists")
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("version conflict")
)

type MetadataFSM struct {
	db         *bolt.DB
	path       string
	OnSnapshot func()
}

func NewMetadataFSM(path string) (*MetadataFSM, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		buckets := []string{"inodes", "nodes", "users", "groups"}
		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return err
			}
		}
		return nil
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
	CmdCreateInode     CommandType = 1
	CmdUpdateInode     CommandType = 2
	CmdDeleteInode     CommandType = 3
	CmdRegisterNode    CommandType = 4
	CmdHeartbeatNode   CommandType = 5
	CmdCreateUser      CommandType = 6
	CmdCreateGroup     CommandType = 7
	CmdUpdateGroup     CommandType = 8
	CmdAddChild        CommandType = 9
	CmdRemoveChild     CommandType = 10
	CmdAddChunkReplica CommandType = 11
)

type LogCommand struct {
	Type CommandType `json:"type"`
	Data []byte      `json:"data"`
}

type ChildUpdate struct {
	ParentID string `json:"parent_id"`
	Name     string `json:"name"`
	ChildID  string `json:"child_id"`
}

type AddReplicaRequest struct {
	InodeID string   `json:"inode_id"`
	ChunkID string   `json:"chunk_id"`
	NodeIDs []string `json:"node_ids"`
}

func (fsm *MetadataFSM) Apply(l *raft.Log) interface{} {
	var cmd LogCommand
	if err := json.Unmarshal(l.Data, &cmd); err != nil {
		return err
	}

	switch cmd.Type {
	case CmdCreateInode:
		return fsm.applyCreateInode(cmd.Data)
	case CmdUpdateInode:
		return fsm.applyUpdateInode(cmd.Data)
	case CmdDeleteInode:
		return fsm.applyDeleteInode(cmd.Data)
	case CmdRegisterNode, CmdHeartbeatNode:
		return fsm.applyRegisterNode(cmd.Data)
	case CmdCreateUser:
		return fsm.applyCreateUser(cmd.Data)
	case CmdCreateGroup:
		return fsm.applyCreateGroup(cmd.Data)
	case CmdUpdateGroup:
		return fsm.applyUpdateGroup(cmd.Data)
	case CmdAddChild:
		return fsm.applyAddChild(cmd.Data)
	case CmdRemoveChild:
		return fsm.applyRemoveChild(cmd.Data)
	case CmdAddChunkReplica:
		return fsm.applyAddChunkReplica(cmd.Data)
	}
	return fmt.Errorf("unknown command")
}

func (fsm *MetadataFSM) applyCreateInode(data []byte) interface{} {
	var inode Inode
	if err := json.Unmarshal(data, &inode); err != nil {
		return err
	}

	err := fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		if b.Get([]byte(inode.ID)) != nil {
			return ErrExists
		}
		inode.Version = 1
		encoded, err := json.Marshal(inode)
		if err != nil {
			return err
		}
		return b.Put([]byte(inode.ID), encoded)
	})
	if err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) applyUpdateInode(data []byte) interface{} {
	var inode Inode
	if err := json.Unmarshal(data, &inode); err != nil {
		return err
	}

	err := fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(inode.ID))
		if v == nil {
			return ErrNotFound
		}
		var existing Inode
		if err := json.Unmarshal(v, &existing); err != nil {
			return err
		}

		if inode.Version != existing.Version {
			return ErrConflict
		}

		inode.Version++
		encoded, err := json.Marshal(inode)
		if err != nil {
			return err
		}
		return b.Put([]byte(inode.ID), encoded)
	})
	if err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) applyDeleteInode(data []byte) interface{} {
	id := string(data)
	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		return b.Delete([]byte(id))
	})
}

func (fsm *MetadataFSM) applyRegisterNode(data []byte) interface{} {
	var node Node
	if err := json.Unmarshal(data, &node); err != nil {
		return err
	}

	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		encoded, err := json.Marshal(node)
		if err != nil {
			return err
		}
		return b.Put([]byte(node.ID), encoded)
	})
}

func (fsm *MetadataFSM) applyCreateUser(data []byte) interface{} {
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return err
	}
	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		if b.Get([]byte(user.ID)) != nil {
			return ErrExists
		}
		encoded, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return b.Put([]byte(user.ID), encoded)
	})
}

func (fsm *MetadataFSM) applyCreateGroup(data []byte) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return err
	}
	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		if b.Get([]byte(group.ID)) != nil {
			return ErrExists
		}
		encoded, err := json.Marshal(group)
		if err != nil {
			return err
		}
		return b.Put([]byte(group.ID), encoded)
	})
}

func (fsm *MetadataFSM) applyUpdateGroup(data []byte) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return err
	}
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		if b.Get([]byte(group.ID)) == nil {
			return ErrNotFound
		}
		encoded, err := json.Marshal(group)
		if err != nil {
			return err
		}
		return b.Put([]byte(group.ID), encoded)
	})
	if err != nil {
		return err
	}
	return &group
}

func (fsm *MetadataFSM) applyAddChild(data []byte) interface{} {
	var update ChildUpdate
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}

	var inode Inode
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(update.ParentID))
		if v == nil {
			return ErrNotFound
		}

		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}

		if inode.Type != DirType {
			return fmt.Errorf("parent not a directory")
		}
		if inode.Children == nil {
			inode.Children = make(map[string]string)
		}

		if _, exists := inode.Children[update.Name]; exists {
			return ErrExists
		}

		inode.Children[update.Name] = update.ChildID
		inode.Version++

		encoded, err := json.Marshal(inode)
		if err != nil {
			return err
		}
		return b.Put([]byte(inode.ID), encoded)
	})
	if err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) applyRemoveChild(data []byte) interface{} {
	var update ChildUpdate
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}

	var inode Inode
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(update.ParentID))
		if v == nil {
			return ErrNotFound
		}

		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}

		if inode.Type != DirType {
			return fmt.Errorf("parent not a directory")
		}

		if inode.Children == nil {
			return ErrNotFound
		}
		if _, exists := inode.Children[update.Name]; !exists {
			return ErrNotFound
		}

		delete(inode.Children, update.Name)
		inode.Version++

		encoded, err := json.Marshal(inode)
		if err != nil {
			return err
		}
		return b.Put([]byte(inode.ID), encoded)
	})
	if err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) applyAddChunkReplica(data []byte) interface{} {
	var req AddReplicaRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	var inode Inode
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(req.InodeID))
		if v == nil {
			return ErrNotFound
		}

		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}

		updated := false
		for i, chunk := range inode.ChunkManifest {
			if chunk.ID == req.ChunkID {
				for _, newID := range req.NodeIDs {
					exists := false
					for _, existingID := range chunk.Nodes {
						if existingID == newID {
							exists = true
							break
						}
					}
					if !exists {
						inode.ChunkManifest[i].Nodes = append(inode.ChunkManifest[i].Nodes, newID)
						updated = true
					}
				}
				break
			}
		}

		if updated {
			inode.Version++
			encoded, err := json.Marshal(inode)
			if err != nil {
				return err
			}
			return b.Put([]byte(inode.ID), encoded)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) Snapshot() (raft.FSMSnapshot, error) {
	if fsm.OnSnapshot != nil {
		fsm.OnSnapshot()
	}
	return &MetadataSnapshot{db: fsm.db}, nil
}

func (fsm *MetadataFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()

	if err := fsm.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}

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

	if err := os.Rename(tmpPath, fsm.path); err != nil {
		os.Remove(tmpPath)
		fsm.reopen()
		return err
	}

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