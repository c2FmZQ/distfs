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
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
		buckets := []string{"inodes", "nodes", "users", "groups", "uids", "gids", "garbage_collection", "chunk_pages"}
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
	CmdRename          CommandType = 12
	CmdSetAttr         CommandType = 13
	CmdLink            CommandType = 14
	CmdGCRemove        CommandType = 15
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

type RenameRequest struct {
	OldParentID string `json:"old_parent_id"`
	OldName     string `json:"old_name"`
	NewParentID string `json:"new_parent_id"`
	NewName     string `json:"new_name"`
}

type SetAttrRequest struct {
	InodeID string  `json:"inode_id"`
	Mode    *uint32 `json:"mode,omitempty"`
	UID     *uint32 `json:"uid,omitempty"`
	GID     *uint32 `json:"gid,omitempty"`
	Size    *uint64 `json:"size,omitempty"`
	MTime   *int64  `json:"mtime,omitempty"`
}

type LinkRequest struct {
	ParentID string `json:"parent_id"`
	Name     string `json:"name"`
	TargetID string `json:"target_id"`
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
	case CmdRename:
		return fsm.applyRename(cmd.Data)
	case CmdSetAttr:
		return fsm.applySetAttr(cmd.Data)
	case CmdLink:
		return fsm.applyLink(cmd.Data)
	case CmdGCRemove:
		return fsm.applyGCRemove(cmd.Data)
	}
	return fmt.Errorf("unknown command")
}

func (fsm *MetadataFSM) applyCreateInode(data []byte) interface{} {
	var inode Inode
	if err := json.Unmarshal(data, &inode); err != nil {
		return err
	}

	now := time.Now().UnixNano()
	if inode.MTime == 0 {
		inode.MTime = now
	}
	if inode.CTime == 0 {
		inode.CTime = now
	}
	if inode.NLink == 0 {
		inode.NLink = 1
	}
	if inode.Mode == 0 {
		if inode.Type == DirType {
			inode.Mode = 0755
		} else {
			inode.Mode = 0644
		}
	}

	err := fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		if b.Get([]byte(inode.ID)) != nil {
			return ErrExists
		}
		inode.Version = 1
		return saveInodeWithPages(tx, &inode)
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

		oldPages := existing.ChunkPages

		inode.Version++
		if err := saveInodeWithPages(tx, &inode); err != nil {
			return err
		}

		// Clean up orphaned pages (pages in old but not in new)
		if len(oldPages) > 0 {
			newPagesMap := make(map[string]bool)
			for _, pid := range inode.ChunkPages {
				newPagesMap[pid] = true
			}

			pb := tx.Bucket([]byte("chunk_pages"))
			for _, pid := range oldPages {
				if !newPagesMap[pid] {
					pb.Delete([]byte(pid))
				}
			}
		}
		return nil
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
		v := b.Get([]byte(id))
		if v != nil {
			var inode Inode
			if err := json.Unmarshal(v, &inode); err == nil {
				if len(inode.ChunkPages) > 0 {
					pb := tx.Bucket([]byte("chunk_pages"))
					for _, pid := range inode.ChunkPages {
						pb.Delete([]byte(pid))
					}
				}
			}
		}
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

	err := fsm.db.Update(func(tx *bolt.Tx) error {
		ub := tx.Bucket([]byte("users"))
		idx := tx.Bucket([]byte("uids"))

		if ub.Get([]byte(user.ID)) != nil {
			return ErrExists
		}

		// Allocate unique UID if not provided or 0
		if user.UID == 0 {
			for {
				uid := generateID32()
				if uid < 1000 {
					continue // Reserve low UIDs
				}
				if idx.Get(uint32ToBytes(uid)) == nil {
					user.UID = uid
					break
				}
			}
		} else {
			// If UID provided, check if already taken
			if existing := idx.Get(uint32ToBytes(user.UID)); existing != nil {
				return fmt.Errorf("UID %d already assigned to %s", user.UID, string(existing))
			}
		}

		encoded, err := json.Marshal(user)
		if err != nil {
			return err
		}

		if err := ub.Put([]byte(user.ID), encoded); err != nil {
			return err
		}
		return idx.Put(uint32ToBytes(user.UID), []byte(user.ID))
	})

	if err != nil {
		return err
	}
	return &user
}

func (fsm *MetadataFSM) applyCreateGroup(data []byte) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return err
	}

	err := fsm.db.Update(func(tx *bolt.Tx) error {
		gb := tx.Bucket([]byte("groups"))
		idx := tx.Bucket([]byte("gids"))

		if gb.Get([]byte(group.ID)) != nil {
			return ErrExists
		}

		// Allocate unique GID if not provided or 0
		if group.GID == 0 {
			for {
				gid := generateID32()
				if gid < 1000 {
					continue // Reserve low GIDs
				}
				if idx.Get(uint32ToBytes(gid)) == nil {
					group.GID = gid
					break
				}
			}
		} else {
			// If GID provided, check if already taken
			if existing := idx.Get(uint32ToBytes(group.GID)); existing != nil {
				return fmt.Errorf("GID %d already assigned to %s", group.GID, string(existing))
			}
		}

		encoded, err := json.Marshal(group)
		if err != nil {
			return err
		}

		if err := gb.Put([]byte(group.ID), encoded); err != nil {
			return err
		}
		return idx.Put(uint32ToBytes(group.GID), []byte(group.ID))
	})

	if err != nil {
		return err
	}
	return &group
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

func (fsm *MetadataFSM) applyLink(data []byte) interface{} {
	var req LinkRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))

		// 1. Load Target
		vTarget := b.Get([]byte(req.TargetID))
		if vTarget == nil {
			return ErrNotFound
		}
		var target Inode
		if err := json.Unmarshal(vTarget, &target); err != nil {
			return err
		}

		if target.Type == DirType {
			return fmt.Errorf("cannot link directory")
		}

		// 2. Load Parent
		vParent := b.Get([]byte(req.ParentID))
		if vParent == nil {
			return ErrNotFound
		}
		var parent Inode
		if err := json.Unmarshal(vParent, &parent); err != nil {
			return err
		}

		// 3. Add to Parent
		if parent.Children == nil {
			parent.Children = make(map[string]string)
		}
		if _, exists := parent.Children[req.Name]; exists {
			return ErrExists
		}
		parent.Children[req.Name] = req.TargetID
		parent.Version++

		// 4. Update Target
		target.NLink++
		target.Version++

		// 5. Save
		// Parent doesn't need pagination for Children map yet (Phase 10.1 is ChunkManifest)
		// But target might be large file?
		if err := saveInodeWithPages(tx, &parent); err != nil {
			return err
		}
		return saveInodeWithPages(tx, &target)
	})
}

func (fsm *MetadataFSM) applySetAttr(data []byte) interface{} {
	var req SetAttrRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))
		v := b.Get([]byte(req.InodeID))
		if v == nil {
			return ErrNotFound
		}
		var inode Inode
		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}

		if req.Mode != nil {
			inode.Mode = *req.Mode
		}
		if req.UID != nil {
			inode.UID = *req.UID
		}
		if req.GID != nil {
			inode.GID = *req.GID
		}
		if req.Size != nil {
			inode.Size = *req.Size
		}
		if req.MTime != nil {
			inode.MTime = *req.MTime
		}

		inode.CTime = time.Now().UnixNano()
		inode.Version++

		return saveInodeWithPages(tx, &inode)
	})
}

func (fsm *MetadataFSM) applyRename(data []byte) interface{} {
	var req RenameRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("inodes"))

		// 1. Load Old Parent
		vOld := b.Get([]byte(req.OldParentID))
		if vOld == nil {
			return ErrNotFound
		}
		var oldParent Inode
		if err := json.Unmarshal(vOld, &oldParent); err != nil {
			return err
		}

		// 2. Identify Child
		childID, ok := oldParent.Children[req.OldName]
		if !ok {
			return ErrNotFound
		}

		// 3. Load New Parent
		var newParent Inode
		if req.NewParentID == req.OldParentID {
			newParent = oldParent
		} else {
			vNew := b.Get([]byte(req.NewParentID))
			if vNew == nil {
				return ErrNotFound
			}
			if err := json.Unmarshal(vNew, &newParent); err != nil {
				return err
			}
		}

		// 4. Handle Overwrite
		if targetID, exists := newParent.Children[req.NewName]; exists {
			vTarget := b.Get([]byte(targetID))
			if vTarget != nil {
				var target Inode
				if err := json.Unmarshal(vTarget, &target); err == nil {
					if target.Type == DirType && len(target.Children) > 0 {
						return fmt.Errorf("cannot overwrite non-empty directory")
					}
					// Decrement nlink of overwritten entry
					if target.NLink > 0 {
						target.NLink--
					}
					if target.NLink == 0 {
						b.Delete([]byte(target.ID))
						enqueueGC(tx, &target)
					} else {
						if err := saveInodeWithPages(tx, &target); err != nil {
							return err
						}
					}
				}
			}
		}

		// 5. Update
		delete(oldParent.Children, req.OldName)
		oldParent.Version++

		if newParent.Children == nil {
			newParent.Children = make(map[string]string)
		}
		newParent.Children[req.NewName] = childID
		newParent.Version++

		// 5. Update Child Metadata
		vChild := b.Get([]byte(childID))
		if vChild != nil {
			var child Inode
			if err := json.Unmarshal(vChild, &child); err == nil {
				child.ParentID = req.NewParentID
				child.Version++
				if err := saveInodeWithPages(tx, &child); err != nil {
					return err
				}
			}
		}

		// 6. Save
		if err := saveInodeWithPages(tx, &oldParent); err != nil {
			return err
		}

		if req.NewParentID != req.OldParentID {
			if err := saveInodeWithPages(tx, &newParent); err != nil {
				return err
			}
		}

		return nil
	})
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

		return saveInodeWithPages(tx, &inode)
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

	return fsm.db.Update(func(tx *bolt.Tx) error {
		ib := tx.Bucket([]byte("inodes"))

		// 1. Load Parent
		vParent := ib.Get([]byte(update.ParentID))
		if vParent == nil {
			return ErrNotFound
		}
		var parent Inode
		if err := json.Unmarshal(vParent, &parent); err != nil {
			return err
		}

		// 2. Identify Child
		childID, ok := parent.Children[update.Name]
		if !ok {
			return ErrNotFound
		}

		// 3. Load Child
		vChild := ib.Get([]byte(childID))
		if vChild == nil {
			return ErrNotFound
		}
		var child Inode
		if err := json.Unmarshal(vChild, &child); err != nil {
			return err
		}

		// 4. POSIX Checks
		if child.Type == DirType && len(child.Children) > 0 {
			return fmt.Errorf("directory not empty")
		}

		// 5. Remove from Parent
		delete(parent.Children, update.Name)
		parent.Version++
		if err := saveInodeWithPages(tx, &parent); err != nil {
			return err
		}

		// 6. Update Child
		if child.NLink > 0 {
			child.NLink--
		}
		child.Version++

		if child.NLink == 0 {
			// Delete Inode
			ib.Delete([]byte(child.ID))
			// Cleanup chunks (Garbage Collection)
			enqueueGC(tx, &child)
		} else {
			if err := saveInodeWithPages(tx, &child); err != nil {
				return err
			}
		}

		return nil
	})
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

		// Load manifest to find chunk
		if err := loadInodeWithPages(tx, &inode); err != nil {
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
			return saveInodeWithPages(tx, &inode)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) applyGCRemove(data []byte) interface{} {
	chunkID := string(data)
	return fsm.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("garbage_collection"))
		return b.Delete([]byte(chunkID))
	})
}

func (fsm *MetadataFSM) Snapshot() (raft.FSMSnapshot, error) {
	if fsm.OnSnapshot != nil {
		fsm.OnSnapshot()
	}
	return &MetadataSnapshot{db: fsm.db}, nil
}

func (fsm *MetadataFSM) ValidateNode(address string) error {
	return fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				// Address in FSM is full URL (e.g. http://1.2.3.4:8080)
				// Target might be host:port or URL.
				if strings.Contains(n.Address, address) {
					return nil
				}
			}
		}
		return fmt.Errorf("node address %s not found in registry", address)
	})
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

func generateID32() uint32 {
	b := make([]byte, 4)
	rand.Read(b)
	return binary.BigEndian.Uint32(b)
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

const ChunkPageSize = 1000

func saveInodeWithPages(tx *bolt.Tx, inode *Inode) error {
	// If manifest is large, split it
	if len(inode.ChunkManifest) > ChunkPageSize {
		var pageIDs []string
		for i := 0; i < len(inode.ChunkManifest); i += ChunkPageSize {
			end := i + ChunkPageSize
			if end > len(inode.ChunkManifest) {
				end = len(inode.ChunkManifest)
			}
			page := ChunkPage{
				ID:     fmt.Sprintf("%s-page-%d", inode.ID, len(pageIDs)),
				Chunks: inode.ChunkManifest[i:end],
			}
			pageIDs = append(pageIDs, page.ID)

			b := tx.Bucket([]byte("chunk_pages"))
			encoded, err := json.Marshal(page)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(page.ID), encoded); err != nil {
				return err
			}
		}
		inode.ChunkPages = pageIDs
		inode.ChunkManifest = nil
	} else if len(inode.ChunkPages) > 0 && len(inode.ChunkManifest) <= ChunkPageSize && inode.ChunkManifest != nil {
		// Was large, now small. Cleanup old pages.
		pb := tx.Bucket([]byte("chunk_pages"))
		for _, pid := range inode.ChunkPages {
			pb.Delete([]byte(pid))
		}
		inode.ChunkPages = nil
	}

	b := tx.Bucket([]byte("inodes"))
	encoded, err := json.Marshal(inode)
	if err != nil {
		return err
	}
	return b.Put([]byte(inode.ID), encoded)
}

func loadInodeWithPages(tx *bolt.Tx, inode *Inode) error {
	if len(inode.ChunkPages) > 0 && len(inode.ChunkManifest) == 0 {
		pb := tx.Bucket([]byte("chunk_pages"))
		for _, pid := range inode.ChunkPages {
			v := pb.Get([]byte(pid))
			if v != nil {
				var page ChunkPage
				if err := json.Unmarshal(v, &page); err == nil {
					inode.ChunkManifest = append(inode.ChunkManifest, page.Chunks...)
				}
			}
		}
	}
	return nil
}

func enqueueGC(tx *bolt.Tx, inode *Inode) error {
	// Ensure we have the manifest loaded
	if err := loadInodeWithPages(tx, inode); err != nil {
		return err
	}
	
	// Delete pages if they exist
	if len(inode.ChunkPages) > 0 {
		pb := tx.Bucket([]byte("chunk_pages"))
		for _, pid := range inode.ChunkPages {
			pb.Delete([]byte(pid))
		}
	}

	b := tx.Bucket([]byte("garbage_collection"))
	for _, chunk := range inode.ChunkManifest {
		nodesJSON, _ := json.Marshal(chunk.Nodes)
		if err := b.Put([]byte(chunk.ID), nodesJSON); err != nil {
			return err
		}
	}
	return nil
}