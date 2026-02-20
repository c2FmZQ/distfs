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
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/storage"
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrExists   = errors.New("already exists")
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("version conflict")
)

// MetadataFSM implements the Raft Finite State Machine for the metadata layer.
// It manages the Inode table, User registry, and other cluster state using BoltDB.
type MetadataFSM struct {
	db         *bolt.DB
	path       string
	OnSnapshot func()

	st      *storage.Storage
	trusted map[string]bool // PubKey(bytes) -> true
	mu      sync.RWMutex

	metrics *MetricsCollector
}

// NewMetadataFSM creates a new FSM backed by a BoltDB file at the given path.
func NewMetadataFSM(path string, st *storage.Storage) (*MetadataFSM, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		buckets := []string{"inodes", "nodes", "users", "groups", "uids", "gids", "garbage_collection", "chunk_pages", "system", "keysync", "admins", "metrics", "user_memberships", "owner_groups"}
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

	fsm := &MetadataFSM{
		db:      db,
		path:    path,
		st:      st,
		trusted: make(map[string]bool),
		metrics: NewMetricsCollector(),
	}
	fsm.loadTrustState()
	return fsm, nil
}

// Close closes the underlying BoltDB.
func (fsm *MetadataFSM) Close() error {
	if fsm.db != nil {
		return fsm.db.Close()
	}
	return nil
}

type TrustData struct {
	Keys []string `json:"keys"` // Hex encoded pub keys
}

func (fsm *MetadataFSM) loadTrustState() {
	if fsm.st == nil {
		return
	}
	var td TrustData
	if err := fsm.st.ReadDataFile("trust.bin", &td); err == nil {
		fsm.mu.Lock()
		for _, k := range td.Keys {
			fsm.trusted[k] = true
		}
		fsm.mu.Unlock()
	}
}

func (fsm *MetadataFSM) saveTrustState() {
	if fsm.st == nil {
		return
	}
	fsm.mu.RLock()
	var keys []string
	for k := range fsm.trusted {
		keys = append(keys, k)
	}
	fsm.mu.RUnlock()

	td := TrustData{Keys: keys}
	fsm.st.SaveDataFile("trust.bin", td)
}

func (fsm *MetadataFSM) IsInitialized() bool {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return len(fsm.trusted) > 0
}

func (fsm *MetadataFSM) IsTrusted(pubKey []byte) bool {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.trusted[string(pubKey)]
}

func (fsm *MetadataFSM) GetNode(id string) (*Node, error) {
	var node Node
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &node)
	})
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func (fsm *MetadataFSM) GetNodeByRaftAddress(raftAddr string) (*Node, error) {
	var node Node
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				if n.RaftAddress == raftAddr {
					node = n
					return nil
				}
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// CommandType identifies the type of operation in the Raft log.
type CommandType uint8

const (
	CmdCreateInode     CommandType = 1
	CmdUpdateInode     CommandType = 2
	CmdDeleteInode     CommandType = 3
	CmdRegisterNode    CommandType = 4
	CmdCreateUser      CommandType = 6
	CmdCreateGroup     CommandType = 7
	CmdUpdateGroup     CommandType = 8
	CmdAddChild        CommandType = 9
	CmdAddChunkReplica CommandType = 11
	CmdSetAttr         CommandType = 13
	CmdGCRemove        CommandType = 15
	CmdInitSecret      CommandType = 16
	CmdSetUserQuota    CommandType = 17
	CmdRotateKey       CommandType = 18
	CmdInitWorld       CommandType = 19
	CmdStoreKeySync    CommandType = 20
	CmdBatch           CommandType = 21
	CmdAcquireLeases   CommandType = 22
	CmdReleaseLeases   CommandType = 23
	CmdPromoteAdmin    CommandType = 24
	CmdAdminChown      CommandType = 25
	CmdAdminChmod      CommandType = 26
	CmdStoreMetrics    CommandType = 27
	CmdSetGroupQuota   CommandType = 28
)

// LogCommand is the structure stored in the Raft log.
type LogCommand struct {
	Type CommandType `json:"type"`
	Data []byte      `json:"data"`
}

func (c LogCommand) Marshal() []byte {
	b, _ := json.Marshal(c)
	return b
}

type LeaseRequest struct {
	InodeIDs []string       `json:"inode_ids"`
	OwnerID  string         `json:"owner_id"` // Session ID
	UserID   string         `json:"user_id"`  // Actual User ID for placeholders
	Lockbox  crypto.Lockbox `json:"lockbox,omitempty"`
	Duration int64          `json:"duration"` // Nanoseconds
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
	GroupID *string `json:"group_id,omitempty"`
	Size    *uint64 `json:"size,omitempty"`
	MTime   *int64  `json:"mtime,omitempty"`
}

type LinkRequest struct {
	ParentID string `json:"parent_id"`
	Name     string `json:"name"`
	TargetID string `json:"target_id"`
}

type SetUserQuotaRequest struct {
	UserID    string `json:"user_id"`
	MaxBytes  *int64 `json:"max_bytes,omitempty"`
	MaxInodes *int64 `json:"max_inodes,omitempty"`
}

type SetGroupQuotaRequest struct {
	GroupID   string `json:"group_id"`
	MaxBytes  *int64 `json:"max_bytes,omitempty"`
	MaxInodes *int64 `json:"max_inodes,omitempty"`
}

type ClusterKey struct {
	ID        string `json:"id"`
	EncKey    []byte `json:"enc_key"` // Public
	DecKey    []byte `json:"dec_key"` // Private
	CreatedAt int64  `json:"created_at"`
}

// Apply applies a Raft log entry to the FSM.
func (fsm *MetadataFSM) Apply(l *raft.Log) interface{} {
	var cmd LogCommand
	if err := json.Unmarshal(l.Data, &cmd); err != nil {
		return err
	}

	if cmd.Type == CmdBatch {
		return fsm.applyBatch(cmd.Data)
	}

	var result interface{}
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		res := fsm.executeCommand(tx, cmd.Type, cmd.Data, 0)
		if err, ok := res.(error); ok {
			return err
		}
		result = res
		return nil
	})
	if err != nil {
		return err
	}
	return result
}

func (fsm *MetadataFSM) applyBatch(data []byte) interface{} {
	var cmds []LogCommand
	if err := json.Unmarshal(data, &cmds); err != nil {
		return []interface{}{err}
	}

	var results []interface{}
	// We use a single transaction for performance.
	_ = fsm.db.Update(func(tx *bolt.Tx) error {
		results = fsm.executeBatchCommands(tx, cmds, 0)
		return nil
	})
	return results
}

func (fsm *MetadataFSM) executeBatchCommands(tx *bolt.Tx, cmds []LogCommand, depth int) []interface{} {
	if depth > 4 {
		return []interface{}{fmt.Errorf("batch recursion depth exceeded")}
	}
	results := make([]interface{}, len(cmds))
	for i, cmd := range cmds {
		res := fsm.executeCommand(tx, cmd.Type, cmd.Data, depth)
		results[i] = res
	}
	return results
}

func (fsm *MetadataFSM) applyBatchTx(tx *bolt.Tx, data []byte, depth int) []interface{} {
	var cmds []LogCommand
	if err := json.Unmarshal(data, &cmds); err != nil {
		return []interface{}{err}
	}
	return fsm.executeBatchCommands(tx, cmds, depth)
}

func (fsm *MetadataFSM) executeCommand(tx *bolt.Tx, cmdType CommandType, data []byte, depth int) interface{} {
	start := time.Now()
	defer func() {
		fsm.metrics.RecordOp(cmdType, time.Since(start))
	}()

	switch cmdType {
	case CmdCreateInode:
		return fsm.executeCreateInode(tx, data)
	case CmdUpdateInode:
		return fsm.executeUpdateInode(tx, data)
	case CmdDeleteInode:
		return fsm.executeDeleteInode(tx, data)
	case CmdRegisterNode:
		return fsm.executeRegisterNode(tx, data)
	case CmdCreateUser:
		return fsm.executeCreateUser(tx, data)
	case CmdCreateGroup:
		return fsm.executeCreateGroup(tx, data)
	case CmdUpdateGroup:
		return fsm.executeUpdateGroup(tx, data)
	case CmdAddChild:
		return fsm.executeAddChild(tx, data)
	case CmdAddChunkReplica:
		return fsm.executeAddChunkReplica(tx, data)
	case CmdSetAttr:
		return fsm.executeSetAttr(tx, data)
	case CmdGCRemove:
		return fsm.executeGCRemove(tx, data)
	case CmdInitSecret:
		return fsm.executeInitSecret(tx, data)
	case CmdSetUserQuota:
		return fsm.executeSetUserQuota(tx, data)
	case CmdRotateKey:
		return fsm.executeRotateKey(tx, data)
	case CmdInitWorld:
		return fsm.executeInitWorld(tx, data)
	case CmdStoreKeySync:
		return fsm.executeStoreKeySync(tx, data)
	case CmdAcquireLeases:
		return fsm.executeAcquireLeases(tx, data)
	case CmdReleaseLeases:
		return fsm.executeReleaseLeases(tx, data)
	case CmdPromoteAdmin:
		return fsm.executePromoteAdmin(tx, data)
	case CmdAdminChown:
		return fsm.executeAdminChown(tx, data)
	case CmdAdminChmod:
		return fsm.executeAdminChmod(tx, data)
	case CmdStoreMetrics:
		return fsm.executeStoreMetrics(tx, data)
	case CmdSetGroupQuota:
		return fsm.executeSetGroupQuota(tx, data)
	case CmdBatch:
		return fsm.applyBatchTx(tx, data, depth+1)
	}
	return fmt.Errorf("unknown command")
}

func (fsm *MetadataFSM) executeCreateInode(tx *bolt.Tx, data []byte) interface{} {
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
	inode.Mode = SanitizeMode(inode.Mode, inode.Type)

	b := tx.Bucket([]byte("inodes"))
	if b.Get([]byte(inode.ID)) != nil {
		return ErrExists
	}

	if inode.OwnerID != "" {
		if err := checkQuota(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}

	inode.Version = 1
	if err := saveInodeWithPages(tx, &inode); err != nil {
		return err
	}
	if inode.OwnerID != "" {
		if err := updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}
	return &inode
}

func (fsm *MetadataFSM) executeUpdateInode(tx *bolt.Tx, data []byte) interface{} {
	var inode Inode
	if err := json.Unmarshal(data, &inode); err != nil {
		return err
	}

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

	ownerChanged := inode.OwnerID != existing.OwnerID
	groupChanged := inode.GroupID != existing.GroupID

	if ownerChanged || groupChanged {
		// 1. Decrement old owner/group FIRST
		if err := updateUsage(tx, existing.OwnerID, existing.GroupID, -1, -int64(existing.Size)); err != nil {
			return err
		}
		// 2. Check Quota for new owner/group
		if err := checkQuota(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
		// 3. Increment new owner/group
		if err := updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}

	oldPages := existing.ChunkPages
	diffBytes := int64(inode.Size) - int64(existing.Size)

	if !(ownerChanged || groupChanged) && diffBytes > 0 {
		if err := checkQuota(tx, inode.OwnerID, inode.GroupID, 0, diffBytes); err != nil {
			return err
		}
	}

	inode.Version++
	inode.Mode = SanitizeMode(inode.Mode, inode.Type)
	if err := saveInodeWithPages(tx, &inode); err != nil {
		return err
	}

	if !(ownerChanged || groupChanged) && diffBytes != 0 {
		if err := updateUsage(tx, inode.OwnerID, inode.GroupID, 0, diffBytes); err != nil {
			return err
		}
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
	return &inode
}

func (fsm *MetadataFSM) executeDeleteInode(tx *bolt.Tx, data []byte) interface{} {
	id := string(data)
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
			if inode.OwnerID != "" {
				if err := updateUsage(tx, inode.OwnerID, inode.GroupID, -1, -int64(inode.Size)); err != nil {
					return err
				}
			}
			enqueueGC(tx, &inode)
		}
	}
	return b.Delete([]byte(id))
}

func (fsm *MetadataFSM) executeRegisterNode(tx *bolt.Tx, data []byte) interface{} {
	var node Node
	if err := json.Unmarshal(data, &node); err != nil {
		return err
	}

	fsm.mu.Lock()
	if len(node.PublicKey) > 0 {
		fsm.trusted[string(node.PublicKey)] = true
	}
	if len(node.SignKey) > 0 {
		fsm.trusted[string(node.SignKey)] = true
	}
	fsm.mu.Unlock()

	if len(node.PublicKey) > 0 || len(node.SignKey) > 0 {
		fsm.saveTrustState()
	}

	b := tx.Bucket([]byte("nodes"))
	encoded, err := json.Marshal(node)
	if err != nil {
		return err
	}
	return b.Put([]byte(node.ID), encoded)
}

func (fsm *MetadataFSM) executeCreateUser(tx *bolt.Tx, data []byte) interface{} {
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return err
	}

	ub := tx.Bucket([]byte("users"))
	idx := tx.Bucket([]byte("uids"))
	ab := tx.Bucket([]byte("admins"))

	if ub.Get([]byte(user.ID)) != nil {
		return ErrExists
	}

	// Bootstrap: First user is admin
	isFirst := false
	if stats := ub.Stats(); stats.KeyN == 0 {
		isFirst = true
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
	if err := idx.Put(uint32ToBytes(user.UID), []byte(user.ID)); err != nil {
		return err
	}

	if isFirst {
		if err := ab.Put([]byte(user.ID), []byte("true")); err != nil {
			return err
		}
	}

	return &user
}

func (fsm *MetadataFSM) executePromoteAdmin(tx *bolt.Tx, data []byte) interface{} {
	userID := string(data)
	ub := tx.Bucket([]byte("users"))
	if ub.Get([]byte(userID)) == nil {
		return ErrNotFound
	}
	ab := tx.Bucket([]byte("admins"))
	return ab.Put([]byte(userID), []byte("true"))
}

func (fsm *MetadataFSM) IsAdmin(userID string) bool {
	isAdmin := false
	_ = fsm.db.View(func(tx *bolt.Tx) error {
		ab := tx.Bucket([]byte("admins"))
		if ab.Get([]byte(userID)) != nil {
			isAdmin = true
		}
		return nil
	})
	return isAdmin
}

func (fsm *MetadataFSM) executeCreateGroup(tx *bolt.Tx, data []byte) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		log.Printf("FSM: executeCreateGroup unmarshal failed: %v", err)
		return err
	}

	gb := tx.Bucket([]byte("groups"))
	idx := tx.Bucket([]byte("gids"))

	if gb.Get([]byte(group.ID)) != nil {
		return ErrExists
	}

	// Ensure GID is unique
	if existing := idx.Get(uint32ToBytes(group.GID)); existing != nil {
		return fmt.Errorf("GID %d already assigned to %s", group.GID, string(existing))
	}

	group.Version = 1
	encoded, err := json.Marshal(group)
	if err != nil {
		return err
	}

	if err := gb.Put([]byte(group.ID), encoded); err != nil {
		return err
	}
	if err := idx.Put(uint32ToBytes(group.GID), []byte(group.ID)); err != nil {
		return err
	}

	if err := fsm.updateGroupIndices(tx, &group, nil); err != nil {
		return err
	}

	return &group
}

func (fsm *MetadataFSM) executeUpdateGroup(tx *bolt.Tx, data []byte) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return err
	}
	b := tx.Bucket([]byte("groups"))
	v := b.Get([]byte(group.ID))
	if v == nil {
		return ErrNotFound
	}

	var existing Group
	if err := json.Unmarshal(v, &existing); err != nil {
		return err
	}

	if group.Version != existing.Version {
		return ErrConflict
	}

	group.Version++
	encoded, err := json.Marshal(group)
	if err != nil {
		return err
	}
	if err := b.Put([]byte(group.ID), encoded); err != nil {
		return err
	}

	if err := fsm.updateGroupIndices(tx, &group, &existing); err != nil {
		return err
	}

	return &group
}

func (fsm *MetadataFSM) updateGroupIndices(tx *bolt.Tx, group *Group, existing *Group) error {
	mb := tx.Bucket([]byte("user_memberships"))
	ob := tx.Bucket([]byte("owner_groups"))

	// 1. Membership Updates
	if existing == nil {
		// New group: Add all members
		for uid := range group.Members {
			sub, err := mb.CreateBucketIfNotExists([]byte(uid))
			if err != nil {
				return err
			}
			sub.Put([]byte(group.ID), []byte("1"))
		}
	} else {
		// Existing group: Delta update
		// 1a. Remove users who left
		for uid := range existing.Members {
			if !group.Members[uid] {
				sub := mb.Bucket([]byte(uid))
				if sub != nil {
					sub.Delete([]byte(existing.ID))
				}
			}
		}
		// 1b. Add users who joined
		for uid := range group.Members {
			if !existing.Members[uid] {
				sub, err := mb.CreateBucketIfNotExists([]byte(uid))
				if err != nil {
					return err
				}
				sub.Put([]byte(group.ID), []byte("1"))
			}
		}
	}

	// 2. Ownership Updates
	if (existing == nil && group.OwnerID != "") || (existing != nil && existing.OwnerID != group.OwnerID) {
		// Owner changed or new group
		if existing != nil {
			sub := ob.Bucket([]byte(existing.OwnerID))
			if sub != nil {
				sub.Delete([]byte(existing.ID))
			}
		}
		sub, err := ob.CreateBucketIfNotExists([]byte(group.OwnerID))
		if err != nil {
			return err
		}
		sub.Put([]byte(group.ID), []byte("1"))
	}

	return nil
}

func (fsm *MetadataFSM) executeSetAttr(tx *bolt.Tx, data []byte) interface{} {
	var req SetAttrRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("inodes"))
	v := b.Get([]byte(req.InodeID))
	if v == nil {
		return ErrNotFound
	}
	var inode Inode
	if err := json.Unmarshal(v, &inode); err != nil {
		return err
	}

	if err := loadInodeWithPages(tx, &inode); err != nil {
		return err
	}

	if req.Mode != nil {
		inode.Mode = SanitizeMode(*req.Mode, inode.Type)
	}
	if req.UID != nil {
		inode.UID = *req.UID
	}
	if req.GID != nil {
		inode.GID = *req.GID
	}
	if req.GroupID != nil && *req.GroupID != inode.GroupID {
		newGroupID := *req.GroupID
		// 1. Decrement old group/owner FIRST
		if err := updateUsage(tx, inode.OwnerID, inode.GroupID, -1, -int64(inode.Size)); err != nil {
			return err
		}
		// 2. Check Quota for new group
		if err := checkQuota(tx, inode.OwnerID, newGroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
		// Update GroupID
		inode.GroupID = newGroupID
		// 3. Increment new group/owner
		if err := updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}
	if req.MTime != nil {
		inode.MTime = *req.MTime
	}

	inode.Version++
	inode.CTime = time.Now().UnixNano()
	return saveInodeWithPages(tx, &inode)
}

func (fsm *MetadataFSM) executeAddChild(tx *bolt.Tx, data []byte) interface{} {
	var update ChildUpdate
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}

	var inode Inode
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

	// Update Child Links
	vChild := b.Get([]byte(update.ChildID))
	if vChild != nil {
		var child Inode
		if err := json.Unmarshal(vChild, &child); err == nil {
			if child.Links == nil {
				child.Links = make(map[string]bool)
			}
			child.Links[update.ParentID+":"+update.Name] = true
			child.Version++
			if err := saveInodeWithPages(tx, &child); err != nil {
				return err
			}
		}
	}

	if err := saveInodeWithPages(tx, &inode); err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) executeAddChunkReplica(tx *bolt.Tx, data []byte) interface{} {
	var req AddReplicaRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	var inode Inode
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
		if err := saveInodeWithPages(tx, &inode); err != nil {
			return err
		}
	}
	return &inode
}

func (fsm *MetadataFSM) executeGCRemove(tx *bolt.Tx, data []byte) interface{} {
	chunkID := string(data)
	b := tx.Bucket([]byte("garbage_collection"))
	return b.Delete([]byte(chunkID))
}

func (fsm *MetadataFSM) executeInitSecret(tx *bolt.Tx, data []byte) interface{} {
	b := tx.Bucket([]byte("system"))
	if b.Get([]byte("cluster_secret")) != nil {
		return ErrExists
	}
	return b.Put([]byte("cluster_secret"), data)
}

func (fsm *MetadataFSM) GetClusterSecret() ([]byte, error) {
	var secret []byte
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("system"))
		v := b.Get([]byte("cluster_secret"))
		if v == nil {
			return ErrNotFound
		}
		secret = make([]byte, len(v))
		copy(secret, v)
		return nil
	})
	return secret, err
}

// Snapshot returns a snapshot of the current state.
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

// Restore restores the FSM from a snapshot.
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

	// Rebuild the in-memory trust cache and persist it to trust.bin after restoring from snapshot.
	fsm.reopen()
	fsm.rebuildTrustCache()
	return nil
}

func (fsm *MetadataFSM) reopen() error {
	db, err := bolt.Open(fsm.path, 0600, nil)
	if err != nil {
		return err
	}
	fsm.db = db
	return nil
}

func (fsm *MetadataFSM) rebuildTrustCache() {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fsm.trusted = make(map[string]bool)

	fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				fsm.trusted[string(n.PublicKey)] = true
			}
		}
		return nil
	})

	// We should also persist it to trust.bin to match
	keys := make([]string, 0, len(fsm.trusted))
	for k := range fsm.trusted {
		keys = append(keys, k)
	}
	if fsm.st != nil {
		fsm.st.SaveDataFile("trust.bin", TrustData{Keys: keys})
	}
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

// ChunkPageSize is the maximum number of chunks stored in a single inode before pagination occurs.
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

func updateUsage(tx *bolt.Tx, userID, groupID string, deltaInodes int64, deltaBytes int64) error {
	remainingInodes := deltaInodes
	remainingBytes := deltaBytes

	if groupID != "" {
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(groupID))
		if v != nil {
			var group Group
			if err := json.Unmarshal(v, &group); err != nil {
				return fmt.Errorf("unmarshal group usage %s: %w", groupID, err)
			}
			group.Usage.InodeCount += deltaInodes
			group.Usage.TotalBytes += deltaBytes

			// Determine if this group is the authoritative budget for these resources
			if group.Quota.MaxInodes > 0 {
				remainingInodes = 0
			}
			if group.Quota.MaxBytes > 0 {
				remainingBytes = 0
			}

			encoded, err := json.Marshal(group)
			if err != nil {
				return fmt.Errorf("marshal group: %w", err)
			}
			if err := b.Put([]byte(groupID), encoded); err != nil {
				return err
			}
		}
	}

	if userID != "" && (remainingInodes != 0 || remainingBytes != 0) {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(userID))
		if v != nil {
			var user User
			if err := json.Unmarshal(v, &user); err != nil {
				return fmt.Errorf("unmarshal user usage %s: %w", userID, err)
			}
			user.Usage.InodeCount += remainingInodes
			user.Usage.TotalBytes += remainingBytes
			encoded, err := json.Marshal(user)
			if err != nil {
				return fmt.Errorf("marshal user: %w", err)
			}
			if err := b.Put([]byte(userID), encoded); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkQuota(tx *bolt.Tx, userID, groupID string, deltaInodes int64, deltaBytes int64) error {
	if deltaInodes <= 0 && deltaBytes <= 0 {
		return nil
	}

	remainingInodes := deltaInodes
	remainingBytes := deltaBytes

	if groupID != "" {
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(groupID))
		if v != nil {
			var group Group
			if err := json.Unmarshal(v, &group); err == nil {
				// Enforce group limits if they are set (non-zero)
				if group.Quota.MaxInodes > 0 {
					if deltaInodes > 0 && group.Usage.InodeCount+deltaInodes > group.Quota.MaxInodes {
						return fmt.Errorf("group inode quota exceeded")
					}
					remainingInodes = 0 // Group quota is authoritative for this resource
				}
				if group.Quota.MaxBytes > 0 {
					if deltaBytes > 0 && group.Usage.TotalBytes+deltaBytes > group.Quota.MaxBytes {
						return fmt.Errorf("group storage quota exceeded")
					}
					remainingBytes = 0 // Group quota is authoritative for this resource
				}
			}
		}
	}

	// Fallback to user quota for any remaining resources not covered by group limits
	if userID != "" && (remainingInodes > 0 || remainingBytes > 0) {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(userID))
		if v == nil {
			return nil
		}
		var user User
		if err := json.Unmarshal(v, &user); err != nil {
			return err
		}
		if remainingInodes > 0 && user.Quota.MaxInodes > 0 {
			if user.Usage.InodeCount+remainingInodes > user.Quota.MaxInodes {
				return fmt.Errorf("user inode quota exceeded")
			}
		}
		if remainingBytes > 0 && user.Quota.MaxBytes > 0 {
			if user.Usage.TotalBytes+remainingBytes > user.Quota.MaxBytes {
				return fmt.Errorf("user storage quota exceeded")
			}
		}
	}
	return nil
}

func (fsm *MetadataFSM) executeSetUserQuota(tx *bolt.Tx, data []byte) interface{} {
	var req SetUserQuotaRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("users"))
	v := b.Get([]byte(req.UserID))
	if v == nil {
		return ErrNotFound
	}
	var user User
	if err := json.Unmarshal(v, &user); err != nil {
		return err
	}

	if req.MaxBytes != nil {
		user.Quota.MaxBytes = *req.MaxBytes
	}
	if req.MaxInodes != nil {
		user.Quota.MaxInodes = *req.MaxInodes
	}

	encoded, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return b.Put([]byte(req.UserID), encoded)
}

func (fsm *MetadataFSM) executeSetGroupQuota(tx *bolt.Tx, data []byte) interface{} {
	var req SetGroupQuotaRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("groups"))
	v := b.Get([]byte(req.GroupID))
	if v == nil {
		return ErrNotFound
	}
	var group Group
	if err := json.Unmarshal(v, &group); err != nil {
		return err
	}

	if req.MaxBytes != nil {
		group.Quota.MaxBytes = *req.MaxBytes
	}
	if req.MaxInodes != nil {
		group.Quota.MaxInodes = *req.MaxInodes
	}

	encoded, err := json.Marshal(group)
	if err != nil {
		return err
	}
	return b.Put([]byte(req.GroupID), encoded)
}

func (fsm *MetadataFSM) executeRotateKey(tx *bolt.Tx, data []byte) interface{} {
	var key ClusterKey
	if err := json.Unmarshal(data, &key); err != nil {
		return err
	}

	b := tx.Bucket([]byte("system"))

	encoded, err := json.Marshal(key)
	if err != nil {
		return err
	}
	if err := b.Put([]byte("epoch_key_"+key.ID), encoded); err != nil {
		return err
	}

	if err := b.Put([]byte("active_epoch_key"), []byte(key.ID)); err != nil {
		return err
	}

	// Prune
	var keys []ClusterKey
	c := b.Cursor()
	prefix := []byte("epoch_key_")
	for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
		var kStruct ClusterKey
		if err := json.Unmarshal(v, &kStruct); err == nil {
			keys = append(keys, kStruct)
		}
	}

	if len(keys) > 3 {
		oldestIdx := -1
		var oldestTime int64 = 1<<63 - 1
		for i, k := range keys {
			if k.CreatedAt < oldestTime {
				oldestTime = k.CreatedAt
				oldestIdx = i
			}
		}
		if oldestIdx != -1 {
			b.Delete([]byte("epoch_key_" + keys[oldestIdx].ID))
		}
	}

	return nil
}
func (fsm *MetadataFSM) GetActiveKey() (*ClusterKey, error) {
	var key ClusterKey
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("system"))
		id := b.Get([]byte("active_epoch_key"))
		if id == nil {
			return ErrNotFound
		}
		v := b.Get([]byte("epoch_key_" + string(id)))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &key)
	})
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (fsm *MetadataFSM) executeInitWorld(tx *bolt.Tx, data []byte) interface{} {
	var world WorldIdentity
	if err := json.Unmarshal(data, &world); err != nil {
		return err
	}
	b := tx.Bucket([]byte("system"))
	if b.Get([]byte("world_identity")) != nil {
		return ErrExists
	}
	encoded, _ := json.Marshal(world)
	return b.Put([]byte("world_identity"), encoded)
}
func (fsm *MetadataFSM) GetWorldIdentity() (*WorldIdentity, error) {
	var world WorldIdentity
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("system"))
		v := b.Get([]byte("world_identity"))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &world)
	})
	if err != nil {
		return nil, err
	}
	return &world, nil
}

func (fsm *MetadataFSM) IsUserInGroup(userID, groupID string) (bool, error) {
	log.Printf("FSM: IsUserInGroup checking groupID=%s for userID=%s", groupID, userID)
	var group Group
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(groupID))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &group)
	})
	if err != nil {
		return false, err
	}
	return group.Members[userID] || group.OwnerID == userID, nil
}

func (fsm *MetadataFSM) GetGroup(id string) (*Group, error) {
	var group Group
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &group)
	})
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func (fsm *MetadataFSM) executeStoreKeySync(tx *bolt.Tx, data []byte) interface{} {
	var req KeySyncRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("keysync"))
	encoded, err := json.Marshal(req.Blob)
	if err != nil {
		return err
	}
	return b.Put([]byte(req.UserID), encoded)
}

// GetKeySyncBlob retrieves the encrypted configuration blob for a user.
func (fsm *MetadataFSM) GetKeySyncBlob(userID string) (*KeySyncBlob, error) {
	var blob KeySyncBlob
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keysync"))
		v := b.Get([]byte(userID))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &blob)
	})
	if err != nil {
		return nil, err
	}
	return &blob, nil
}

func (fsm *MetadataFSM) executeAcquireLeases(tx *bolt.Tx, data []byte) interface{} {
	var req LeaseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("inodes"))
	now := time.Now().UnixNano()
	expiry := now + req.Duration

	// 1. Validation Phase: Check if all are available
	inodes := make([]*Inode, len(req.InodeIDs))
	for i, id := range req.InodeIDs {
		v := b.Get([]byte(id))
		if v == nil {
			continue // Non-existent inodes can be leased for creation
		}
		var inode Inode
		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}
		inodes[i] = &inode

		// Conflict if already owned by someone else AND not expired
		if inode.LeaseOwner != "" && inode.LeaseOwner != req.OwnerID && inode.LeaseExpiry > now {
			return ErrConflict
		}
	}

	// 2. Grant Phase: Apply leases
	for i, id := range req.InodeIDs {
		inode := inodes[i]
		if inode == nil {
			// Create a minimal inode if it doesn't exist.
			inode = &Inode{
				ID:      id,
				OwnerID: req.UserID,
				Lockbox: req.Lockbox,
				Version: 1,
			}
		}
		inode.LeaseOwner = req.OwnerID
		inode.LeaseExpiry = expiry
		if err := saveInodeWithPages(tx, inode); err != nil {
			return err
		}
	}

	return nil
}

func (fsm *MetadataFSM) executeReleaseLeases(tx *bolt.Tx, data []byte) interface{} {
	var req LeaseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("inodes"))
	for _, id := range req.InodeIDs {
		v := b.Get([]byte(id))
		if v == nil {
			continue // Already gone?
		}
		var inode Inode
		if err := json.Unmarshal(v, &inode); err != nil {
			return err
		}

		// Only release if we are the owner
		if inode.LeaseOwner == req.OwnerID {
			inode.LeaseOwner = ""
			inode.LeaseExpiry = 0
			if err := saveInodeWithPages(tx, &inode); err != nil {
				return err
			}
		}
	}

	return nil
}

func (fsm *MetadataFSM) GetNodes() ([]Node, error) {
	var nodes []Node
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				nodes = append(nodes, n)
			}
		}
		return nil
	})
	return nodes, err
}

func (fsm *MetadataFSM) executeAdminChown(tx *bolt.Tx, data []byte) interface{} {
	var req AdminChownRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("inodes"))
	v := b.Get([]byte(req.InodeID))
	if v == nil {
		return ErrNotFound
	}
	var inode Inode
	if err := json.Unmarshal(v, &inode); err != nil {
		return err
	}

	ownerChanged := req.OwnerID != nil && *req.OwnerID != inode.OwnerID
	groupChanged := req.GroupID != nil && *req.GroupID != inode.GroupID

	if ownerChanged || groupChanged {
		newOwnerID := inode.OwnerID
		if req.OwnerID != nil {
			newOwnerID = *req.OwnerID
		}
		newGroupID := inode.GroupID
		if req.GroupID != nil {
			newGroupID = *req.GroupID
		}

		// 1. Decrement old owner/group FIRST to free up quota before checking new.
		if err := updateUsage(tx, inode.OwnerID, inode.GroupID, -1, -int64(inode.Size)); err != nil {
			return err
		}

		// 2. Check Quota for new owner/group
		if err := checkQuota(tx, newOwnerID, newGroupID, 1, int64(inode.Size)); err != nil {
			return err
		}

		// 3. Update Inode
		inode.OwnerID = newOwnerID
		inode.GroupID = newGroupID

		// Update AuthorizedSigners to include new owner
		found := false
		for _, s := range inode.AuthorizedSigners {
			if s == inode.OwnerID {
				found = true
				break
			}
		}
		if !found && inode.OwnerID != "" {
			inode.AuthorizedSigners = append(inode.AuthorizedSigners, inode.OwnerID)
		}

		// 4. Increment new owner/group
		if err := updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}

	if req.UID != nil {
		inode.UID = *req.UID
	}
	if req.GID != nil {
		inode.GID = *req.GID
	}

	inode.CTime = time.Now().UnixNano()
	inode.Version++

	return saveInodeWithPages(tx, &inode)
}

func (fsm *MetadataFSM) executeAdminChmod(tx *bolt.Tx, data []byte) interface{} {
	var req AdminChmodRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket([]byte("inodes"))
	v := b.Get([]byte(req.InodeID))
	if v == nil {
		return ErrNotFound
	}
	var inode Inode
	if err := json.Unmarshal(v, &inode); err != nil {
		return err
	}

	inode.Mode = SanitizeMode(req.Mode, inode.Type)
	inode.CTime = time.Now().UnixNano()
	inode.Version++

	return saveInodeWithPages(tx, &inode)
}

func (fsm *MetadataFSM) executeStoreMetrics(tx *bolt.Tx, data []byte) interface{} {
	var snap MetricSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}

	b := tx.Bucket([]byte("metrics"))
	return b.Put(int64ToBytes(snap.Timestamp), data)
}

func int64ToBytes(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

func (fsm *MetadataFSM) GetLatestMetrics() (*MetricSnapshot, error) {
	var snap MetricSnapshot
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("metrics"))
		c := b.Cursor()
		k, v := c.Last()
		if k == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &snap)
	})
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

func (fsm *MetadataFSM) GetUserGroups(userID string) ([]GroupListEntry, error) {
	var entries []GroupListEntry
	err := fsm.db.View(func(tx *bolt.Tx) error {
		gb := tx.Bucket([]byte("groups"))
		mb := tx.Bucket([]byte("user_memberships"))
		ob := tx.Bucket([]byte("owner_groups"))

		groupsFound := make(map[string]GroupRole)

		// 1. Direct Memberships
		if sub := mb.Bucket([]byte(userID)); sub != nil {
			c := sub.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				groupsFound[string(k)] = RoleMember
			}
		}

		// 2. Direct Ownership
		if sub := ob.Bucket([]byte(userID)); sub != nil {
			c := sub.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				groupsFound[string(k)] = RoleOwner
			}
		}

		// 3. Delegated Management (Manager role)
		// Find all groups the user is a member/owner of, then find groups owned by those groups.
		// Note: we take a snapshot of keys to avoid concurrent map iteration/mutation issues
		var currentGroups []string
		for gid := range groupsFound {
			currentGroups = append(currentGroups, gid)
		}

		for _, gid := range currentGroups {
			if sub := ob.Bucket([]byte(gid)); sub != nil {
				c := sub.Cursor()
				for k, _ := c.First(); k != nil; k, _ = c.Next() {
					targetGID := string(k)
					// Prioritize roles: Owner > Manager > Member
					if existing, ok := groupsFound[targetGID]; !ok || existing == RoleMember {
						groupsFound[targetGID] = RoleManager
					}
				}
			}
		}

		// 4. Resolve metadata
		for gid, role := range groupsFound {
			v := gb.Get([]byte(gid))
			if v == nil {
				continue
			}
			var g Group
			if err := json.Unmarshal(v, &g); err == nil {
				// Optimization: Filter lockbox to only relevant entries
				filteredLockbox := make(crypto.Lockbox)
				if entry, ok := g.Lockbox[userID]; ok {
					filteredLockbox[userID] = entry
				}
				if g.OwnerID != "" && g.OwnerID != userID {
					if entry, ok := g.Lockbox[g.OwnerID]; ok {
						filteredLockbox[g.OwnerID] = entry
					}
				}

				entries = append(entries, GroupListEntry{
					ID:            g.ID,
					OwnerID:       g.OwnerID,
					EncryptedName: g.EncryptedName,
					Role:          role,
					EncKey:        g.EncKey,
					Lockbox:       filteredLockbox,
					Usage:         g.Usage,
					Quota:         g.Quota,
				})
			}
		}
		return nil
	})
	return entries, err
}
