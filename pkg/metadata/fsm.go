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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrExists        = errors.New("already exists")
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("version conflict")
	ErrStopIteration = errors.New("iteration stopped")
	ErrAtomicRollback = errors.New("atomic transaction failure")
)

// MetadataFSM implements the Raft Finite State Machine for the metadata layer.
// It manages the Inode table, User registry, and other cluster state using BoltDB.
type MetadataFSM struct {
	db         *bolt.DB
	path       string
	OnSnapshot func() error

	clusterSecret []byte
	keyRing       *crypto.KeyRing
	trusted       map[string]bool // PubKey(bytes) -> true
	mu            sync.RWMutex

	metrics *MetricsCollector
}

// NewMetadataFSM creates a new FSM backed by a BoltDB file at the given path.
func NewMetadataFSM(path string, clusterSecret []byte) (*MetadataFSM, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		buckets := []string{"inodes", "nodes", "users", "groups", "uids", "gids", "garbage_collection", "chunk_pages", "system", "keysync", "admins", "metrics", "user_memberships", "owner_groups", "leases", "unlinked_inodes", "filename_leases"}
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
		db:            db,
		path:          path,
		clusterSecret: clusterSecret,
		trusted:       make(map[string]bool),
		metrics:       NewMetricsCollector(),
	}

	// Load KeyRing from BoltDB system bucket (Tier 2)
	err = db.Update(func(tx *bolt.Tx) error {
		krData, err := fsm.Get(tx, []byte("system"), []byte("fsm_keyring"))
		if err == nil && krData != nil {
			fsm.keyRing, _ = crypto.UnmarshalKeyRing(krData)
		}

		if fsm.keyRing == nil {
			// Initialize new cluster KeyRing if this is a fresh FSM
			k := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, k); err != nil {
				return err
			}
			fsm.keyRing = crypto.NewKeyRing(k)
			// Persist it immediately to the system bucket
			krData := fsm.keyRing.Marshal()
			if err := fsm.Put(tx, []byte("system"), []byte("fsm_keyring"), krData); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	fsm.loadTrustState()
	return fsm, nil
}

func (fsm *MetadataFSM) systemKey() []byte {
	// Derive a static key from the ClusterSecret for Tier 2 root anchor encryption
	mac := hmac.New(sha256.New, fsm.clusterSecret)
	mac.Write([]byte("FSM_SYSTEM_V1"))
	return mac.Sum(nil)
}

func (fsm *MetadataFSM) EncryptValue(bucket []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	if string(bucket) == "system" {
		// Tier 2: Use ClusterSecret for root anchors
		ct, err := crypto.EncryptDEM(fsm.systemKey(), data)
		if err != nil {
			return nil, err
		}
		// Prefix with 0 to indicate system encryption
		out := make([]byte, 4+len(ct))
		binary.BigEndian.PutUint32(out[:4], 0)
		copy(out[4:], ct)
		return out, nil
	}

	// Tier 3: Use rotating KeyRing for application data
	fsm.mu.RLock()
	kr := fsm.keyRing
	fsm.mu.RUnlock()

	if kr == nil {
		return nil, fmt.Errorf("FSM keyring not initialized")
	}

	key, gen := kr.Current()
	ct, err := crypto.EncryptDEM(key, data)
	if err != nil {
		return nil, err
	}

	// Result: [Gen(4)][Ciphertext]
	out := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(out[:4], gen)
	copy(out[4:], ct)
	return out, nil
}

func (fsm *MetadataFSM) DecryptValue(bucket []byte, data []byte) ([]byte, error) {
	if len(data) < 4 {
		return data, nil
	}
	gen := binary.BigEndian.Uint32(data[:4])

	if string(bucket) == "system" {
		if gen != 0 {
			return nil, fmt.Errorf("invalid encryption for system bucket: expected gen 0, got %d", gen)
		}
		// Tier 2: System encryption
		return crypto.DecryptDEM(fsm.systemKey(), data[4:])
	}

	// Tier 3: Application encryption
	if gen == 0 {
		return nil, fmt.Errorf("invalid encryption for non-system bucket: gen 0 reserved for system")
	}

	fsm.mu.RLock()
	kr := fsm.keyRing
	fsm.mu.RUnlock()

	if kr == nil {
		return nil, fmt.Errorf("FSM keyring not initialized")
	}

	key, ok := kr.Get(gen)
	if !ok {
		return nil, fmt.Errorf("fsm key generation %d not found", gen)
	}
	return crypto.DecryptDEM(key, data[4:])
}

func (fsm *MetadataFSM) KeyRing() *crypto.KeyRing {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.keyRing
}

func (fsm *MetadataFSM) FSMKey() []byte {
	fsm.mu.RLock()
	kr := fsm.keyRing
	fsm.mu.RUnlock()

	k, _ := kr.Current()
	return k
}

func (fsm *MetadataFSM) Put(tx *bolt.Tx, bucket []byte, key []byte, value []byte) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("internal error: bucket %s missing", string(bucket))
	}
	enc, err := fsm.EncryptValue(bucket, value)
	if err != nil {
		return err
	}
	return b.Put(key, enc)
}

func (fsm *MetadataFSM) Get(tx *bolt.Tx, bucket []byte, key []byte) ([]byte, error) {
	b := tx.Bucket(bucket)
	if b == nil {
		return nil, fmt.Errorf("internal error: bucket %s missing", string(bucket))
	}
	v := b.Get(key)
	if v == nil {
		return nil, nil
	}
	dec, err := fsm.DecryptValue(bucket, v)
	return dec, err
}

func (fsm *MetadataFSM) Delete(tx *bolt.Tx, bucket []byte, key []byte) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("internal error: bucket %s missing", string(bucket))
	}
	return b.Delete(key)
}

func (fsm *MetadataFSM) ForEach(tx *bolt.Tx, bucket []byte, fn func(k, v []byte) error) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("internal error: bucket %s missing", string(bucket))
	}
	return b.ForEach(func(k, v []byte) error {
		dec, err := fsm.DecryptValue(bucket, v)
		if err != nil {
			return err
		}
		return fn(k, dec)
	})
}

// Close closes the underlying BoltDB.
func (fsm *MetadataFSM) Close() error {
	if fsm.db != nil {
		return fsm.db.Close()
	}
	return nil
}

func (fsm *MetadataFSM) loadTrustState() {
	fsm.db.View(func(tx *bolt.Tx) error {
		// Trust state is already indexed by register node commands into the 'nodes' bucket.
		// We'll load the initial set of public keys into memory for quick MTLS validation.
		b := tx.Bucket([]byte("nodes"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			plain, err := fsm.DecryptValue([]byte("nodes"), v)
			if err != nil {
				return nil
			}
			var n Node
			if err := json.Unmarshal(plain, &n); err == nil {
				fsm.mu.Lock()
				fsm.trusted[hex.EncodeToString(n.PublicKey)] = true
				fsm.mu.Unlock()
			}
			return nil
		})
	})
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
		plain, err := fsm.Get(tx, []byte("nodes"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &node)
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
			plain, err := fsm.DecryptValue([]byte("nodes"), v)
			if err != nil {
				continue
			}
			var n Node
			if err := json.Unmarshal(plain, &n); err == nil {
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
	CmdCreateInode       CommandType = 1
	CmdUpdateInode       CommandType = 2
	CmdDeleteInode       CommandType = 3
	CmdRegisterNode      CommandType = 4
	CmdCreateUser        CommandType = 6
	CmdCreateGroup       CommandType = 7
	CmdUpdateGroup       CommandType = 8
	CmdAddChild          CommandType = 9
	CmdAddChunkReplica   CommandType = 11
	CmdSetAttr           CommandType = 13
	CmdGCRemove          CommandType = 15
	CmdSetUserQuota      CommandType = 17
	CmdRotateKey         CommandType = 18
	CmdInitWorld         CommandType = 19
	CmdStoreKeySync      CommandType = 20
	CmdBatch             CommandType = 21
	CmdAcquireLeases     CommandType = 22
	CmdReleaseLeases     CommandType = 23
	CmdPromoteAdmin      CommandType = 24
	CmdAdminChown        CommandType = 25
	CmdAdminChmod        CommandType = 26
	CmdStoreMetrics      CommandType = 27
	CmdSetGroupQuota     CommandType = 28
	CmdSetClusterSignKey CommandType = 29
	CmdRemoveNode        CommandType = 30
	CmdRotateFSMKey      CommandType = 31
	CmdReencryptValue    CommandType = 32
)

// LogCommand is the structure stored in the Raft log.
type LogCommand struct {
	Type          CommandType       `json:"type"`
	Data          json.RawMessage   `json:"data"`
	SessionID     string            `json:"session_id,omitempty"`
	LeaseBindings map[string]string `json:"lease_bindings,omitempty"` // nameHMAC -> pathID
	Atomic        bool              `json:"atomic,omitempty"`         // Roll back entire transaction on any sub-command error
}

func (c LogCommand) Marshal() []byte {
	b, _ := json.Marshal(c)
	return b
}

type ReencryptRequest struct {
	Bucket []byte `json:"bucket"`
	Key    []byte `json:"key"`
}

type LeaseRequest struct {
	InodeIDs  []string       `json:"inode_ids"`
	SessionID string         `json:"session_id"`
	Nonce     string         `json:"nonce,omitempty"`
	UserID    string         `json:"user_id"` // Actual User ID for placeholders
	Type      LeaseType      `json:"type"`
	Lockbox   crypto.Lockbox `json:"lockbox,omitempty"`
	Duration  int64          `json:"duration"` // Nanoseconds
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

type LinkRequest struct {
	ParentID string `json:"parent_id"`
	Name     string `json:"name"`
	TargetID string `json:"target_id"`
}

type RotateFSMKeyRequest struct {
	NewKey []byte `json:"new_key"`
	Gen    uint32 `json:"gen"`
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

	log.Printf("FSM: Apply Type=%d Index=%d", cmd.Type, l.Index)

	var results interface{}
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		results = fsm.executeCommand(tx, cmd.Type, cmd.Data, cmd.SessionID, cmd.LeaseBindings, 0)
		shouldRollback := cmd.Atomic && fsm.containsError(results)
		if !shouldRollback && fsm.containsRollbackError(results) {
			shouldRollback = true
		}

		if shouldRollback {
			return fmt.Errorf("command failure") // Trigger rollback
		}
		return nil
	})
	if err != nil {
		return results
	}

	// Post-apply hooks (e.g. key rotation)
	cmds := []LogCommand{cmd}
	if cmd.Type == CmdBatch {
		json.Unmarshal(cmd.Data, &cmds)
	}

	for _, c := range cmds {
		if c.Type == CmdRotateFSMKey {
			fsm.db.View(func(tx *bolt.Tx) error {
				fsm.syncKeyRing(tx)
				return nil
			})
			break
		}
	}

	return results
}

func (fsm *MetadataFSM) syncKeyRing(tx *bolt.Tx) {
	krData, err := fsm.Get(tx, []byte("system"), []byte("fsm_keyring"))
	if err != nil || krData == nil {
		return
	}

	kr, err := crypto.UnmarshalKeyRing(krData)
	if err != nil {
		return
	}

	fsm.mu.Lock()
	fsm.keyRing = kr
	fsm.mu.Unlock()
}

func (fsm *MetadataFSM) containsError(res interface{}) bool {
	if _, ok := res.(error); ok {
		return true
	}
	if slice, ok := res.([]interface{}); ok {
		for _, item := range slice {
			if fsm.containsError(item) {
				return true
			}
		}
	}
	return false
}

func (fsm *MetadataFSM) containsRollbackError(res interface{}) bool {
	if err, ok := res.(error); ok {
		return errors.Is(err, ErrAtomicRollback)
	}
	if slice, ok := res.([]interface{}); ok {
		for _, item := range slice {
			if fsm.containsRollbackError(item) {
				return true
			}
		}
	}
	return false
}

func (fsm *MetadataFSM) executeBatchCommands(tx *bolt.Tx, cmds []LogCommand, depth int) []interface{} {
	if depth > 4 {
		return []interface{}{fmt.Errorf("batch recursion depth exceeded")}
	}
	results := make([]interface{}, len(cmds))
	for i, cmd := range cmds {
		res := fsm.executeCommand(tx, cmd.Type, cmd.Data, cmd.SessionID, cmd.LeaseBindings, depth)
		results[i] = res
		if cmd.Atomic && fsm.containsError(res) {
			// Replace result with explicit rollback error to ensure top-level Apply rolls back
			results[i] = fmt.Errorf("%w: sub-command %d failed", ErrAtomicRollback, i)
		}
	}
	return results
}

func (fsm *MetadataFSM) applyBatchTx(tx *bolt.Tx, data []byte, sessionID string, depth int) []interface{} {
	var cmds []LogCommand
	if err := json.Unmarshal(data, &cmds); err != nil {
		return []interface{}{err}
	}
	// Propagate sessionID to sub-commands if not set
	for i := range cmds {
		if cmds[i].SessionID == "" {
			cmds[i].SessionID = sessionID
		}
	}
	return fsm.executeBatchCommands(tx, cmds, depth)
}

func (fsm *MetadataFSM) executeCommand(tx *bolt.Tx, cmdType CommandType, data []byte, sessionID string, leaseBindings map[string]string, depth int) interface{} {
	start := time.Now()
	defer func() {
		fsm.metrics.RecordOp(cmdType, time.Since(start))
	}()

	switch cmdType {
	case CmdCreateInode:
		return fsm.executeCreateInode(tx, data)
	case CmdUpdateInode:
		return fsm.executeUpdateInode(tx, data, sessionID, leaseBindings)
	case CmdDeleteInode:
		return fsm.executeDeleteInode(tx, data, sessionID)
	case CmdRegisterNode:
		return fsm.executeRegisterNode(tx, data)
	case CmdCreateUser:
		return fsm.executeCreateUser(tx, data)
	case CmdCreateGroup:
		return fsm.executeCreateGroup(tx, data)
	case CmdUpdateGroup:
		return fsm.executeUpdateGroup(tx, data, sessionID)
	case CmdAddChunkReplica:
		return fsm.executeAddChunkReplica(tx, data)
	case CmdGCRemove:
		return fsm.executeGCRemove(tx, data)
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
		return fsm.executeAdminChown(tx, data, sessionID)
	case CmdAdminChmod:
		return fsm.executeAdminChmod(tx, data, sessionID)
	case CmdStoreMetrics:
		return fsm.executeStoreMetrics(tx, data)
	case CmdSetGroupQuota:
		return fsm.executeSetGroupQuota(tx, data)
	case CmdSetClusterSignKey:
		return fsm.executeSetClusterSignKey(tx, data)
	case CmdRemoveNode:
		return fsm.executeRemoveNode(tx, data)
	case CmdRotateFSMKey:
		return fsm.executeRotateFSMKey(tx, data)
	case CmdReencryptValue:
		return fsm.executeReencryptValue(tx, data)
	case CmdBatch:
		return fsm.applyBatchTx(tx, data, sessionID, depth+1)
	}
	return fmt.Errorf("unknown command")
}

func (fsm *MetadataFSM) checkLease(inode *Inode, sessionID string) error {
	if inode == nil || len(inode.Leases) == 0 {
		return nil
	}
	now := time.Now().UnixNano()
	for _, l := range inode.Leases {
		if l.Expiry > now && l.Type == LeaseExclusive && l.SessionID != sessionID {
			return fmt.Errorf("exclusive lease held by another session")
		}
	}
	return nil
}

func (fsm *MetadataFSM) checkPathLease(tx *bolt.Tx, path string, sessionID string) error {
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "path:") {
		path = "path:" + path
	}

	plain, err := fsm.Get(tx, []byte("filename_leases"), []byte(path))
	if err != nil {
		return err
	}
	if plain == nil {
		return nil
	}

	var leases map[string]LeaseInfo
	if err := json.Unmarshal(plain, &leases); err != nil {
		return err
	}

	now := time.Now().UnixNano()
	for _, l := range leases {
		if l.Expiry <= now {
			continue
		}
		// During MUTATION (e.g. rename/link/unlink), ANY lease from another session
		// acts as a conflict. Even a SHARED lease from another session prevents us
		// from swapping the path out from under them.
		if l.SessionID != sessionID {
			return fmt.Errorf("%w: path %s: lease held by session %s", ErrConflict, path, l.SessionID)
		}
	}
	return nil
}

func (fsm *MetadataFSM) executeCreateInode(tx *bolt.Tx, data []byte) interface{} {
	var inode Inode
	if err := json.Unmarshal(data, &inode); err != nil {
		return err
	}

	now := time.Now().UnixNano()
	if inode.CTime == 0 {
		inode.CTime = now
	}
	if inode.Mode == 0 {
		if inode.Type == DirType {
			inode.Mode = 0755
		} else {
			inode.Mode = 0644
		}
	}
	inode.Mode = SanitizeMode(inode.Mode, inode.Type)
	if inode.NLink == 0 {
		inode.NLink = 1
	}
	v, err := fsm.Get(tx, []byte("inodes"), []byte(inode.ID))
	if err != nil {
		return err
	}
	if v != nil {
		return ErrExists
	}

	if inode.OwnerID != "" {
		if err := fsm.checkQuota(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}

	inode.Version = 1
	if err := fsm.saveInodeWithPages(tx, &inode); err != nil {
		return err
	}
	if inode.OwnerID != "" {
		if err := fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}
	return &inode
}

func (fsm *MetadataFSM) executeUpdateInode(tx *bolt.Tx, data []byte, sessionID string, leaseBindings map[string]string) interface{} {
	var inode Inode
	if err := json.Unmarshal(data, &inode); err != nil {
		return err
	}

	plain, err := fsm.Get(tx, []byte("inodes"), []byte(inode.ID))
	if err != nil {
		return err
	}
	if plain == nil {
		return ErrNotFound
	}

	var existing Inode
	if err := json.Unmarshal(plain, &existing); err != nil {
		return err
	}

	if err := fsm.checkLease(&existing, sessionID); err != nil {
		return err
	}

	// Phase 41/42: Check individual path leases if this is a directory update (atomic swap or move).
	if existing.Type == DirType && leaseBindings != nil {
		// 1. Check for removed or changed entries
		for nameHMAC, existingID := range existing.Children {
			newID, stillExists := inode.Children[nameHMAC]
			if !stillExists || newID != existingID {
				if pathID, ok := leaseBindings[nameHMAC]; ok && pathID != "" {
					if err := fsm.checkPathLease(tx, pathID, sessionID); err != nil {
						return err
					}
				}
			}
		}
		// 2. Check for newly added entries
		for nameHMAC := range inode.Children {
			if _, wasPresent := existing.Children[nameHMAC]; !wasPresent {
				if pathID, ok := leaseBindings[nameHMAC]; ok && pathID != "" {
					if err := fsm.checkPathLease(tx, pathID, sessionID); err != nil {
						return err
					}
				}
			}
		}
	}

	if inode.Version != existing.Version+1 {
		return ErrConflict
	}

	ownerChanged := inode.OwnerID != existing.OwnerID
	groupChanged := inode.GroupID != existing.GroupID

	if ownerChanged || groupChanged {
		// 1. Decrement old owner/group FIRST
		if err := fsm.updateUsage(tx, existing.OwnerID, existing.GroupID, -1, -int64(existing.Size)); err != nil {
			return err
		}
		// 2. Check Quota for new owner/group
		// Safety: NEVER allow clearing OwnerID in an update if it was set
		if inode.OwnerID == "" {
			inode.OwnerID = existing.OwnerID
		}
		if err := fsm.checkQuota(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
		// 3. Increment new owner/group
		if err := fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	} else if inode.OwnerID == "" {
		inode.OwnerID = existing.OwnerID
	}

	oldPages := existing.ChunkPages
	diffBytes := int64(inode.Size) - int64(existing.Size)

	if !(ownerChanged || groupChanged) && diffBytes > 0 {
		if err := fsm.checkQuota(tx, inode.OwnerID, inode.GroupID, 0, diffBytes); err != nil {
			return err
		}
	}

	inode.Unlinked = existing.Unlinked
	// Deep copy leases map to be safe
	if existing.Leases != nil {
		inode.Leases = make(map[string]LeaseInfo)
		for k, v := range existing.Leases {
			inode.Leases[k] = v
		}
	}

	if !inode.Unlinked {
		inode.Mode = SanitizeMode(inode.Mode, inode.Type)
	}

	if inode.NLink == 0 {
		return fsm.deleteInodeInternal(tx, &inode)
	}

	if err := fsm.saveInodeWithPages(tx, &inode); err != nil {
		return err
	}

	if !(ownerChanged || groupChanged) && diffBytes != 0 {
		if err := fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, 0, diffBytes); err != nil {
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

func (fsm *MetadataFSM) executeDeleteInode(tx *bolt.Tx, data []byte, sessionID string) interface{} {
	var id string
	if err := json.Unmarshal(data, &id); err != nil {
		id = string(data)
	}
	plain, err := fsm.Get(tx, []byte("inodes"), []byte(id))
	if err != nil {
		return err
	}
	if plain == nil {
		return nil
	}

	var inode Inode
	if err := json.Unmarshal(plain, &inode); err != nil {
		return err
	}

	if err := fsm.checkLease(&inode, sessionID); err != nil {
		return err
	}

	if inode.NLink > 0 {
		return fmt.Errorf("cannot delete inode with active links (nlink=%d)", inode.NLink)
	}

	return fsm.deleteInodeInternal(tx, &inode)
}

func (fsm *MetadataFSM) deleteInodeInternal(tx *bolt.Tx, inode *Inode) error {
	// Check for active leases
	now := time.Now().UnixNano()
	hasActiveLeases := false
	for _, l := range inode.Leases {
		if l.Expiry > now {
			hasActiveLeases = true
			break
		}
	}

	if hasActiveLeases {
		// Mark as unlinked and defer deletion
		inode.Unlinked = true
		if err := fsm.saveInodeWithPages(tx, inode); err != nil {
			return err
		}
		// Add to unlinked_inodes bucket for reaper index
		ub := tx.Bucket([]byte("unlinked_inodes"))
		return ub.Put([]byte(inode.ID), []byte("true"))
	}

	return fsm.finalizeDeleteInode(tx, inode)
}

func (fsm *MetadataFSM) finalizeDeleteInode(tx *bolt.Tx, inode *Inode) error {
	if len(inode.ChunkPages) > 0 {
		pb := tx.Bucket([]byte("chunk_pages"))
		for _, pid := range inode.ChunkPages {
			pb.Delete([]byte(pid))
		}
	}
	if inode.OwnerID != "" {
		if err := fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, -1, -int64(inode.Size)); err != nil {
			return err
		}
	}
	fsm.enqueueGC(tx, inode)

	// Clean up unlinked index if it was there
	ub := tx.Bucket([]byte("unlinked_inodes"))
	ub.Delete([]byte(inode.ID))

	return fsm.Delete(tx, []byte("inodes"), []byte(inode.ID))
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

	encoded, err := json.Marshal(node)
	if err != nil {
		return err
	}
	return fsm.Put(tx, []byte("nodes"), []byte(node.ID), encoded)
}

func (fsm *MetadataFSM) executeRemoveNode(tx *bolt.Tx, data []byte) interface{} {
	var nodeID string
	if err := json.Unmarshal(data, &nodeID); err != nil {
		nodeID = string(data) // Fallback for non-JSON raw strings if needed during transition
	}
	plain, err := fsm.Get(tx, []byte("nodes"), []byte(nodeID))
	if err != nil {
		return err
	}
	if plain == nil {
		return ErrNotFound
	}

	var node Node
	if err := json.Unmarshal(plain, &node); err != nil {
		return err
	}

	// Remove from in-memory trust cache
	fsm.mu.Lock()
	delete(fsm.trusted, string(node.PublicKey))
		delete(fsm.trusted, string(node.SignKey))
		fsm.mu.Unlock()
	
		return fsm.Delete(tx, []byte("nodes"), []byte(nodeID))
	}
	

func (fsm *MetadataFSM) executeCreateUser(tx *bolt.Tx, data []byte) interface{} {
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return err
	}

	v, err := fsm.Get(tx, []byte("users"), []byte(user.ID))
	if err != nil {
		return err
	}
	if v != nil {
		return ErrExists
	}

	// Bootstrap: First user is admin
	isFirst := false
	ub := tx.Bucket([]byte("users"))
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
			v, err := fsm.Get(tx, []byte("uids"), uint32ToBytes(uid))
			if err != nil {
				return err
			}
			if v == nil {
				user.UID = uid
				break
			}
		}
	} else {
		// If UID provided, check if already taken
		existing, err := fsm.Get(tx, []byte("uids"), uint32ToBytes(user.UID))
		if err != nil {
			return err
		}
		if existing != nil {
			return fmt.Errorf("UID %d already assigned to %s", user.UID, string(existing))
		}
	}

	encoded, err := json.Marshal(user)
	if err != nil {
		return err
	}

	if err := fsm.Put(tx, []byte("users"), []byte(user.ID), encoded); err != nil {
		return err
	}
	if err := fsm.Put(tx, []byte("uids"), uint32ToBytes(user.UID), []byte(user.ID)); err != nil {
		return err
	}

	if isFirst {
		if err := fsm.Put(tx, []byte("admins"), []byte(user.ID), []byte("true")); err != nil {
			return err
		}
	}

	return &user
}

func (fsm *MetadataFSM) executePromoteAdmin(tx *bolt.Tx, data []byte) interface{} {
	var userID string
	if err := json.Unmarshal(data, &userID); err != nil {
		userID = string(data) // Fallback for non-JSON raw strings if needed during transition
	}
	v, err := fsm.Get(tx, []byte("users"), []byte(userID))
	if err != nil {
		return err
	}
	if v == nil {
		return ErrNotFound
	}
	return fsm.Put(tx, []byte("admins"), []byte(userID), []byte("true"))
}

func (fsm *MetadataFSM) IsAdmin(userID string) bool {
	isAdmin := false
	_ = fsm.db.View(func(tx *bolt.Tx) error {
		v, err := fsm.Get(tx, []byte("admins"), []byte(userID))
		if err != nil {
			return err
		}
		if v != nil {
			isAdmin = true
		}
		return nil
	})
	return isAdmin
}

func (fsm *MetadataFSM) executeCreateGroup(tx *bolt.Tx, data []byte) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return err
	}

	v, err := fsm.Get(tx, []byte("groups"), []byte(group.ID))
	if err != nil {
		return err
	}
	if v != nil {
		return ErrExists
	}

	// Ensure GID is unique
	existing, err := fsm.Get(tx, []byte("gids"), uint32ToBytes(group.GID))
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("GID %d already assigned to %s", group.GID, string(existing))
	}

	// We trust the client's version (should be 1 for a new group)
	if group.Version == 0 {
		group.Version = 1
	}
	encoded, err := json.Marshal(group)
	if err != nil {
		return err
	}

	if err := fsm.Put(tx, []byte("groups"), []byte(group.ID), encoded); err != nil {
		return err
	}
	if err := fsm.Put(tx, []byte("gids"), uint32ToBytes(group.GID), []byte(group.ID)); err != nil {
		return err
	}

	if err := fsm.updateGroupIndices(tx, &group, nil); err != nil {
		return err
	}

	return &group
}

func (fsm *MetadataFSM) executeUpdateGroup(tx *bolt.Tx, data []byte, sessionID string) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return err
	}
	v, err := fsm.Get(tx, []byte("groups"), []byte(group.ID))
	if err != nil {
		return err
	}
	if v == nil {
		return ErrNotFound
	}

	var existing Group
	if err := json.Unmarshal(v, &existing); err != nil {
		return err
	}

	if group.Version != existing.Version+1 {
		return ErrConflict
	}

	// Handle GID change in index
	if group.GID != existing.GID {
		fsm.Delete(tx, []byte("gids"), uint32ToBytes(existing.GID))
		if err := fsm.Put(tx, []byte("gids"), uint32ToBytes(group.GID), []byte(group.ID)); err != nil {
			return err
		}
	}

	encoded, err := json.Marshal(group)
	if err != nil {
		return err
	}
	if err := fsm.Put(tx, []byte("groups"), []byte(group.ID), encoded); err != nil {
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

	encOne, _ := fsm.EncryptValue([]byte("user_memberships"), []byte("1"))

	// 1. Membership Updates
	if existing == nil {
		// New group: Add all members
		for uid := range group.Members {
			sub, err := mb.CreateBucketIfNotExists([]byte(uid))
			if err != nil {
				return err
			}
			sub.Put([]byte(group.ID), encOne)
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
				sub.Put([]byte(group.ID), encOne)
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
		sub.Put([]byte(group.ID), encOne)
	}

	return nil
}

func (fsm *MetadataFSM) executeAddChunkReplica(tx *bolt.Tx, data []byte) interface{} {
	var req AddReplicaRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	plain, err := fsm.Get(tx, []byte("inodes"), []byte(req.InodeID))
	if err != nil {
		return err
	}
	if plain == nil {
		return ErrNotFound
	}

	var inode Inode
	if err := json.Unmarshal(plain, &inode); err != nil {
		return err
	}

	// Load manifest to find chunk
	if err := fsm.LoadInodeWithPages(tx, &inode); err != nil {
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
		if err := fsm.saveInodeWithPages(tx, &inode); err != nil {
			return err
		}
	}
	return &inode
}

func (fsm *MetadataFSM) executeGCRemove(tx *bolt.Tx, data []byte) interface{} {
	var chunkID string
	if err := json.Unmarshal(data, &chunkID); err != nil {
		chunkID = string(data) // Fallback for non-JSON raw strings if needed during transition
	}
	b := tx.Bucket([]byte("garbage_collection"))
	return b.Delete([]byte(chunkID))
}

func (fsm *MetadataFSM) executeSetClusterSignKey(tx *bolt.Tx, data []byte) interface{} {
	if existing, _ := fsm.Get(tx, []byte("system"), []byte("cluster_sign_key")); existing != nil {
		return fmt.Errorf("cluster signing key already initialized")
	}
	return fsm.Put(tx, []byte("system"), []byte("cluster_sign_key"), data)
}

func (fsm *MetadataFSM) GetClusterSignPublicKey() ([]byte, error) {
	var pub []byte
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("system"), []byte("cluster_sign_key"))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		var key ClusterSignKey
		if err := json.Unmarshal(plain, &key); err != nil {
			return err
		}
		pub = key.Public
		return nil
	})
	return pub, err
}

func (fsm *MetadataFSM) GetClusterSignPrivateKey() ([]byte, error) {
	var priv []byte
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("system"), []byte("cluster_sign_key"))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		var key ClusterSignKey
		if err := json.Unmarshal(plain, &key); err != nil {
			return err
		}
		priv = key.EncryptedPrivate
		return nil
	})
	return priv, err
}

func (fsm *MetadataFSM) GetClusterSecret() ([]byte, error) {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	if fsm.clusterSecret == nil {
		return nil, ErrNotFound
	}
	return fsm.clusterSecret, nil
}

// Snapshot returns a snapshot of the current state.
func (fsm *MetadataFSM) Snapshot() (raft.FSMSnapshot, error) {
	if fsm.OnSnapshot != nil {
		if err := fsm.OnSnapshot(); err != nil {
			return nil, err
		}
	}
	return &MetadataSnapshot{db: fsm.db, keyRing: fsm.keyRing}, nil
}

func (fsm *MetadataFSM) ValidateNode(address string) error {
	err := fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				// Address in FSM is full URL (e.g. http://1.2.3.4:8080)
				// Target might be full URL or Host:Port string.
				if n.Address == address || n.ClusterAddress == address || strings.HasSuffix(n.Address, "/"+address) || strings.HasSuffix(n.ClusterAddress, "/"+address) {
					return ErrStopIteration
				}
			}
			return nil
		})
	})
	if err == ErrStopIteration {
		return nil
	}
	if err == nil {
		return fmt.Errorf("node address %s not found in registry", address)
	}
	return err
}

// Restore restores the FSM from a snapshot.
func (fsm *MetadataFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()

	if err := fsm.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}

	// 1. Read FSM KeyRing
	lBuf := make([]byte, 4)
	if _, err := io.ReadFull(rc, lBuf); err != nil {
		fsm.reopen()
		return fmt.Errorf("read keyring length: %w", err)
	}
	l := binary.BigEndian.Uint32(lBuf)
	krData := make([]byte, l)
	if _, err := io.ReadFull(rc, krData); err != nil {
		fsm.reopen()
		return fmt.Errorf("read keyring data: %w", err)
	}

	kr, err := crypto.UnmarshalKeyRing(krData)
	if err != nil {
		fsm.reopen()
		return fmt.Errorf("unmarshal keyring: %w", err)
	}

	// 2. Restore DB
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

	if err := fsm.reopen(); err != nil {
		return err
	}

	// 3. Update memory state
	fsm.mu.Lock()
	fsm.keyRing = kr
	fsm.mu.Unlock()

	// 4. Rebuild the in-memory trust cache after restoring from snapshot.
	fsm.loadTrustState()
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

type MetadataSnapshot struct {
	db      *bolt.DB
	keyRing *crypto.KeyRing
}

func (s *MetadataSnapshot) Persist(sink raft.SnapshotSink) error {
	// 1. Write FSM KeyRing
	krData := s.keyRing.Marshal()
	l := uint32(len(krData))
	lBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lBuf, l)

	if _, err := sink.Write(lBuf); err != nil {
		sink.Cancel()
		return err
	}
	if _, err := sink.Write(krData); err != nil {
		sink.Cancel()
		return err
	}

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

func (fsm *MetadataFSM) saveInodeWithPages(tx *bolt.Tx, inode *Inode) error {
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

			encoded, err := json.Marshal(page)
			if err != nil {
				return err
			}
			if err := fsm.Put(tx, []byte("chunk_pages"), []byte(page.ID), encoded); err != nil {
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

	encoded, err := json.Marshal(inode)
	if err != nil {
		return err
	}
	return fsm.Put(tx, []byte("inodes"), []byte(inode.ID), encoded)
}

func (fsm *MetadataFSM) LoadInodeWithPages(tx *bolt.Tx, inode *Inode) error {
	if len(inode.ChunkPages) > 0 && len(inode.ChunkManifest) == 0 {
		for _, pid := range inode.ChunkPages {
			plain, err := fsm.Get(tx, []byte("chunk_pages"), []byte(pid))
			if err != nil {
				return err
			}
			if plain != nil {
				var page ChunkPage
				if err := json.Unmarshal(plain, &page); err == nil {
					inode.ChunkManifest = append(inode.ChunkManifest, page.Chunks...)
				}
			}
		}
	}
	return nil
}

func (fsm *MetadataFSM) enqueueGC(tx *bolt.Tx, inode *Inode) error {
	// Ensure we have the manifest loaded
	if err := fsm.LoadInodeWithPages(tx, inode); err != nil {
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
		// GC bucket might not need encryption if chunkIDs are anonymous,
		// but let's be consistent and encrypt values.
		enc, _ := fsm.EncryptValue([]byte("garbage_collection"), nodesJSON)
		if err := b.Put([]byte(chunk.ID), enc); err != nil {
			return err
		}
	}
	return nil
}

func (fsm *MetadataFSM) updateUsage(tx *bolt.Tx, userID, groupID string, deltaInodes int64, deltaBytes int64) error {
	remainingInodes := deltaInodes
	remainingBytes := deltaBytes

	if groupID != "" {
		v, err := fsm.Get(tx, []byte("groups"), []byte(groupID))
		if err != nil {
			return err
		}
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
			if err := fsm.Put(tx, []byte("groups"), []byte(groupID), encoded); err != nil {
				return err
			}
		}
	}

	if userID != "" && (remainingInodes != 0 || remainingBytes != 0) {
		v, err := fsm.Get(tx, []byte("users"), []byte(userID))
		if err != nil {
			return err
		}
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
			if err := fsm.Put(tx, []byte("users"), []byte(userID), encoded); err != nil {
				return err
			}
		}
	}
	return nil
}

func (fsm *MetadataFSM) checkQuota(tx *bolt.Tx, userID, groupID string, deltaInodes int64, deltaBytes int64) error {
	if deltaInodes <= 0 && deltaBytes <= 0 {
		return nil
	}

	remainingInodes := deltaInodes
	remainingBytes := deltaBytes

	if groupID != "" {
		v, err := fsm.Get(tx, []byte("groups"), []byte(groupID))
		if err == nil && v != nil {
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
		v, err := fsm.Get(tx, []byte("users"), []byte(userID))
		if err != nil || v == nil {
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

	plain, err := fsm.Get(tx, []byte("users"), []byte(req.UserID))
	if err != nil {
		return err
	}
	if plain == nil {
		return ErrNotFound
	}
	var user User
	if err := json.Unmarshal(plain, &user); err != nil {
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
	return fsm.Put(tx, []byte("users"), []byte(req.UserID), encoded)
}

func (fsm *MetadataFSM) executeSetGroupQuota(tx *bolt.Tx, data []byte) interface{} {
	var req SetGroupQuotaRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	plain, err := fsm.Get(tx, []byte("groups"), []byte(req.GroupID))
	if err != nil {
		return err
	}
	if plain == nil {
		return ErrNotFound
	}
	var group Group
	if err := json.Unmarshal(plain, &group); err != nil {
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
	return fsm.Put(tx, []byte("groups"), []byte(req.GroupID), encoded)
}

func (fsm *MetadataFSM) executeRotateKey(tx *bolt.Tx, data []byte) interface{} {
	var key ClusterKey
	if err := json.Unmarshal(data, &key); err != nil {
		return err
	}

	if err := fsm.Put(tx, []byte("system"), []byte("epoch_key_"+key.ID), data); err != nil {
		return err
	}

	if err := fsm.Put(tx, []byte("system"), []byte("active_epoch_key"), []byte(key.ID)); err != nil {
		return err
	}

	// Prune
	var keys []ClusterKey
	prefix := "epoch_key_"
	err := fsm.ForEach(tx, []byte("system"), func(k, v []byte) error {
		if strings.HasPrefix(string(k), prefix) {
			var kStruct ClusterKey
			if err := json.Unmarshal(v, &kStruct); err == nil {
				keys = append(keys, kStruct)
			}
		}
		return nil
	})
	if err != nil {
		return err
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
			fsm.Delete(tx, []byte("system"), []byte("epoch_key_"+keys[oldestIdx].ID))
		}
	}

	return nil
}
func (fsm *MetadataFSM) GetActiveKey() (*ClusterKey, error) {
	var key ClusterKey
	err := fsm.db.View(func(tx *bolt.Tx) error {
		id, err := fsm.Get(tx, []byte("system"), []byte("active_epoch_key"))
		if err != nil || id == nil {
			return ErrNotFound
		}

		v, err := fsm.Get(tx, []byte("system"), []byte("epoch_key_"+string(id)))

		if err != nil || v == nil {
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
	v, err := fsm.Get(tx, []byte("system"), []byte("world_identity"))
	if err != nil {
		return err
	}
	if v != nil {
		return fmt.Errorf("world identity already initialized")
	}
	return fsm.Put(tx, []byte("system"), []byte("world_identity"), data)
}
func (fsm *MetadataFSM) GetWorldIdentity() (*WorldIdentity, error) {
	var world WorldIdentity
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("system"), []byte("world_identity"))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &world)
	})
	if err != nil {
		return nil, err
	}
	return &world, nil
}

func (fsm *MetadataFSM) IsUserInGroup(userID, groupID string) (bool, error) {
	var group Group
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("groups"), []byte(groupID))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &group)
	})
	if err != nil {
		return false, err
	}
	return group.Members[userID] || group.OwnerID == userID, nil
}

func (fsm *MetadataFSM) GetGroup(id string) (*Group, error) {
	var group Group
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("groups"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &group)
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

	encoded, err := json.Marshal(req.Blob)
	if err != nil {
		return err
	}
	return fsm.Put(tx, []byte("keysync"), []byte(req.UserID), encoded)
}

// GetKeySyncBlob retrieves the encrypted configuration blob for a user.
func (fsm *MetadataFSM) GetKeySyncBlob(userID string) (*KeySyncBlob, error) {
	var blob KeySyncBlob
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("keysync"), []byte(userID))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		return json.Unmarshal(plain, &blob)
	})
	if err != nil {
		return nil, err
	}
	return &blob, nil
}

// InspectBucket allows read-only access to a bucket for testing purposes.
func (fsm *MetadataFSM) InspectBucket(bucketName string, fn func(k, v []byte) error) error {
	return fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte(bucketName), fn)
	})
}

func (fsm *MetadataFSM) executeAcquireLeases(tx *bolt.Tx, data []byte) interface{} {
	var req LeaseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	lb := tx.Bucket([]byte("leases"))
	fb := tx.Bucket([]byte("filename_leases"))
	now := time.Now().UnixNano()
	expiry := now + req.Duration

	// 0. Proactive Cleanup (inodes)
	c := lb.Cursor()
	purged := 0
	for k, v := c.First(); k != nil && purged < 10; k, v = c.Next() {
		plain, err := fsm.DecryptValue([]byte("leases"), v)
		if err != nil {
			continue
		}
		var info LeaseInfo
		if err := json.Unmarshal(plain, &info); err == nil {
			if info.Expiry <= now {
				lb.Delete(k)
				purged++
			}
		}
	}

	// 0.1 Proactive Cleanup (filenames)
	fc := fb.Cursor()
	purged = 0
	for k, v := fc.First(); k != nil && purged < 10; k, v = fc.Next() {
		plain, err := fsm.DecryptValue([]byte("filename_leases"), v)
		if err != nil {
			continue
		}
		var leases map[string]LeaseInfo
		if err := json.Unmarshal(plain, &leases); err == nil {
			changed := false
			for nonce, info := range leases {
				if info.Expiry <= now {
					delete(leases, nonce)
					changed = true
				}
			}
			if changed {
				if len(leases) == 0 {
					fb.Delete(k)
					purged++
				} else {
					encoded, _ := json.Marshal(leases)
					fsm.Put(tx, []byte("filename_leases"), k, encoded)
				}
			}
		}
	}

	// 1. Validation Phase
	inodes := make([]*Inode, len(req.InodeIDs))
	for i, id := range req.InodeIDs {
		isPath := strings.HasPrefix(id, "path:")
		if !isPath && IsInodeID(id) {
			plain, err := fsm.Get(tx, []byte("inodes"), []byte(id))
			if err != nil {
				return err
			}
			if plain == nil {
				continue
			}
			var inode Inode
			if err := json.Unmarshal(plain, &inode); err != nil {
				return err
			}
			inodes[i] = &inode

			// Conflict check
			for _, l := range inode.Leases {
				if l.Expiry <= now {
					continue
				}
				if req.Type == LeaseExclusive {
					// Exclusive conflicts with ANY lease from another session
					if l.SessionID != req.SessionID {
						return fmt.Errorf("%w: inode %s: held by session %s", ErrConflict, id, l.SessionID)
					}
				} else {
					// Shared only conflicts with EXCLUSIVE leases from another session
					if l.Type == LeaseExclusive && l.SessionID != req.SessionID {
						return fmt.Errorf("%w: inode %s: exclusive lease held by session %s", ErrConflict, id, l.SessionID)
					}
				}
			}
		} else {
			// Filename Lease
			plain, err := fsm.Get(tx, []byte("filename_leases"), []byte(id))
			if err != nil {
				return err
			}
			if plain != nil {
				var leases map[string]LeaseInfo
				if err := json.Unmarshal(plain, &leases); err == nil {
					for _, l := range leases {
						if l.Expiry <= now {
							continue
						}
						if req.Type == LeaseExclusive {
							if l.SessionID != req.SessionID {
								return fmt.Errorf("%w: path %s: held by session %s", ErrConflict, id, l.SessionID)
							}
						} else {
							// Shared lease request: conflicts ONLY if there is an existing EXCLUSIVE lease from another session
							if l.Type == LeaseExclusive && l.SessionID != req.SessionID {
								return fmt.Errorf("%w: path %s: exclusive lease held by session %s", ErrConflict, id, l.SessionID)
							}
						}
					}
				}
			}
		}
	}

	// 2. Grant Phase
	for i, id := range req.InodeIDs {
		isPath := strings.HasPrefix(id, "path:")
		info := LeaseInfo{
			InodeID:   id,
			SessionID: req.SessionID,
			Nonce:     req.Nonce,
			Expiry:    expiry,
			Type:      req.Type,
		}

		if !isPath && IsInodeID(id) {
			inode := inodes[i]
			if inode == nil {
				inode = &Inode{
					ID:      id,
					OwnerID: req.UserID,
					Lockbox: req.Lockbox,
					Version: 1,
				}
			}

			if inode.Leases == nil {
				inode.Leases = make(map[string]LeaseInfo)
			}

			// Use Nonce as the unique key for this handle's lease
			nonce := req.Nonce
			if nonce == "" {
				nonce = "legacy-" + req.SessionID
			}
			inode.Leases[nonce] = info

			if err := fsm.saveInodeWithPages(tx, inode); err != nil {
				return err
			}
			encoded, _ := json.Marshal(info)
			leaseKey := id + ":" + nonce
			fsm.Put(tx, []byte("leases"), []byte(leaseKey), encoded)
		} else {
			// Filename lease (Map format)
			plain, err := fsm.Get(tx, []byte("filename_leases"), []byte(id))
			if err != nil {
				return err
			}
			leases := make(map[string]LeaseInfo)
			if plain != nil {
				if err := json.Unmarshal(plain, &leases); err != nil {
					return fmt.Errorf("corrupted filename leases for %s: %w", id, err)
				}
			}
			nonce := req.Nonce
			if nonce == "" {
				nonce = "legacy-" + req.SessionID
			}
			leases[nonce] = info
			encoded, _ := json.Marshal(leases)
			fsm.Put(tx, []byte("filename_leases"), []byte(id), encoded)
		}
	}

	return nil
}

func (fsm *MetadataFSM) executeReleaseLeases(tx *bolt.Tx, data []byte) interface{} {
	var req LeaseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	lb := tx.Bucket([]byte("leases"))
	fb := tx.Bucket([]byte("filename_leases"))
	now := time.Now().UnixNano()

	for _, id := range req.InodeIDs {
		isPath := strings.HasPrefix(id, "path:")
		if isPath || !IsInodeID(id) {
			// Filename Lease
			plain, err := fsm.Get(tx, []byte("filename_leases"), []byte(id))
			if err != nil {
				return err
			}
			if plain != nil {
				var leases map[string]LeaseInfo
				if err := json.Unmarshal(plain, &leases); err != nil {
					return err
				}
				nonce := req.Nonce
				if nonce == "" {
					// Robustness: find any lease belonging to this session matching requested type
					for n, l := range leases {
						if l.SessionID == req.SessionID && l.Type == req.Type {
							nonce = n
							break
						}
					}
					if nonce == "" {
						// Last resort: any from this session
						for n, l := range leases {
							if l.SessionID == req.SessionID {
								nonce = n
								break
							}
						}
					}
				}
				if nonce != "" {
					delete(leases, nonce)
					if len(leases) == 0 {
						fb.Delete([]byte(id))
					} else {
						encoded, _ := json.Marshal(leases)
						fsm.Put(tx, []byte("filename_leases"), []byte(id), encoded)
					}
				}
			}
			// Important: if it looks like a path but IS also a valid InodeID (unlikely but possible),
			// we should ALSO try to remove it from the inode bucket if it was an Inode-level lease.
			// But if it has "path:" prefix, it's definitely NOT an InodeID in the database.
			if isPath {
				continue
			}
		}

		plain, err := fsm.Get(tx, []byte("inodes"), []byte(id))
		if err != nil {
			return err
		}
		if plain == nil {
			continue
		}
		var inode Inode
		if err := json.Unmarshal(plain, &inode); err != nil {
			return err
		}

		nonce := req.Nonce
		if nonce == "" {
			// Robustness: if nonce is omitted, try to find any lease belonging to this session.
			for n, l := range inode.Leases {
				if l.SessionID == req.SessionID {
					nonce = n
					break
				}
			}
			if nonce == "" {
				nonce = "legacy-" + req.SessionID
			}
		}

		if _, ok := inode.Leases[nonce]; ok {
			delete(inode.Leases, nonce)
			lb.Delete([]byte(id + ":" + nonce))

			// Check if we should finalize deletion
			if inode.Unlinked {
				active := false
				for _, l := range inode.Leases {
					if l.Expiry > now {
						active = true
						break
					}
				}
				if !active {
					if err := fsm.finalizeDeleteInode(tx, &inode); err != nil {
						return err
					}
					continue // Inode deleted
				}
			}

			if err := fsm.saveInodeWithPages(tx, &inode); err != nil {
				return err
			}
		}
	}

	return nil
}

func (fsm *MetadataFSM) GetNodes() ([]Node, error) {
	var nodes []Node
	err := fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				nodes = append(nodes, n)
			} else {
			}
			return nil
		})
	})
	return nodes, err
}

func (fsm *MetadataFSM) executeAdminChown(tx *bolt.Tx, data []byte, sessionID string) interface{} {
	var req AdminChownRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	plain, err := fsm.Get(tx, []byte("inodes"), []byte(req.InodeID))
	if err != nil {
		return err
	}
	if plain == nil {
		return ErrNotFound
	}
	var inode Inode
	if err := json.Unmarshal(plain, &inode); err != nil {
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
		if err := fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, -1, -int64(inode.Size)); err != nil {
			return err
		}

		// 2. Check Quota for new owner/group
		if err := fsm.checkQuota(tx, newOwnerID, newGroupID, 1, int64(inode.Size)); err != nil {
			return err
		}

		// 3. Update Inode
		inode.OwnerID = newOwnerID
		inode.GroupID = newGroupID

		// 4. Increment new owner/group
		if err := fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size)); err != nil {
			return err
		}
	}

	inode.CTime = time.Now().UnixNano()
	inode.Version++

	return fsm.saveInodeWithPages(tx, &inode)
}

func (fsm *MetadataFSM) executeAdminChmod(tx *bolt.Tx, data []byte, sessionID string) interface{} {
	var req AdminChmodRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	plain, err := fsm.Get(tx, []byte("inodes"), []byte(req.InodeID))
	if err != nil {
		return err
	}
	if plain == nil {
		return ErrNotFound
	}
	var inode Inode
	if err := json.Unmarshal(plain, &inode); err != nil {
		return err
	}

	inode.Mode = SanitizeMode(req.Mode, inode.Type)
	inode.CTime = time.Now().UnixNano()
	inode.Version++

	return fsm.saveInodeWithPages(tx, &inode)
}

func (fsm *MetadataFSM) executeStoreMetrics(tx *bolt.Tx, data []byte) interface{} {
	var snap MetricSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}

	return fsm.Put(tx, []byte("metrics"), int64ToBytes(snap.Timestamp), data)
}

func (fsm *MetadataFSM) executeRotateFSMKey(tx *bolt.Tx, data []byte) interface{} {
	var req RotateFSMKeyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	// We'll update the KeyRing in memory only AFTER the transaction commits.
	// For now, store the entire updated keyring in the system bucket to ensure
	// it's part of the Raft-applied state and is included in future snapshots.

	// Temporarily add to a copy to marshal the full ring
	// Note: keyRing.Marshal() is thread-safe but we are in a write lock context anyway.
	krCopy, _ := crypto.UnmarshalKeyRing(fsm.keyRing.Marshal())
	krCopy.AddKey(req.Gen, req.NewKey)

	krData := krCopy.Marshal()
	if err := fsm.Put(tx, []byte("system"), []byte("fsm_keyring"), krData); err != nil {
		return err
	}

	return nil
}

func (fsm *MetadataFSM) executeReencryptValue(tx *bolt.Tx, data []byte) interface{} {
	var req ReencryptRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	b := tx.Bucket(req.Bucket)
	if b == nil {
		return nil
	}
	v := b.Get(req.Key)
	if v == nil {
		return nil
	}

	if len(v) < 4 {
		return nil
	}

	_, activeGen := fsm.keyRing.Current()
	if binary.BigEndian.Uint32(v[:4]) == activeGen {
		return nil // Already updated
	}

	// Fetch (decrypts automatically) and Put (encrypts with active key)
	plain, err := fsm.Get(tx, req.Bucket, req.Key)
	if err != nil {
		return err
	}
	return fsm.Put(tx, req.Bucket, req.Key, plain)
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
		plain, err := fsm.DecryptValue([]byte("metrics"), v)
		if err != nil {
			return err
		}
		return json.Unmarshal(plain, &snap)
	})
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

func (fsm *MetadataFSM) GetUserGroups(userID string) ([]GroupListEntry, error) {
	var entries []GroupListEntry
	err := fsm.db.View(func(tx *bolt.Tx) error {
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
			plain, err := fsm.Get(tx, []byte("groups"), []byte(gid))
			if err != nil || plain == nil {
				continue
			}
			var g Group
			if err := json.Unmarshal(plain, &g); err == nil {
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
					ID:         g.ID,
					OwnerID:    g.OwnerID,
					Role:       role,
					EncKey:     g.EncKey,
					Lockbox:    filteredLockbox,
					IsSystem:   g.IsSystem,
					ClientBlob: g.ClientBlob,
					Usage:      g.Usage,
					Quota:      g.Quota,
				})
			}
		}
		return nil
	})
	return entries, err
}

func (fsm *MetadataFSM) GetLeases() ([]LeaseInfo, error) {
	var leases []LeaseInfo
	now := time.Now().UnixNano()
	err := fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte("leases"), func(k, v []byte) error {
			var info LeaseInfo
			if err := json.Unmarshal(v, &info); err == nil {
				if info.Expiry > now {
					leases = append(leases, info)
				}
			}
			return nil
		})
	})
	return leases, err
}

// GetGroups returns a paginated list of groups. Sorting is stable based on lexicographical Group IDs.
func (fsm *MetadataFSM) GetGroups(cursor string, limit int) ([]Group, string, error) {
	var groups []Group
	var nextCursor string
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		var k, v []byte
		if cursor == "" {
			k, v = c.First()
		} else {
			k, v = c.Seek([]byte(cursor))
			if k != nil && string(k) == cursor {
				k, v = c.Next() // Start AFTER the cursor
			}
		}

		for count := 0; k != nil && (limit <= 0 || count < limit); k, v = c.Next() {
			plain, err := fsm.DecryptValue([]byte("groups"), v)
			if err != nil {
				return err
			}
			var g Group
			if err := json.Unmarshal(plain, &g); err == nil {
				groups = append(groups, g)
			}
			count++
		}
		if k != nil {
			nextCursor = string(k)
		}
		return nil
	})
	return groups, nextCursor, err
}
