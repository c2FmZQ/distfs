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
	"encoding/base64"
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
	ErrExists                  = errors.New("already exists")
	ErrNotFound                = errors.New("not found")
	ErrConflict                = errors.New("version conflict")
	ErrStopIteration           = errors.New("iteration stopped")
	ErrAtomicRollback          = errors.New("atomic transaction failure")
	ErrLeaseRequired           = errors.New("lease required")
	ErrStructuralInconsistency = errors.New("structural inconsistency detected")
	ErrQuotaExceeded           = errors.New("quota exceeded")
	ErrQuotaDisabled           = errors.New("group quota is disabled")
)

type CommandType uint8

const (
	CmdCreateInode       CommandType = 1
	CmdUpdateInode       CommandType = 2
	CmdDeleteInode       CommandType = 3
	CmdRegisterNode      CommandType = 4
	CmdCreateUser        CommandType = 5
	CmdCreateGroup       CommandType = 6
	CmdUpdateGroup       CommandType = 7
	CmdAddChunkReplica   CommandType = 8
	CmdGCRemove          CommandType = 9
	CmdSetUserQuota      CommandType = 10
	CmdRotateKey         CommandType = 11
	CmdInitWorld         CommandType = 12
	CmdStoreKeySync      CommandType = 13
	CmdBatch             CommandType = 14
	CmdAcquireLeases     CommandType = 15
	CmdReleaseLeases     CommandType = 16
	CmdPromoteAdmin      CommandType = 17
	CmdStoreMetrics      CommandType = 18
	CmdSetGroupQuota     CommandType = 19
	CmdSetClusterSignKey CommandType = 20
	CmdRemoveNode        CommandType = 21
	CmdRotateFSMKey      CommandType = 22
	CmdReencryptValue    CommandType = 23
)

type LogCommand struct {
	Type          CommandType       `json:"type"`
	Data          json.RawMessage   `json:"data"`
	UserID        string            `json:"uid,omitempty"`
	SessionNonce  string            `json:"sid,omitempty"`
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
	InodeIDs     []string  `json:"inode_ids"`
	SessionID    string    `json:"session_id"`
	Nonce        string    `json:"nonce,omitempty"`
	Duration     int64     `json:"duration"`
	UserID       string    `json:"user_id,omitempty"`
	Type         LeaseType `json:"type,omitempty"`
	Placeholders []Inode   `json:"placeholders,omitempty"`
}

type RotateKeyRequest struct {
	Gen uint32 `json:"gen"`
	Key []byte `json:"key"`
}

type RotateFSMKeyRequest struct {
	Gen    uint32 `json:"gen"`
	NewKey []byte `json:"new_key"`
}

type ClusterKey struct {
	ID        string `json:"id"`
	CreatedAt int64  `json:"created_at"`
	Key       []byte `json:"key"`
	EncKey    []byte `json:"enc_key,omitempty"`
	DecKey    []byte `json:"dec_key,omitempty"`
}

type AddReplicaRequest struct {
	InodeID string   `json:"inode_id"`
	ChunkID string   `json:"chunk_id"`
	NodeIDs []string `json:"node_ids"`
}

type MetadataSnapshot struct {
	db      *bolt.DB
	keyRing *crypto.KeyRing
}

func (s *MetadataSnapshot) Persist(sink raft.SnapshotSink) error {
	krData := s.keyRing.Marshal()
	lBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lBuf, uint32(len(krData)))
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

type MetadataFSM struct {
	nodeID        string
	db            *bolt.DB
	path          string
	OnSnapshot    func() error
	clusterSecret []byte
	keyRing       *crypto.KeyRing
	trusted       map[string]bool
	mu            sync.RWMutex

	metrics *MetricsCollector
}

func NewMetadataFSM(nodeID string, path string, clusterSecret []byte) (*MetadataFSM, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		buckets := []string{"inodes", "nodes", "users", "groups", "uids", "gids", "garbage_collection", "chunk_pages", "system", "keysync", "admins", "metrics", "user_memberships", "owner_groups", "leases", "unlinked_inodes", "filename_leases"}
		for _, b := range buckets {
			tx.CreateBucketIfNotExists([]byte(b))
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	fsm := &MetadataFSM{
		nodeID:        nodeID,
		db:            db,
		path:          path,
		clusterSecret: clusterSecret,
		trusted:       make(map[string]bool),
		metrics:       NewMetricsCollector(),
	}
	db.Update(func(tx *bolt.Tx) error {
		krData, _ := fsm.Get(tx, []byte("system"), []byte("fsm_keyring"))
		if krData != nil {
			fsm.keyRing, _ = crypto.UnmarshalKeyRing(krData)
		}
		if fsm.keyRing == nil && len(clusterSecret) > 0 {
			k := make([]byte, 32)
			rand.Read(k)
			fsm.keyRing = crypto.NewKeyRing(k)
			fsm.Put(tx, []byte("system"), []byte("fsm_keyring"), fsm.keyRing.Marshal())
		}
		return nil
	})
	fsm.loadTrustState()
	return fsm, nil
}

func (fsm *MetadataFSM) systemKey() []byte {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	if len(fsm.clusterSecret) == 0 {
		// Return a distinct marker or panic?
		// If we use an empty key, it corrupts. If we panic, it crashes.
		// Crashing is better than silent corruption during Raft apply.
		panic("FSM: clusterSecret is uninitialized; cannot generate systemKey")
	}
	mac := hmac.New(sha256.New, fsm.clusterSecret)
	mac.Write([]byte("FSM_SYSTEM_V1"))
	return mac.Sum(nil)
}

func (fsm *MetadataFSM) EncryptValue(bucket []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	if string(bucket) == "system" {
		ct, err := crypto.EncryptDEM(fsm.systemKey(), data)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 4+len(ct))
		binary.BigEndian.PutUint32(out[:4], 0)
		copy(out[4:], ct)
		return out, nil
	}
	fsm.mu.RLock()
	kr := fsm.keyRing
	fsm.mu.RUnlock()
	key, gen := kr.Current()
	ct, err := crypto.EncryptDEM(key, data)
	if err != nil {
		return nil, err
	}
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
	if gen == 0 {
		return crypto.DecryptDEM(fsm.systemKey(), data[4:])
	}
	fsm.mu.RLock()
	kr := fsm.keyRing
	fsm.mu.RUnlock()
	key, ok := kr.Get(gen)
	if !ok {
		return nil, fmt.Errorf("fsm key gen %d not found (bucket=%s)", gen, string(bucket))
	}
	return crypto.DecryptDEM(key, data[4:])
}

func (fsm *MetadataFSM) Get(tx *bolt.Tx, bucket, key []byte) ([]byte, error) {
	b := tx.Bucket(bucket)
	if b == nil {
		return nil, fmt.Errorf("bucket %s missing", string(bucket))
	}
	v := b.Get(key)
	if v == nil {
		return nil, nil
	}
	return fsm.DecryptValue(bucket, v)
}

func (fsm *MetadataFSM) Put(tx *bolt.Tx, bucket, key, value []byte) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("bucket %s missing", string(bucket))
	}
	enc, err := fsm.EncryptValue(bucket, value)
	if err != nil {
		return err
	}
	return b.Put(key, enc)
}

func (fsm *MetadataFSM) Delete(tx *bolt.Tx, bucket, key []byte) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("bucket %s missing", string(bucket))
	}
	return b.Delete(key)
}

func (fsm *MetadataFSM) ForEach(tx *bolt.Tx, bucket []byte, fn func(k, v []byte) error) error {
	return tx.Bucket(bucket).ForEach(func(k, v []byte) error {
		plain, err := fsm.DecryptValue(bucket, v)
		if err != nil {
			return err
		}
		return fn(k, plain)
	})
}

// GetFSMKeyRing serializes the current FSM keyring for bootstrap push.
func (fsm *MetadataFSM) GetFSMKeyRing() []byte {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	if fsm.keyRing == nil {
		return nil
	}
	return fsm.keyRing.Marshal()
}

// InitializeFSMKeyRing sets the initial keyring during bootstrap.
func (fsm *MetadataFSM) InitializeFSMKeyRing(krData []byte) error {
	kr, err := crypto.UnmarshalKeyRing(krData)
	if err != nil {
		return err
	}
	fsm.mu.Lock()
	fsm.keyRing = kr
	fsm.mu.Unlock()

	return fsm.db.Update(func(tx *bolt.Tx) error {
		return fsm.Put(tx, []byte("system"), []byte("fsm_keyring"), krData)
	})
}

func (fsm *MetadataFSM) Close() error {
	if fsm.db == nil {
		return nil
	}
	return fsm.db.Close()
}

func extractError(res interface{}) error {
	if err, ok := res.(error); ok && err != nil {
		return err
	}
	if slice, ok := res.([]interface{}); ok {
		for _, item := range slice {
			if err := extractError(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func extractErrorString(res interface{}) string {
	if err, ok := res.(error); ok && err != nil {
		return err.Error()
	}
	if s, ok := res.(string); ok && strings.HasPrefix(s, "api error:") {
		return s
	}
	if slice, ok := res.([]interface{}); ok {
		for _, item := range slice {
			if str := extractErrorString(item); str != "" {
				return str
			}
		}
	}
	return ""
}

// Apply applies a Raft log entry to the state machine.
func (fsm *MetadataFSM) Apply(l *raft.Log) interface{} {
	var cmd LogCommand
	if err := json.Unmarshal(l.Data, &cmd); err != nil {
		log.Printf("ERROR FSM Apply: failed to unmarshal command: %v (data=%s)", err, string(l.Data))
		return err
	}
	var results interface{}
	err := fsm.db.Update(func(tx *bolt.Tx) error {
		results = fsm.executeCommand(tx, cmd, 0)
		if err, ok := results.(error); ok && err != nil {
			return err // Trigger BoltDB rollback for simple errors
		}
		if cmd.Atomic && fsm.containsError(results) {
			log.Printf("DEBUG FSM Apply [%s]: Triggering rollback due to atomic failure", fsm.nodeID)
			subErr := extractError(results)
			if subErr != nil {
				return fmt.Errorf("%w: %w", ErrAtomicRollback, subErr)
			}
			return ErrAtomicRollback
		}
		return nil
	})
	if err != nil && cmd.Atomic {
		// If db.Update failed due to our explicit rollback trigger, return the error
		// so the caller can inspect it using errors.Is()
		results = err
	}
	return results
}

func (fsm *MetadataFSM) containsError(res interface{}) bool {
	if res == nil {
		return false
	}
	if err, ok := res.(error); ok && err != nil {
		return true
	}
	if s, ok := res.(string); ok && strings.HasPrefix(s, "api error:") {
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

func (fsm *MetadataFSM) executeBatchCommands(tx *bolt.Tx, cmds []LogCommand, depth int, atomic bool) []interface{} {
	if depth > 4 {
		return []interface{}{fmt.Errorf("batch recursion depth exceeded")}
	}
	preInodes := make(map[string]*Inode)
	getOriginal := func(id string) *Inode {
		if i, ok := preInodes[id]; ok {
			return i
		}
		plain, _ := fsm.Get(tx, []byte("inodes"), []byte(id))
		if plain == nil {
			preInodes[id] = nil
			return nil
		}
		var inode Inode
		json.Unmarshal(plain, &inode)
		preInodes[id] = &inode
		return &inode
	}
	results := make([]interface{}, len(cmds))
	modifiedIDs := make(map[string]bool)
	for i, cmd := range cmds {
		var id string
		switch cmd.Type {
		case CmdCreateInode, CmdUpdateInode:
			var inode Inode
			json.Unmarshal(cmd.Data, &inode)
			id = inode.ID
		case CmdDeleteInode:
			json.Unmarshal(cmd.Data, &id)
			if id == "" {
				id = string(cmd.Data)
			}
		}
		if id != "" {
			getOriginal(id)
			modifiedIDs[id] = true
		}
		res := fsm.executeCommand(tx, cmd, depth)
		results[i] = res
		// If the OUTER command (from Apply) is non-atomic, we still want to support
		// sub-batches being atomic. But BoltDB has no nested transactions.
		// So if either the OUTER batch is atomic OR this specific sub-command is atomic,
		// we stop on failure to trigger rollback.
		if (atomic || cmd.Atomic) && fsm.containsError(res) {
			return results
		}
	}
	if err := fsm.validateStructuralConsistency(tx, modifiedIDs, preInodes); err != nil {
		if len(results) > 0 {
			results[len(results)-1] = fmt.Errorf("%w: %w", ErrAtomicRollback, err)
		} else {
			return []interface{}{fmt.Errorf("%w: %w", ErrAtomicRollback, err)}
		}
	}
	return results
}

func (fsm *MetadataFSM) validateStructuralConsistency(tx *bolt.Tx, modifiedIDs map[string]bool, preInodes map[string]*Inode) error {
	expectedDeltas := make(map[string]int)
	for id := range modifiedIDs {
		plain, _ := fsm.Get(tx, []byte("inodes"), []byte(id))
		if plain == nil {
			continue
		}
		var post Inode
		json.Unmarshal(plain, &post)
		pre := preInodes[id]

		if post.Type == DirType {
			preChildren := make(map[string]string)
			if pre != nil {
				preChildren = pre.Children
			}

			for nameHMAC, childID := range post.Children {
				if oldID, wasPresent := preChildren[nameHMAC]; !wasPresent || oldID != childID {
					expectedDeltas[childID]++
					childPlain, _ := fsm.Get(tx, []byte("inodes"), []byte(childID))
					if childPlain != nil {
						var child Inode
						json.Unmarshal(childPlain, &child)
						linkKey := id + ":" + nameHMAC
						if child.Links == nil || !child.Links[linkKey] {
							return fmt.Errorf("%w: child %s missing reciprocal link to %s", ErrStructuralInconsistency, childID, linkKey)
						}
					}
				}
			}
			for nameHMAC, childID := range preChildren {
				newID, stillPresent := post.Children[nameHMAC]
				if !stillPresent || newID != childID {
					expectedDeltas[childID]--
				}
			}
		} else {
			if len(post.Children) > 0 {
				return fmt.Errorf("%w: non-directory %s has children", ErrStructuralInconsistency, id)
			}
		}
	}

	for id, delta := range expectedDeltas {
		if delta != 0 && !modifiedIDs[id] {
			return fmt.Errorf("%w: inode %s expected nlink delta %d but was not modified in batch", ErrStructuralInconsistency, id, delta)
		}
	}

	for id := range modifiedIDs {
		pre := preInodes[id]
		plain, _ := fsm.Get(tx, []byte("inodes"), []byte(id))
		if plain == nil {
			continue
		}
		var post Inode
		json.Unmarshal(plain, &post)
		delta := expectedDeltas[id]
		preN := nlinkVal(pre)

		expectedN := int64(preN) + int64(delta)
		// Special Case: New Inode with NLink=1 and no parent links (Initial Root or Orphan)
		if preN == 0 && post.NLink == 1 && len(post.Links) == 0 {
			expectedN = 1
		}

		if int64(post.NLink) != expectedN {
			return fmt.Errorf("%w: inode %s nlink mismatch: expected %d, got %d", ErrStructuralInconsistency, id, expectedN, post.NLink)
		}
		if post.Type == DirType && post.NLink > 1 {
			return fmt.Errorf("%w: directory %s has nlink > 1 (%d)", ErrStructuralInconsistency, id, post.NLink)
		}
		if post.NLink > 0 && len(post.Links) == 0 && post.ID != RootID && !post.IsSystem {
			if post.NLink != 1 {
				return fmt.Errorf("%w: non-root inode %s has no parent links", ErrStructuralInconsistency, id)
			}
		}
		if len(post.Links) == 0 && post.NLink == 0 && id == RootID {
			return fmt.Errorf("%w: cannot unlink root inode %s", ErrStructuralInconsistency, id)
		}
	}
	return nil
}

func nlinkVal(i *Inode) uint32 {
	if i == nil {
		return 0
	}
	return i.NLink
}

func (fsm *MetadataFSM) executeCommand(tx *bolt.Tx, cmd LogCommand, depth int) interface{} {
	switch cmd.Type {
	case CmdCreateInode:
		return fsm.executeCreateInode(tx, cmd.Data, cmd.UserID)
	case CmdUpdateInode:
		return fsm.executeUpdateInode(tx, cmd.Data, cmd.UserID, cmd.SessionNonce, cmd.LeaseBindings)
	case CmdDeleteInode:
		return fsm.executeDeleteInode(tx, cmd.Data, cmd.SessionNonce)
	case CmdRegisterNode:
		return fsm.executeRegisterNode(tx, cmd.Data)
	case CmdCreateUser:
		return fsm.executeCreateUser(tx, cmd.Data)
	case CmdCreateGroup:
		return fsm.executeCreateGroup(tx, cmd.Data)
	case CmdUpdateGroup:
		return fsm.executeUpdateGroup(tx, cmd.Data, cmd.UserID)
	case CmdAddChunkReplica:
		return fsm.executeAddChunkReplica(tx, cmd.Data)
	case CmdGCRemove:
		return fsm.executeGCRemove(tx, cmd.Data)
	case CmdSetUserQuota:
		return fsm.executeSetUserQuota(tx, cmd.Data)
	case CmdRotateKey:
		return fsm.executeRotateKey(tx, cmd.Data)
	case CmdInitWorld:
		return fsm.executeInitWorld(tx, cmd.Data)
	case CmdStoreKeySync:
		return fsm.executeStoreKeySync(tx, cmd.Data)
	case CmdAcquireLeases:
		return fsm.executeAcquireLeases(tx, cmd.Data, cmd.SessionNonce)
	case CmdReleaseLeases:
		return fsm.executeReleaseLeases(tx, cmd.Data, cmd.SessionNonce)
	case CmdPromoteAdmin:
		return fsm.executePromoteAdmin(tx, cmd.Data)
	case CmdStoreMetrics:
		return fsm.executeStoreMetrics(tx, cmd.Data)
	case CmdSetGroupQuota:
		return fsm.executeSetGroupQuota(tx, cmd.Data)
	case CmdSetClusterSignKey:
		return fsm.executeSetClusterSignKey(tx, cmd.Data)
	case CmdRemoveNode:
		return fsm.executeRemoveNode(tx, cmd.Data)
	case CmdRotateFSMKey:
		return fsm.executeRotateFSMKey(tx, cmd.Data)
	case CmdReencryptValue:
		return fsm.executeReencryptValue(tx, cmd.Data)
	case CmdBatch:
		var subCmds []LogCommand
		json.Unmarshal(cmd.Data, &subCmds)
		for i := range subCmds {
			if subCmds[i].UserID == "" {
				subCmds[i].UserID = cmd.UserID
			}
			if subCmds[i].SessionNonce == "" {
				subCmds[i].SessionNonce = cmd.SessionNonce
			}
		}
		return fsm.executeBatchCommands(tx, subCmds, depth+1, cmd.Atomic)
	}
	return fmt.Errorf("unknown command")
}

func (fsm *MetadataFSM) resolveSessionUser(sessionID string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("missing session ID")
	}
	b, err := base64.StdEncoding.DecodeString(sessionID)
	if err != nil {
		return "", fmt.Errorf("invalid session encoding")
	}
	var st SignedSessionToken
	if err := json.Unmarshal(b, &st); err != nil {
		return "", fmt.Errorf("failed to unmarshal session: %w", err)
	}
	return st.Token.UserID, nil
}

func (fsm *MetadataFSM) checkLease(inode *Inode, sessionNonce string) error {
	if inode == nil || len(inode.Leases) == 0 {
		return nil
	}
	now := time.Now().UnixNano()
	for _, l := range inode.Leases {
		if l.Expiry > now && l.Type == LeaseExclusive && l.SessionID != sessionNonce {
			return fmt.Errorf("exclusive lease held by another session")
		}
	}
	return nil
}

func (fsm *MetadataFSM) checkPathLease(tx *bolt.Tx, path, sessionNonce string) error {
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "path:") {
		path = "path:" + path
	}
	plain, _ := fsm.Get(tx, []byte("filename_leases"), []byte(path))
	if plain == nil {
		return nil
	}
	var leases map[string]LeaseInfo
	json.Unmarshal(plain, &leases)
	now := time.Now().UnixNano()
	for _, l := range leases {
		if l.Expiry > now && l.SessionID != sessionNonce {
			return fmt.Errorf("%w: path %s: lease held by session %s", ErrConflict, path, l.SessionID)
		}
	}
	return nil
}

func (fsm *MetadataFSM) verifyInodeSignature(tx *bolt.Tx, inode *Inode, userID string) error {
	if len(inode.UserSig) == 0 {
		return fmt.Errorf("missing UserSig")
	}

	if userID == "" {
		return fmt.Errorf("signature verification failed: missing UserID")
	}

	// 1. Fetch User SignKey
	v, err := fsm.Get(tx, []byte("users"), []byte(userID))
	if err != nil {
		return fmt.Errorf("failed to fetch user: %w", err)
	}
	if v == nil {
		return fmt.Errorf("user %s not found", userID)
	}
	var user User
	if err := json.Unmarshal(v, &user); err != nil {
		return fmt.Errorf("failed to unmarshal user: %w", err)
	}

	// 2. Verify Signature
	hash := inode.ManifestHash()
	if !crypto.VerifySignature(user.SignKey, hash, inode.UserSig) {
		return fmt.Errorf("invalid UserSig for user %s", userID)
	}

	return nil
}

func (fsm *MetadataFSM) executeCreateInode(tx *bolt.Tx, data []byte, userID string) interface{} {
	var inode Inode
	json.Unmarshal(data, &inode)

	if err := fsm.verifyInodeSignature(tx, &inode, userID); err != nil {
		return err
	}

	// Phase 47: Admin creation bypass. Only admins can create inodes for other users.
	if inode.OwnerID != userID && !fsm.IsAdmin(userID) {
		return fmt.Errorf("user %s is not authorized to create inodes for %s", userID, inode.OwnerID)
	}

	if inode.CTime == 0 {
		inode.CTime = time.Now().UnixNano()
	}
	inode.Mode = SanitizeMode(inode.Mode, inode.Type)
	if inode.NLink == 0 {
		inode.NLink = 1
	}
	v, _ := fsm.Get(tx, []byte("inodes"), []byte(inode.ID))
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
		fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, 1, int64(inode.Size))
	}
	return &inode
}

func (fsm *MetadataFSM) executeUpdateInode(tx *bolt.Tx, data []byte, userID, sessionNonce string, leaseBindings map[string]string) interface{} {
	var update Inode
	json.Unmarshal(data, &update)

	if err := fsm.verifyInodeSignature(tx, &update, userID); err != nil {
		return err
	}

	var fields map[string]json.RawMessage
	json.Unmarshal(data, &fields)

	plain, err := fsm.Get(tx, []byte("inodes"), []byte(update.ID))
	if err != nil {
		log.Printf("DEBUG FSM executeUpdateInode: Get error for %s: %v", update.ID, err)
	}
	if plain == nil {
		log.Printf("DEBUG FSM executeUpdateInode: Inode %s not found (err=%v)", update.ID, err)
		return ErrNotFound
	}
	var inode Inode
	json.Unmarshal(plain, &inode)

	if update.Version != inode.Version+1 {
		return ErrConflict
	}

	if err := fsm.checkLease(&inode, sessionNonce); err != nil {
		return err
	}
	if inode.Type == DirType {
		for nameHMAC, existingID := range inode.Children {
			newID, stillExists := update.Children[nameHMAC]
			if !stillExists || newID != existingID {
				pathID, ok := leaseBindings[nameHMAC]
				if !ok {
					return fmt.Errorf("%w: missing lease binding for change to entry %s", ErrLeaseRequired, nameHMAC)
				}
				if err := fsm.checkPathLease(tx, pathID, sessionNonce); err != nil {
					return err
				}
			}
		}
		for nameHMAC := range update.Children {
			if _, wasPresent := inode.Children[nameHMAC]; !wasPresent {
				pathID, ok := leaseBindings[nameHMAC]
				if !ok {
					return fmt.Errorf("%w: missing lease binding for new entry %s", ErrLeaseRequired, nameHMAC)
				}
				if err := fsm.checkPathLease(tx, pathID, sessionNonce); err != nil {
					return err
				}
			}
		}
	}
	ownerChanged := fields["owner_id"] != nil && update.OwnerID != inode.OwnerID
	if ownerChanged {
		return fmt.Errorf("OwnerID is immutable")
	}

	groupChanged := fields["group_id"] != nil && update.GroupID != inode.GroupID
	if groupChanged && update.GroupID != "" {
		// Verify signer is authorized for the new group
		v, err := fsm.Get(tx, []byte("groups"), []byte(update.GroupID))
		if err != nil {
			return fmt.Errorf("failed to fetch group: %w", err)
		}
		if v == nil {
			return fmt.Errorf("group %s not found", update.GroupID)
		}
		var group Group
		json.Unmarshal(v, &group)
		if !group.Members[userID] && group.OwnerID != userID {
			return fmt.Errorf("user %s is not authorized to assign files to group %s", userID, update.GroupID)
		}
	}

	if groupChanged {
		newGroup := update.GroupID
		if err := fsm.checkQuota(tx, inode.OwnerID, newGroup, 1, int64(update.Size)); err != nil {
			return err
		}
		fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, -1, -int64(inode.Size))
		fsm.updateUsage(tx, inode.OwnerID, newGroup, 1, int64(update.Size))
		inode.GroupID = newGroup
	}
	oldPages := inode.ChunkPages
	diffBytes := int64(update.Size) - int64(inode.Size)
	if !(ownerChanged || groupChanged) && fields["size"] != nil && diffBytes > 0 {
		if err := fsm.checkQuota(tx, inode.OwnerID, inode.GroupID, 0, diffBytes); err != nil {
			return err
		}
	}
	inode.Version = update.Version
	if fields["mode"] != nil {
		inode.Mode = update.Mode
	}
	if fields["size"] != nil {
		inode.Size = update.Size
	}
	if fields["ctime"] != nil {
		inode.CTime = update.CTime
	}
	if update.ClientBlob != nil {
		inode.ClientBlob = update.ClientBlob
	}
	if update.Children != nil || fields["children"] != nil {
		inode.Children = update.Children
	}
	if update.ChunkManifest != nil {
		inode.ChunkManifest = update.ChunkManifest
	}
	if update.ChunkPages != nil {
		inode.ChunkPages = update.ChunkPages
	}
	if update.UserSig != nil {
		inode.UserSig = update.UserSig
	}
	if update.GroupSig != nil {
		inode.GroupSig = update.GroupSig
	}
	if update.SignerID != "" {
		inode.SignerID = update.SignerID
	}
	if len(update.Lockbox) > 0 {
		inode.Lockbox = update.Lockbox
	}
	if fields["is_system"] != nil {
		inode.IsSystem = update.IsSystem
	}
	if fields["nlink"] != nil {
		inode.NLink = update.NLink
	}
	if fields["unlinked"] != nil {
		inode.Unlinked = update.Unlinked
	}
	if update.Links != nil || fields["links"] != nil {
		inode.Links = update.Links
	}
	if !inode.Unlinked {
		inode.Mode = SanitizeMode(inode.Mode, inode.Type)
	}
	if inode.NLink == 0 {
		err := fsm.deleteInodeInternal(tx, &inode)
		if err != nil {
			return err
		}
		return &inode
	}
	fsm.saveInodeWithPages(tx, &inode)
	if !(ownerChanged || groupChanged) && fields["size"] != nil && diffBytes != 0 {
		fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, 0, diffBytes)
	}
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

func (fsm *MetadataFSM) executeDeleteInode(tx *bolt.Tx, data []byte, sessionNonce string) interface{} {
	var id string
	if err := json.Unmarshal(data, &id); err != nil {
		id = string(data)
	}
	plain, _ := fsm.Get(tx, []byte("inodes"), []byte(id))
	if plain == nil {
		return nil
	}
	var inode Inode
	json.Unmarshal(plain, &inode)
	if err := fsm.checkLease(&inode, sessionNonce); err != nil {
		return err
	}
	if inode.NLink > 0 {
		return fmt.Errorf("cannot delete inode with active links (nlink=%d)", inode.NLink)
	}
	if inode.Type == DirType && len(inode.Children) > 0 {
		return fmt.Errorf("cannot delete non-empty directory")
	}
	err := fsm.deleteInodeInternal(tx, &inode)
	if err != nil {
		return err
	}
	return &inode
}

func (fsm *MetadataFSM) deleteInodeInternal(tx *bolt.Tx, inode *Inode) error {
	now := time.Now().UnixNano()
	hasActiveLeases := false
	for _, l := range inode.Leases {
		if l.Expiry > now {
			hasActiveLeases = true
			break
		}
	}
	if hasActiveLeases {
		inode.Unlinked = true
		fsm.saveInodeWithPages(tx, inode)
		tx.Bucket([]byte("unlinked_inodes")).Put([]byte(inode.ID), []byte("true"))
		return nil
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
		fsm.updateUsage(tx, inode.OwnerID, inode.GroupID, -1, -int64(inode.Size))
	}
	fsm.enqueueGC(tx, inode)
	tx.Bucket([]byte("unlinked_inodes")).Delete([]byte(inode.ID))
	return fsm.Delete(tx, []byte("inodes"), []byte(inode.ID))
}

func (fsm *MetadataFSM) executeRegisterNode(tx *bolt.Tx, data []byte) interface{} {
	var node Node
	json.Unmarshal(data, &node)
	fsm.mu.Lock()
	fsm.trusted[hex.EncodeToString(node.SignKey)] = true
	fsm.mu.Unlock()
	encoded, _ := json.Marshal(node)
	return fsm.Put(tx, []byte("nodes"), []byte(node.ID), encoded)
}

func (fsm *MetadataFSM) executeCreateUser(tx *bolt.Tx, data []byte) interface{} {
	var user User
	json.Unmarshal(data, &user)

	if user.UID == 0 {
		return fmt.Errorf("UID must be provided and non-zero")
	}

	// Enforce UID uniqueness
	existing, _ := fsm.Get(tx, []byte("uids"), uint32ToBytes(user.UID))
	if existing != nil && string(existing) != user.ID {
		return fmt.Errorf("UID %d already assigned", user.UID)
	}

	ub := tx.Bucket([]byte("users"))
	isFirst := true
	if k, _ := ub.Cursor().First(); k != nil {
		isFirst = false
	}

	encoded, _ := json.Marshal(user)
	fsm.Put(tx, []byte("users"), []byte(user.ID), encoded)
	fsm.Put(tx, []byte("uids"), uint32ToBytes(user.UID), []byte(user.ID))

	// Bootstrap: First user is admin
	if isFirst {
		log.Printf("DEBUG FSM [%s]: Bootstrapping first user %s as admin", fsm.nodeID, user.ID)
		fsm.Put(tx, []byte("admins"), []byte(user.ID), []byte("true"))
	}

	return &user
}

func (fsm *MetadataFSM) executePromoteAdmin(tx *bolt.Tx, data []byte) interface{} {
	var userID string
	if err := json.Unmarshal(data, &userID); err != nil {
		userID = string(data)
	}
	log.Printf("DEBUG FSM PromoteAdmin [%s]: promoting user %s", fsm.nodeID, userID)
	return fsm.Put(tx, []byte("admins"), []byte(userID), []byte("true"))
}

// IsAdmin returns true if the given user has administrative privileges.
func (s *Server) IsAdmin(userID string) bool {
	return s.fsm.IsAdmin(userID)
}

func (fsm *MetadataFSM) IsAdmin(userID string) bool {
	var isAdmin bool
	fsm.db.View(func(tx *bolt.Tx) error {
		v, _ := fsm.Get(tx, []byte("admins"), []byte(userID))
		isAdmin = v != nil
		log.Printf("DEBUG FSM IsAdmin [%s]: user=%q isAdmin=%v (val=%q)", fsm.nodeID, userID, isAdmin, string(v))
		return nil
	})
	return isAdmin
}

func (fsm *MetadataFSM) executeCreateGroup(tx *bolt.Tx, data []byte) interface{} {
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return err
	}
	if group.Version == 0 {
		group.Version = 1
	}

	if group.GID == 0 {
		return fmt.Errorf("GID must be provided and non-zero")
	}

	// Enforce GID uniqueness
	existing, _ := fsm.Get(tx, []byte("gids"), uint32ToBytes(group.GID))
	if existing != nil && string(existing) != group.ID {
		return fmt.Errorf("GID %d already assigned", group.GID)
	}

	fsm.updateGroupIndices(tx, &group, nil)
	encoded, _ := json.Marshal(group)
	fsm.Put(tx, []byte("groups"), []byte(group.ID), encoded)
	fsm.Put(tx, []byte("gids"), uint32ToBytes(group.GID), []byte(group.ID))
	return &group
}

func (fsm *MetadataFSM) executeUpdateGroup(tx *bolt.Tx, data []byte, sessionID string) interface{} {
	var update Group
	json.Unmarshal(data, &update)
	plain, _ := fsm.Get(tx, []byte("groups"), []byte(update.ID))
	if plain == nil {
		return ErrNotFound
	}
	var existing Group
	json.Unmarshal(plain, &existing)
	if update.Version != existing.Version+1 {
		return ErrConflict
	}
	update.QuotaEnabled = existing.QuotaEnabled // Immutable
	fsm.updateGroupIndices(tx, &update, &existing)
	encoded, _ := json.Marshal(update)
	return fsm.Put(tx, []byte("groups"), []byte(update.ID), encoded)
}

func (fsm *MetadataFSM) updateGroupIndices(tx *bolt.Tx, group, existing *Group) error {
	mb := tx.Bucket([]byte("user_memberships"))
	ob := tx.Bucket([]byte("owner_groups"))
	encOne, err := fsm.EncryptValue([]byte("user_memberships"), []byte("1"))
	if err != nil {
		return err
	}
	if existing != nil {
		for uid := range existing.Members {
			if !group.Members[uid] {
				sub := mb.Bucket([]byte(uid))
				if sub != nil {
					sub.Delete([]byte(existing.ID))
				}
			}
		}
		if existing.OwnerID != "" && existing.OwnerID != group.OwnerID {
			sub := ob.Bucket([]byte(existing.OwnerID))
			if sub != nil {
				sub.Delete([]byte(existing.ID))
			}
		}
	}
	for uid := range group.Members {
		if uid != "" && (existing == nil || !existing.Members[uid]) {
			sub, err := mb.CreateBucketIfNotExists([]byte(uid))
			if err == nil && sub != nil {
				sub.Put([]byte(group.ID), encOne)
			}
		}
	}
	if group.OwnerID != "" && (existing == nil || existing.OwnerID != group.OwnerID) {
		sub, err := ob.CreateBucketIfNotExists([]byte(group.OwnerID))
		if err == nil && sub != nil {
			sub.Put([]byte(group.ID), encOne)
		}
	}
	return nil
}

func (fsm *MetadataFSM) executeAddChunkReplica(tx *bolt.Tx, data []byte) interface{} {
	var req AddReplicaRequest
	json.Unmarshal(data, &req)
	plain, _ := fsm.Get(tx, []byte("inodes"), []byte(req.InodeID))
	if plain == nil {
		return ErrNotFound
	}
	var inode Inode
	json.Unmarshal(plain, &inode)
	fsm.LoadInodeWithPages(tx, &inode)
	for i, chunk := range inode.ChunkManifest {
		if chunk.ID == req.ChunkID {
			for _, nid := range req.NodeIDs {
				found := false
				for _, eid := range chunk.Nodes {
					if eid == nid {
						found = true
						break
					}
				}
				if !found {
					inode.ChunkManifest[i].Nodes = append(inode.ChunkManifest[i].Nodes, nid)
				}
			}
			break
		}
	}
	return fsm.saveInodeWithPages(tx, &inode)
}

func (fsm *MetadataFSM) executeGCRemove(tx *bolt.Tx, data []byte) interface{} {
	var chunkID string
	if err := json.Unmarshal(data, &chunkID); err != nil {
		chunkID = string(data)
	}
	return tx.Bucket([]byte("garbage_collection")).Delete([]byte(chunkID))
}

func (fsm *MetadataFSM) executeSetUserQuota(tx *bolt.Tx, data []byte) interface{} {
	var req SetUserQuotaRequest
	err := json.Unmarshal(data, &req)
	if err != nil {
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
	json.Unmarshal(plain, &user)
	if req.MaxBytes != nil {
		user.Quota.MaxBytes = int64(*req.MaxBytes)
	}
	if req.MaxInodes != nil {
		user.Quota.MaxInodes = int64(*req.MaxInodes)
	}
	encoded, _ := json.Marshal(user)
	return fsm.Put(tx, []byte("users"), []byte(req.UserID), encoded)
}

func (fsm *MetadataFSM) executeSetGroupQuota(tx *bolt.Tx, data []byte) interface{} {
	var req SetGroupQuotaRequest
	err := json.Unmarshal(data, &req)
	if err != nil {
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
	json.Unmarshal(plain, &group)

	if !group.QuotaEnabled {
		return ErrQuotaDisabled
	}

	if req.MaxBytes != nil {
		group.Quota.MaxBytes = int64(*req.MaxBytes)
	}
	if req.MaxInodes != nil {
		group.Quota.MaxInodes = int64(*req.MaxInodes)
	}

	encoded, _ := json.Marshal(group)
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

	// Prune old keys (optional, keep last 5)
	return nil
}

func (fsm *MetadataFSM) executeInitWorld(tx *bolt.Tx, data []byte) interface{} {
	return fsm.Put(tx, []byte("system"), []byte("world_identity"), data)
}

func (fsm *MetadataFSM) executeStoreKeySync(tx *bolt.Tx, data []byte) interface{} {
	var req KeySyncRequest
	json.Unmarshal(data, &req)
	encoded, _ := json.Marshal(req.Blob)
	return fsm.Put(tx, []byte("keysync"), []byte(req.UserID), encoded)
}

func (fsm *MetadataFSM) executeStoreMetrics(tx *bolt.Tx, data []byte) interface{} {
	var snap MetricSnapshot
	json.Unmarshal(data, &snap)
	return fsm.Put(tx, []byte("metrics"), int64ToBytes(snap.Timestamp), data)
}

func (fsm *MetadataFSM) executeRotateFSMKey(tx *bolt.Tx, data []byte) interface{} {
	var req RotateFSMKeyRequest
	json.Unmarshal(data, &req)
	fsm.mu.Lock()
	fsm.keyRing.AddKey(req.Gen, req.NewKey)
	krData := fsm.keyRing.Marshal()
	fsm.mu.Unlock()
	return fsm.Put(tx, []byte("system"), []byte("fsm_keyring"), krData)
}

func (fsm *MetadataFSM) executeReencryptValue(tx *bolt.Tx, data []byte) interface{} {
	var req ReencryptRequest
	json.Unmarshal(data, &req)
	plain, err := fsm.Get(tx, req.Bucket, req.Key)
	if err != nil {
		return err
	}
	return fsm.Put(tx, req.Bucket, req.Key, plain)
}

func (fsm *MetadataFSM) executeSetClusterSignKey(tx *bolt.Tx, data []byte) interface{} {
	return fsm.Put(tx, []byte("system"), []byte("cluster_sign_key"), data)
}

func (fsm *MetadataFSM) executeRemoveNode(tx *bolt.Tx, data []byte) interface{} {
	var nodeID string
	json.Unmarshal(data, &nodeID)

	// Fetch node to revoke trust from in-memory map
	if v, err := fsm.Get(tx, []byte("nodes"), []byte(nodeID)); err == nil && v != nil {
		var node Node
		if err := json.Unmarshal(v, &node); err == nil {
			fsm.mu.Lock()
			delete(fsm.trusted, hex.EncodeToString(node.SignKey))
			fsm.mu.Unlock()
		}
	}

	return fsm.Delete(tx, []byte("nodes"), []byte(nodeID))
}

func (fsm *MetadataFSM) loadTrustState() {
	fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil && n.Status == NodeStatusActive {
				fsm.mu.Lock()
				fsm.trusted[hex.EncodeToString(n.SignKey)] = true
				fsm.mu.Unlock()
			}
			return nil
		})
	})
}

func (fsm *MetadataFSM) saveInodeWithPages(tx *bolt.Tx, inode *Inode) error {
	const maxManifest = 100
	if len(inode.ChunkManifest) > maxManifest {
		pages := (len(inode.ChunkManifest) + maxManifest - 1) / maxManifest
		inode.ChunkPages = make([]string, pages)
		for i := 0; i < pages; i++ {
			start := i * maxManifest
			end := (i + 1) * maxManifest
			if end > len(inode.ChunkManifest) {
				end = len(inode.ChunkManifest)
			}
			pageID := fmt.Sprintf("%s:p%d", inode.ID, i)
			page := ChunkPage{ID: pageID, Chunks: inode.ChunkManifest[start:end]}
			data, _ := json.Marshal(page)
			fsm.Put(tx, []byte("chunk_pages"), []byte(pageID), data)
			inode.ChunkPages[i] = pageID
		}
		savedManifest := inode.ChunkManifest
		inode.ChunkManifest = nil
		data, _ := json.Marshal(inode)
		err := fsm.Put(tx, []byte("inodes"), []byte(inode.ID), data)
		inode.ChunkManifest = savedManifest
		return err
	}
	data, _ := json.Marshal(inode)
	return fsm.Put(tx, []byte("inodes"), []byte(inode.ID), data)
}

func (fsm *MetadataFSM) LoadInodeWithPages(tx *bolt.Tx, inode *Inode) error {
	if len(inode.ChunkPages) > 0 {
		inode.ChunkManifest = nil
		for _, pid := range inode.ChunkPages {
			plain, err := fsm.Get(tx, []byte("chunk_pages"), []byte(pid))
			if err == nil && plain != nil {
				var page ChunkPage
				if err := json.Unmarshal(plain, &page); err == nil {
					inode.ChunkManifest = append(inode.ChunkManifest, page.Chunks...)
				}
			}
		}
	}
	return nil
}

func (fsm *MetadataFSM) checkQuota(tx *bolt.Tx, userID, groupID string, inodes, bytes int64) error {
	var g *Group
	if groupID != "" {
		plain, _ := fsm.Get(tx, []byte("groups"), []byte(groupID))
		if plain != nil {
			var group Group
			json.Unmarshal(plain, &group)
			g = &group
		}
	}

	var u *User
	if userID != "" {
		plain, _ := fsm.Get(tx, []byte("users"), []byte(userID))
		if plain != nil {
			var user User
			json.Unmarshal(plain, &user)
			u = &user
		}
	}

	// 1. Check Inode Quota
	if inodes != 0 {
		if g != nil && g.QuotaEnabled {
			if g.Quota.MaxInodes > 0 && g.Usage.InodeCount+inodes > g.Quota.MaxInodes {
				return fmt.Errorf("%w: group inode quota exceeded", ErrQuotaExceeded)
			}
		} else if u != nil {
			if u.Quota.MaxInodes > 0 && u.Usage.InodeCount+inodes > u.Quota.MaxInodes {
				return fmt.Errorf("%w: user inode quota exceeded", ErrQuotaExceeded)
			}
		}
	}

	// 2. Check Byte Quota
	if bytes != 0 {
		if g != nil && g.QuotaEnabled {
			if g.Quota.MaxBytes > 0 && g.Usage.TotalBytes+bytes > g.Quota.MaxBytes {
				return fmt.Errorf("%w: group storage quota exceeded", ErrQuotaExceeded)
			}
		} else if u != nil {
			if u.Quota.MaxBytes > 0 && u.Usage.TotalBytes+bytes > u.Quota.MaxBytes {
				return fmt.Errorf("%w: user storage quota exceeded", ErrQuotaExceeded)
			}
		}
	}

	return nil
}

func (fsm *MetadataFSM) updateUsage(tx *bolt.Tx, userID, groupID string, inodes, bytes int64) error {
	var g *Group
	if groupID != "" {
		plain, _ := fsm.Get(tx, []byte("groups"), []byte(groupID))
		if plain != nil {
			var group Group
			json.Unmarshal(plain, &group)
			g = &group
		}
	}

	var u *User
	if userID != "" {
		plain, _ := fsm.Get(tx, []byte("users"), []byte(userID))
		if plain != nil {
			var user User
			json.Unmarshal(plain, &user)
			u = &user
		}
	}

	// 1. Update Inode Usage
	if inodes != 0 {
		if g != nil && g.QuotaEnabled {
			g.Usage.InodeCount += inodes
		} else if u != nil {
			u.Usage.InodeCount += inodes
		}
	}

	// 2. Update Byte Usage
	if bytes != 0 {
		if g != nil && g.QuotaEnabled {
			g.Usage.TotalBytes += bytes
		} else if u != nil {
			u.Usage.TotalBytes += bytes
		}
	}

	// Save back
	if g != nil {
		data, _ := json.Marshal(g)
		fsm.Put(tx, []byte("groups"), []byte(groupID), data)
	}
	if u != nil {
		data, _ := json.Marshal(u)
		fsm.Put(tx, []byte("users"), []byte(userID), data)
	}
	return nil
}

func (fsm *MetadataFSM) enqueueGC(tx *bolt.Tx, inode *Inode) {
	fsm.LoadInodeWithPages(tx, inode)
	for _, chunk := range inode.ChunkManifest {
		nodesData, _ := json.Marshal(chunk.Nodes)
		fsm.Put(tx, []byte("garbage_collection"), []byte(chunk.ID), nodesData)
	}
}

func (fsm *MetadataFSM) IsInitialized() bool {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return len(fsm.trusted) > 0
}

func (fsm *MetadataFSM) IsTrusted(pubKey []byte) bool {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.trusted[hex.EncodeToString(pubKey)]
}

// GetActiveKey returns the current active cluster encryption key.
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
	return &key, err
}

func (fsm *MetadataFSM) executeAcquireLeases(tx *bolt.Tx, data []byte, sessionNonce string) interface{} {
	var req LeaseRequest
	json.Unmarshal(data, &req)

	// If sessionNonce is provided via LogCommand, it takes precedence over req.SessionID
	if sessionNonce != "" {
		req.SessionID = sessionNonce
	}

	now := time.Now().UnixNano()
	expiry := now + req.Duration
	inodes := make([]*Inode, len(req.InodeIDs))
	for i, id := range req.InodeIDs {
		isPath := strings.HasPrefix(id, "path:")
		if !isPath && IsInodeID(id) {
			plain, err := fsm.Get(tx, []byte("inodes"), []byte(id))
			if err != nil {
				return err
			}
			if plain != nil {
				var inode Inode
				json.Unmarshal(plain, &inode)
				inodes[i] = &inode
				for _, l := range inode.Leases {
					if l.Expiry > now && l.SessionID != req.SessionID {
						if req.Type == LeaseExclusive || l.Type == LeaseExclusive {
							return fmt.Errorf("%w: inode %s: held by session %s", ErrConflict, id, l.SessionID)
						}
					}
				}
			}
		} else {
			plain, err := fsm.Get(tx, []byte("filename_leases"), []byte(id))
			if err != nil {
				return err
			}
			if plain != nil {
				var leases map[string]LeaseInfo
				json.Unmarshal(plain, &leases)
				for _, l := range leases {
					if l.Expiry > now && l.SessionID != req.SessionID {
						if req.Type == LeaseExclusive || l.Type == LeaseExclusive {
							return fmt.Errorf("%w: path %s: held by session %s", ErrConflict, id, l.SessionID)
						}
					}
				}
			}
		}
	}
	for i, id := range req.InodeIDs {
		isPath := strings.HasPrefix(id, "path:")
		info := LeaseInfo{InodeID: id, SessionID: req.SessionID, Nonce: req.Nonce, Expiry: expiry, Type: req.Type}
		nonce := req.Nonce
		if nonce == "" {
			nonce = req.SessionID
		}
		if !isPath && IsInodeID(id) {
			inode := inodes[i]
			if inode == nil {
				// Find provided placeholder
				for _, p := range req.Placeholders {
					if p.ID == id {
						// Verify placeholder signature
						if err := fsm.verifyInodeSignature(tx, &p, req.UserID); err != nil {
							return fmt.Errorf("invalid placeholder signature for %s: %w", id, err)
						}
						// Ensure it's marked as a valid placeholder (Version 1, no chunks, etc)
						if p.Version != 1 || len(p.ChunkManifest) > 0 || p.Size > 0 {
							return fmt.Errorf("provided inode %s is not a valid placeholder", id)
						}
						inode = &p
						break
					}
				}
				if inode == nil {
					return fmt.Errorf("no signed placeholder provided for new inode %s", id)
				}
			}
			if inode.Leases == nil {
				inode.Leases = make(map[string]LeaseInfo)
			}
			inode.Leases[nonce] = info
			fsm.saveInodeWithPages(tx, inode)
			encoded, _ := json.Marshal(info)
			log.Printf("DEBUG FSM [%s]: Indexing lease %s:%s", fsm.nodeID, id, nonce)
			fsm.Put(tx, []byte("leases"), []byte(id+":"+nonce), encoded)
		} else {
			plain, err := fsm.Get(tx, []byte("filename_leases"), []byte(id))
			if err != nil {
				return err
			}
			leases := make(map[string]LeaseInfo)
			if plain != nil {
				json.Unmarshal(plain, &leases)
			}
			leases[nonce] = info
			encoded, _ := json.Marshal(leases)
			log.Printf("DEBUG FSM [%s]: Indexing path lease %s:%s", fsm.nodeID, id, nonce)
			fsm.Put(tx, []byte("filename_leases"), []byte(id), encoded)
		}
	}
	return nil
}

func (fsm *MetadataFSM) executeReleaseLeases(tx *bolt.Tx, data []byte, sessionNonce string) interface{} {
	var req LeaseRequest
	json.Unmarshal(data, &req)

	if sessionNonce != "" {
		req.SessionID = sessionNonce
	}

	now := time.Now().UnixNano()
	for _, id := range req.InodeIDs {
		nonce := req.Nonce
		if nonce == "" {
			nonce = req.SessionID
		}
		isPath := strings.HasPrefix(id, "path:")
		if isPath || !IsInodeID(id) {
			plain, err := fsm.Get(tx, []byte("filename_leases"), []byte(id))
			if err == nil && plain != nil {
				var leases map[string]LeaseInfo
				json.Unmarshal(plain, &leases)
				if nonce == "" {
					for n, l := range leases {
						if l.SessionID == req.SessionID {
							nonce = n
							break
						}
					}
				}
				if nonce != "" {
					delete(leases, nonce)
					log.Printf("DEBUG FSM [%s]: Removing path lease index %s:%s", fsm.nodeID, id, nonce)
					if len(leases) == 0 {
						fsm.Delete(tx, []byte("filename_leases"), []byte(id))
					} else {
						encoded, _ := json.Marshal(leases)
						fsm.Put(tx, []byte("filename_leases"), []byte(id), encoded)
					}
				}
			}
			if isPath {
				continue
			}
		}
		plain, err := fsm.Get(tx, []byte("inodes"), []byte(id))
		if err == nil && plain != nil {
			var inode Inode
			if err := json.Unmarshal(plain, &inode); err == nil {
				if nonce == "" {
					for n, l := range inode.Leases {
						if l.SessionID == req.SessionID {
							nonce = n
							break
						}
					}
				}
				if _, ok := inode.Leases[nonce]; ok {
					delete(inode.Leases, nonce)
					log.Printf("DEBUG FSM [%s]: Removing lease index %s:%s", fsm.nodeID, id, nonce)
					fsm.Delete(tx, []byte("leases"), []byte(id+":"+nonce))
					if inode.Unlinked {
						active := false
						for _, l := range inode.Leases {
							if l.Expiry > now {
								active = true
								break
							}
						}
						if !active {
							fsm.finalizeDeleteInode(tx, &inode)
							continue
						}
					}
					fsm.saveInodeWithPages(tx, &inode)
				}
			}
		}
	}
	return nil
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
		json.Unmarshal(plain, &key)
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
		json.Unmarshal(plain, &key)
		priv = key.EncryptedPrivate
		return nil
	})
	return priv, err
}

func (fsm *MetadataFSM) GetClusterSecret() ([]byte, error) {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.clusterSecret, nil
}

func (fsm *MetadataFSM) IsUserInGroup(userID, groupID string) (bool, error) {
	var found bool
	err := fsm.db.View(func(tx *bolt.Tx) error {
		plain, err := fsm.Get(tx, []byte("groups"), []byte(groupID))
		if err != nil {
			return err
		}
		if plain == nil {
			return ErrNotFound
		}
		var g Group
		json.Unmarshal(plain, &g)
		if g.Members[userID] || g.OwnerID == userID {
			found = true
			return nil
		}

		// Recursive check: if the owner is a group, are we in THAT group?
		visited := make(map[string]bool)
		currID := g.OwnerID
		for currID != "" && !visited[currID] {
			visited[currID] = true
			pPlain, _ := fsm.Get(tx, []byte("groups"), []byte(currID))
			if pPlain == nil {
				// Not a group ID, must be a user ID (direct check already done or it doesn't match)
				if currID == userID {
					found = true
				}
				return nil
			}
			var p Group
			json.Unmarshal(pPlain, &p)
			if p.Members[userID] || p.OwnerID == userID {
				found = true
				return nil
			}
			currID = p.OwnerID
		}
		return nil
	})
	return found, err
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
	return &group, err
}

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
	return &blob, err
}

func (fsm *MetadataFSM) GetUserGroups(userID string) ([]GroupListEntry, error) {
	var entries []GroupListEntry
	err := fsm.db.View(func(tx *bolt.Tx) error {
		mb := tx.Bucket([]byte("user_memberships"))
		ob := tx.Bucket([]byte("owner_groups"))
		groupsFound := make(map[string]GroupRole)

		// Helper to set role with priority: Owner > Manager > Member
		setRole := func(gid string, role GroupRole) {
			existing, ok := groupsFound[gid]
			if !ok {
				groupsFound[gid] = role
				return
			}
			if role == RoleOwner {
				groupsFound[gid] = RoleOwner
			} else if role == RoleManager && existing == RoleMember {
				groupsFound[gid] = RoleManager
			}
		}

		// 1. Direct memberships
		if sub := mb.Bucket([]byte(userID)); sub != nil {
			sub.ForEach(func(k, v []byte) error {
				setRole(string(k), RoleMember)
				return nil
			})
		}

		// 2. Direct ownerships
		if sub := ob.Bucket([]byte(userID)); sub != nil {
			sub.ForEach(func(k, v []byte) error {
				setRole(string(k), RoleOwner)
				return nil
			})
		}

		// 3. Recursive Manager discovery
		queue := make([]string, 0, len(groupsFound))
		for gid := range groupsFound {
			queue = append(queue, gid)
		}
		visited := make(map[string]bool)
		for len(queue) > 0 {
			parentID := queue[0]
			queue = queue[1:]
			if visited[parentID] {
				continue
			}
			visited[parentID] = true

			if sub := ob.Bucket([]byte(parentID)); sub != nil {
				sub.ForEach(func(k, v []byte) error {
					childID := string(k)
					setRole(childID, RoleManager)
					queue = append(queue, childID)
					return nil
				})
			}
		}

		for gid, role := range groupsFound {
			plain, err := fsm.Get(tx, []byte("groups"), []byte(gid))
			if err == nil && plain != nil {
				var g Group
				json.Unmarshal(plain, &g)
				entries = append(entries, GroupListEntry{
					ID: g.ID, OwnerID: g.OwnerID, Role: role, EncKey: g.EncKey,
					Lockbox: g.Lockbox, IsSystem: g.IsSystem, Usage: g.Usage, Quota: g.Quota,
					ClientBlob: g.ClientBlob,
				})
			}
		}
		return nil
	})
	return entries, err
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
	return &snap, err
}

func (fsm *MetadataFSM) GetGroups(cursor string, limit int) ([]Group, string, error) {
	var groups []Group
	var nextCursor string
	err := fsm.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("groups"))
		c := b.Cursor()
		var k, v []byte
		if cursor == "" {
			k, v = c.First()
		} else {
			k, v = c.Seek([]byte(cursor))
			if k != nil && string(k) == cursor {
				k, v = c.Next()
			}
		}
		for count := 0; k != nil && (limit <= 0 || count < limit); k, v = c.Next() {
			plain, err := fsm.DecryptValue([]byte("groups"), v)
			if err == nil {
				var g Group
				if err := json.Unmarshal(plain, &g); err == nil {
					groups = append(groups, g)
				}
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

func (fsm *MetadataFSM) GetLeases() ([]LeaseInfo, error) {
	var leases []LeaseInfo
	now := time.Now().UnixNano()
	err := fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte("leases"), func(k, v []byte) error {
			log.Printf("DEBUG FSM: GetLeases found key %s", string(k))
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
	return &world, err
}

func (fsm *MetadataFSM) ValidateNode(address string) error {
	err := fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
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
	if err != nil {
		return err
	}
	return fmt.Errorf("node address %s not found", address)
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
	return &node, err
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
	return &node, err
}

func (fsm *MetadataFSM) FSMKey() []byte {
	fsm.mu.RLock()
	kr := fsm.keyRing
	fsm.mu.RUnlock()
	k, _ := kr.Current()
	return k
}

func (fsm *MetadataFSM) KeyRing() *crypto.KeyRing {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.keyRing
}

const ChunkPageSize = 1000

func (fsm *MetadataFSM) GetNodes() ([]Node, error) {
	var nodes []Node
	err := fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte("nodes"), func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				nodes = append(nodes, n)
			}
			return nil
		})
	})
	return nodes, err
}

func (fsm *MetadataFSM) InspectBucket(bucketName string, fn func(k, v []byte) error) error {
	return fsm.db.View(func(tx *bolt.Tx) error {
		return fsm.ForEach(tx, []byte(bucketName), fn)
	})
}

// Snapshot returns a point-in-time snapshot of the FSM.
func (fsm *MetadataFSM) Snapshot() (raft.FSMSnapshot, error) {
	if fsm.OnSnapshot != nil {
		fsm.OnSnapshot()
	}
	return &MetadataSnapshot{db: fsm.db, keyRing: fsm.keyRing}, nil
}

// Restore restores the FSM state from a snapshot reader.
func (fsm *MetadataFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	lBuf := make([]byte, 4)
	if _, err := io.ReadFull(rc, lBuf); err != nil {
		return err
	}
	l := binary.BigEndian.Uint32(lBuf)
	krData := make([]byte, l)
	if _, err := io.ReadFull(rc, krData); err != nil {
		return err
	}
	kr, _ := crypto.UnmarshalKeyRing(krData)
	fsm.mu.Lock()
	fsm.keyRing = kr
	fsm.mu.Unlock()
	fsm.db.Close()
	tmpPath := fsm.path + ".restore"
	f, _ := os.Create(tmpPath)
	io.Copy(f, rc)
	f.Close()
	os.Rename(tmpPath, fsm.path)
	return fsm.reopen()
}

func (fsm *MetadataFSM) reopen() error {
	db, err := bolt.Open(fsm.path, 0600, nil)
	if err != nil {
		return err
	}
	fsm.mu.Lock()
	fsm.db = db
	fsm.mu.Unlock()
	return nil
}

func (fsm *MetadataFSM) DumpInodes(tx *bolt.Tx) {
	log.Printf("--- FSM STATE DUMP [%s] ---", fsm.nodeID)

	// 1. Dump Inodes
	ib := tx.Bucket([]byte("inodes"))
	if ib != nil {
		log.Printf("  INODES:")
		ib.ForEach(func(k, v []byte) error {
			var inode Inode
			plain, err := fsm.DecryptValue([]byte("inodes"), v)
			if err == nil {
				if err := json.Unmarshal(plain, &inode); err == nil {
					log.Printf("    Inode %s (%s): Owner=%s Group=%s Version=%d Children=%d Links=%d NLink=%d Unlinked=%v Size=%d",
						inode.ID, inode.GetName(), inode.OwnerID, inode.GroupID, inode.Version, len(inode.Children), len(inode.Links), inode.NLink, inode.Unlinked, inode.Size)
				}
			}
			return nil
		})
	}

	// 2. Dump Users
	ub := tx.Bucket([]byte("users"))
	if ub != nil {
		log.Printf("  USERS:")
		ub.ForEach(func(k, v []byte) error {
			var u User
			plain, err := fsm.DecryptValue([]byte("users"), v)
			if err == nil {
				if err := json.Unmarshal(plain, &u); err == nil {
					log.Printf("    User %s: UID=%d Usage={Inodes:%d, Bytes:%d} Quota={MaxInodes:%d, MaxBytes:%d}",
						u.ID, u.UID, u.Usage.InodeCount, u.Usage.TotalBytes, u.Quota.MaxInodes, u.Quota.MaxBytes)
				}
			}
			return nil
		})
	}

	// 3. Dump Groups
	gb := tx.Bucket([]byte("groups"))
	if gb != nil {
		log.Printf("  GROUPS:")
		gb.ForEach(func(k, v []byte) error {
			var g Group
			plain, err := fsm.DecryptValue([]byte("groups"), v)
			if err == nil {
				if err := json.Unmarshal(plain, &g); err == nil {
					log.Printf("    Group %s: GID=%d Owner=%s Usage={Inodes:%d, Bytes:%d} Quota={MaxInodes:%d, MaxBytes:%d}",
						g.ID, g.GID, g.OwnerID, g.Usage.InodeCount, g.Usage.TotalBytes, g.Quota.MaxInodes, g.Quota.MaxBytes)
				}
			}
			return nil
		})
	}

	log.Printf("--- END DUMP [%s] ---", fsm.nodeID)
}

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

func int64ToBytes(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}
