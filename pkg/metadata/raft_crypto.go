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
	"encoding/binary"
	"fmt"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

// EncryptedLogStore wraps a LogStore with encryption.
type EncryptedLogStore struct {
	store   *raftboltdb.BoltStore
	keyRing *crypto.KeyRing
}

// NewEncryptedLogStore creates a new encrypted log store.
func NewEncryptedLogStore(store *raftboltdb.BoltStore, keyRing *crypto.KeyRing) *EncryptedLogStore {
	return &EncryptedLogStore{store: store, keyRing: keyRing}
}

func (e *EncryptedLogStore) FirstIndex() (uint64, error) { return e.store.FirstIndex() }
func (e *EncryptedLogStore) LastIndex() (uint64, error)  { return e.store.LastIndex() }

func (e *EncryptedLogStore) GetLog(index uint64, log *raft.Log) error {
	var encLog raft.Log
	if err := e.store.GetLog(index, &encLog); err != nil {
		return err
	}
	// Decrypt Data
	if len(encLog.Data) > 4 {
		gen := binary.BigEndian.Uint32(encLog.Data[:4])
		key, ok := e.keyRing.Get(gen)
		if !ok {
			return fmt.Errorf("key generation %d not found for log %d", gen, index)
		}
		plain, err := crypto.DecryptDEM(key, encLog.Data[4:])
		if err != nil {
			return fmt.Errorf("failed to decrypt log %d (gen %d): %w", index, gen, err)
		}
		encLog.Data = plain
	}
	*log = encLog
	return nil
}

func (e *EncryptedLogStore) StoreLog(log *raft.Log) error {
	return e.StoreLogs([]*raft.Log{log})
}

func (e *EncryptedLogStore) StoreLogs(logs []*raft.Log) error {
	encLogs := make([]*raft.Log, len(logs))
	key, gen := e.keyRing.Current()

	for i, l := range logs {
		cp := *l // shallow copy
		if len(cp.Data) > 0 {
			ct, err := crypto.EncryptDEM(key, cp.Data)
			if err != nil {
				return err
			}
			// Prefix with generation ID
			data := make([]byte, 4+len(ct))
			binary.BigEndian.PutUint32(data[:4], gen)
			copy(data[4:], ct)
			cp.Data = data
		}
		encLogs[i] = &cp
	}
	return e.store.StoreLogs(encLogs)
}

func (e *EncryptedLogStore) DeleteRange(min, max uint64) error {
	return e.store.DeleteRange(min, max)
}
