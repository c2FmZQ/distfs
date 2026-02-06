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
	"fmt"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/hashicorp/raft"
	"github.com/hashicorp/raft-boltdb"
)

// EncryptedLogStore wraps a LogStore with encryption.
type EncryptedLogStore struct {
	store     *raftboltdb.BoltStore
	masterKey []byte
}

func NewEncryptedLogStore(store *raftboltdb.BoltStore, masterKey []byte) (*EncryptedLogStore, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes")
	}
	return &EncryptedLogStore{store: store, masterKey: masterKey}, nil
}

func (e *EncryptedLogStore) FirstIndex() (uint64, error) { return e.store.FirstIndex() }
func (e *EncryptedLogStore) LastIndex() (uint64, error) { return e.store.LastIndex() }

func (e *EncryptedLogStore) GetLog(index uint64, log *raft.Log) error {
	var encLog raft.Log
	if err := e.store.GetLog(index, &encLog); err != nil {
		return err
	}
	// Decrypt Data
	if len(encLog.Data) > 0 {
		plain, err := crypto.DecryptDEM(e.masterKey, encLog.Data)
		if err != nil {
			return fmt.Errorf("failed to decrypt log %d: %w", index, err)
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
	for i, l := range logs {
		cp := *l // shallow copy
		if len(cp.Data) > 0 {
			ct, err := crypto.EncryptDEM(e.masterKey, cp.Data)
			if err != nil {
				return err
			}
			cp.Data = ct
		}
		encLogs[i] = &cp
	}
	return e.store.StoreLogs(encLogs)
}

func (e *EncryptedLogStore) DeleteRange(min, max uint64) error {
	return e.store.DeleteRange(min, max)
}
