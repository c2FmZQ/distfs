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
	"log"

	"github.com/c2FmZQ/storage"
)

const (
	clusterSecretName = "cluster.secret"
)

// NodeVault manages node-local secrets protected by the MasterKey.
type NodeVault struct {
	st *storage.Storage
}

// NewNodeVault creates a new vault using the provided storage engine.
func NewNodeVault(st *storage.Storage) *NodeVault {
	return &NodeVault{st: st}
}

// LoadClusterSecret retrieves the shared cluster secret from the local vault.
func (v *NodeVault) LoadClusterSecret() ([]byte, error) {
	var kd KeyData
	if err := v.st.ReadDataFile(clusterSecretName, &kd); err != nil {
		return nil, err
	}
	return kd.Bytes, nil
}

// SaveClusterSecret persists the shared cluster secret to the local vault.
func (v *NodeVault) SaveClusterSecret(secret []byte) error {
	kd := KeyData{Bytes: secret}
	err := v.st.SaveDataFile(clusterSecretName, kd)
	if err != nil {
		log.Printf("ERROR: SaveDataFile(%q): %v", clusterSecretName, err)
	}
	return err
}

// HasClusterSecret returns true if the secret is already present in the vault.
func (v *NodeVault) HasClusterSecret() bool {
	var kd KeyData
	err := v.st.ReadDataFile(clusterSecretName, &kd)
	return err == nil
}
