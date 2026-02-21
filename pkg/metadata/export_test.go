// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"crypto/mlkem"
	"encoding/json"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

func BootstrapCluster(t *testing.T, raftNode *RaftNode) (*mlkem.EncapsulationKey768, []byte) {
	WaitLeader(t, raftNode.Raft)
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	key := ClusterKey{
		ID:        "key-1",
		EncKey:    ek.Bytes(),
		DecKey:    dk.Bytes(),
		CreatedAt: time.Now().Unix(),
	}
	keyBytes, _ := json.Marshal(key)
	cmd := LogCommand{Type: CmdRotateKey, Data: keyBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := raftNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap cluster key apply failed: %v", err)
	}

	// Bootstrap cluster sign key
	csk, _ := crypto.GenerateIdentityKey()
	cskData := ClusterSignKey{
		Public:           csk.Public(),
		EncryptedPrivate: csk.MarshalPrivate(),
	}
	cskBytes, _ := json.Marshal(cskData)
	future = raftNode.Raft.Apply(LogCommand{Type: CmdSetClusterSignKey, Data: cskBytes}.Marshal(), 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap sign key apply failed: %v", err)
	}

	return dk.EncapsulationKey(), csk.Public()
}
