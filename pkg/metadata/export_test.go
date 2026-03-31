//go:build !wasm

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
	cmdBytes, err := cmd.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal bootstrap key: %v", err)
	}
	future := raftNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap cluster key apply failed: %v", err)
	}

	signKey, _ := crypto.GenerateIdentityKey()
	cskData := ClusterSignKey{
		Public:           signKey.Public(),
		EncryptedPrivate: signKey.MarshalPrivate(),
	}
	cskBytes, _ := json.Marshal(cskData)
	cskCmdBytes, err := LogCommand{Type: CmdSetClusterSignKey, Data: cskBytes}.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal bootstrap sign key: %v", err)
	}
	future = raftNode.Raft.Apply(cskCmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap sign key apply failed: %v", err)
	}

	// 3. Bootstrap World Identity
	wdk, _ := crypto.GenerateEncryptionKey()
	world := WorldIdentity{
		Public:  wdk.EncapsulationKey().Bytes(),
		Private: crypto.MarshalDecapsulationKey(wdk),
	}
	wb, _ := json.Marshal(world)
	wbBytes, err := LogCommand{Type: CmdInitWorld, Data: wb}.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal bootstrap world init: %v", err)
	}
	if err := raftNode.Raft.Apply(wbBytes, 5*time.Second).Error(); err != nil {
		t.Fatalf("Bootstrap world init failed: %v", err)
	}

	return dk.EncapsulationKey(), signKey.Public()
}
