//go:build !wasm

package client

import (
	"context"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestDebugLockedKeysync(t *testing.T) {
	node, ts, _, ek, _ := metadata.SetupCluster(t)
	defer node.Shutdown()
	defer ts.Close()
	metadata.WaitLeader(t, node.Raft)

	// Admin
	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	metadata.CreateUser(t, node, metadata.User{ID: u1, UID: 1001, SignKey: usk.Public(), Locked: false})

	// Locked user
	u2 := "locked"
	usk2, _ := crypto.GenerateIdentityKey()
	udk2, _ := crypto.GenerateEncryptionKey()
	// CreateUser forces locked=true for second user.
	metadata.CreateUser(t, node, metadata.User{ID: u2, UID: 1002, SignKey: usk2.Public(), EncKey: udk2.EncapsulationKey().Bytes(), Locked: true})

	c := NewClient(ts.URL).WithIdentity(u2, udk2).WithSignKey(usk2)

	svKey, _ := crypto.UnmarshalEncapsulationKey(ek)
	c = c.WithServerKey(svKey)

	_, _ = c.EnsureRoot(context.Background())

	err := c.PushKeySync(context.Background(), &metadata.KeySyncBlob{Ciphertext: []byte("test")})
	if err != nil {
		t.Fatalf("PushKeySync failed: %v", err)
	}
}
