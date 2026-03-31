//go:build !wasm

package client

import (
	"context"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestDebugLockedKeysync(t *testing.T) {
	tc := metadata.SetupCluster(t)
	defer tc.Node.Shutdown()
	defer tc.TS.Close()
	metadata.WaitLeader(t, tc.Node.Raft)

	// Admin
	u1 := "admin"
	usk, _ := crypto.GenerateIdentityKey()
	metadata.CreateUser(t, tc.Node, metadata.User{ID: u1, UID: 1001, SignKey: usk.Public(), Locked: false}, usk, tc.AdminID, tc.AdminSK)

	// Locked user
	u2 := "locked"
	usk2, _ := crypto.GenerateIdentityKey()
	udk2, _ := crypto.GenerateEncryptionKey()
	// CreateUser forces locked=true for second user.
	metadata.CreateUser(t, tc.Node, metadata.User{ID: u2, UID: 1002, SignKey: usk2.Public(), EncKey: udk2.EncapsulationKey().Bytes(), Locked: true}, usk2, tc.AdminID, tc.AdminSK)

	c := NewClient(tc.TS.URL).withIdentity(u2, udk2).withSignKey(usk2)

	svKey, _ := crypto.UnmarshalEncapsulationKey(tc.EpochEK)
	c = c.withServerKey(svKey)

	_, _ = c.EnsureRoot(context.Background())

	err := c.pushKeySync(context.Background(), &metadata.KeySyncBlob{Ciphertext: []byte("test")})
	if err != nil {
		t.Fatalf("PushKeySync failed: %v", err)
	}
}
