//go:build !wasm

package client

import (
	"context"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"testing"
)

func TestClient_WithRootID_Anchoring(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts, adminID, adminSK := setupTestClient(t)
	_ = adminID
	_ = adminSK
	defer ts.Close()

	if _, err := c.EnsureRoot(ctx); err != nil && err != metadata.ErrExists {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// Create a fresh root ID for chroot testing
	nonce := metadata.GenerateNonce()
	chrootID := metadata.GenerateInodeID(c.UserID(), nonce)

	// Create chrooted client
	c2 := c.WithRootID(chrootID)

	// Phase 69: Provision backbone in chroot so it can verify groups
	if err := c2.BootstrapFileSystem(ctx); err != nil {
		t.Fatalf("BootstrapFileSystem in chroot failed: %v", err)
	}

	// Try to use it.
	_, _, err := c2.resolvePath(ctx, "/")
	if err != nil {
		t.Fatalf("ResolvePath / in chroot failed: %v", err)
	}

	err = c2.Mkdir(ctx, "/subdir", 0755)
	if err != nil {
		t.Fatalf("Mkdir in chroot failed: %v", err)
	}
}
