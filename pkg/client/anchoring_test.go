package client

import (
	"context"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"testing"
)

func TestClient_WithRootID_Anchoring(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	if _, err := c.EnsureRoot(ctx); err != nil && err != metadata.ErrExists {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	// Create a sub-root directory
	err := c.Mkdir(ctx, "/chroot", 0755)
	if err != nil {
		t.Fatal(err)
	}

	inode, _, err := c.ResolvePath(ctx, "/chroot")
	if err != nil {
		t.Fatal(err)
	}
	chrootID := inode.ID

	// Create chrooted client
	c2 := c.WithRootID(chrootID)

	// Try to use it.
	// If it incorrectly inherited rootOwner/rootVersion, resolving / might fail or have issues if it doesn't match chrootID.
	_, _, err = c2.ResolvePath(ctx, "/")
	if err != nil {
		t.Fatalf("ResolvePath / in chroot failed: %v", err)
	}

	err = c2.Mkdir(ctx, "/subdir", 0755)
	if err != nil {
		t.Fatalf("Mkdir in chroot failed: %v", err)
	}
}
