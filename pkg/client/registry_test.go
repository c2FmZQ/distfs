//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"testing"
)

func TestResolveGroupName(t *testing.T) {
	c, node, _, ts, adminID, _ := setupTestClient(t)
	defer ts.Close()
	defer node.Shutdown()

	ctx := t.Context()

	// 1. Create a group
	groupName := "test-group"
	group, err := c.createGroup(ctx, groupName, false)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// 2. Anchoring happened automatically during CreateGroup
	// (Check if CreateGroup actually anchors)
	// Wait, does CreateGroup anchor?
	// I'll check createGroupInternal in client.go.

	// 3. Resolve by name
	resolvedID, entry, err := c.ResolveGroupName(ctx, groupName)
	if err != nil {
		t.Fatalf("ResolveGroupName failed: %v", err)
	}

	if resolvedID != group.ID {
		t.Errorf("Expected ID %s, got %s", group.ID, resolvedID)
	}
	if entry.GroupName != groupName {
		t.Errorf("Expected name %s, got %s", groupName, entry.GroupName)
	}
	if entry.VerifierID != adminID {
		t.Errorf("Expected verifier %s, got %s", adminID, entry.VerifierID)
	}

	// 4. Test missing group
	_, _, err = c.ResolveGroupName(ctx, "non-existent")
	if err == nil {
		t.Errorf("Expected error for non-existent group")
	}
}
