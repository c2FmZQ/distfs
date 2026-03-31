// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/c2FmZQ/distfs/pkg/client"
)

func cmdDump(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("usage: distfs dump <path or rootID>")
	}
	target := args[0]

	c := loadClient()

	// Try to resolve as path first
	rootID := target
	if fi, err := c.Stat(ctx, target); err == nil {
		rootID = fi.Sys().(*client.InodeInfo).ID
	}

	visited := make(map[string]bool)
	queue := []string{rootID}

	fmt.Println("--- INODE DUMP START ---")

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]

		if visited[id] {
			continue
		}
		visited[id] = true

		inode, err := c.AdminGetInodeDump(ctx, id)
		if err != nil {
			fmt.Printf("ERROR fetching inode %s: %v\n", id, err)
			continue
		}

		dumpInode(inode)

		// Enqueue children if directory
		for _, childID := range inode.Children {
			queue = append(queue, childID)
		}
	}

	fmt.Println("--- INODE DUMP END ---")
}

func dumpInode(i *client.InodeDump) {
	fmt.Printf("Inode ID: %s\n", i.ID)
	fmt.Printf("  Type: %v\n", i.Type)
	fmt.Printf("  Mode: %04o\n", i.Mode)
	fmt.Printf("  Size: %d\n", i.Size)
	fmt.Printf("  Owner: %s\n", i.OwnerID)
	fmt.Printf("  Group: %s\n", i.GroupID)
	fmt.Printf("  Version: %d\n", i.Version)
	fmt.Printf("  SignerID: %s\n", i.SignerID)

	if i.SymlinkTarget != "" {
		fmt.Printf("  SymlinkTarget: %s\n", i.SymlinkTarget)
	}

	// Print raw signature bytes (truncated)
	if i.HasUserSig {
		fmt.Printf("  UserSig: %s... (len=%d)\n", i.UserSigPref, i.UserSigLen)
	} else {
		fmt.Printf("  UserSig: <empty>\n")
	}

	fmt.Printf("  Links: %v\n", i.Links)
	if i.NumChunks > 0 {
		fmt.Printf("  Chunks: %d\n", i.NumChunks)
	}
	if i.NumPages > 0 {
		fmt.Printf("  ChunkPages: %d\n", i.NumPages)
	}
	if i.InlineSize > 0 {
		fmt.Printf("  InlineData: %d bytes\n", i.InlineSize)
	}
	fmt.Println("")
}
