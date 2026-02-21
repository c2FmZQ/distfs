// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"context"
	"fmt"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func cmdDumpInodes(args []string) {
	c := loadClient()

	// Start from root
	rootID := metadata.RootID
	if len(args) > 0 {
		// Try to resolve path to ID if arg provided
		path := args[0]
		inode, _, err := c.ResolvePath(path)
		if err != nil {
			fmt.Printf("Error resolving path %s: %v. Assuming it's an ID.\n", path, err)
			rootID = path
		} else {
			rootID = inode.ID
		}
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

		inode, err := c.GetInode(context.Background(), id)
		if err != nil {
			fmt.Printf("ERROR fetching inode %s: %v\n", id, err)
			continue
		}

		dumpInode(inode)

		// Enqueue children if directory
		if inode.Type == metadata.DirType && inode.Children != nil {
			for name, childID := range inode.Children {
				fmt.Printf("  -> Child: %s (%s)\n", name, childID)
				queue = append(queue, childID)
			}
		}
	}
	fmt.Println("--- INODE DUMP END ---")
}

func dumpInode(i *metadata.Inode) {
	fmt.Printf("Inode ID: %s\n", i.ID)
	fmt.Printf("  Type: %v\n", i.Type)
	fmt.Printf("  Mode: %04o\n", i.Mode)
	fmt.Printf("  Size: %d\n", i.Size)
	fmt.Printf("  Owner: %s\n", i.OwnerID)
	fmt.Printf("  Group: %s\n", i.GroupID)
	fmt.Printf("  Version: %d\n", i.Version)
	fmt.Printf("  SignerID: %s\n", i.GetSignerID())
	fmt.Printf("  AuthorizedSigners: %v\n", i.GetAuthorizedSigners())

	if l := len(i.EncryptedSymlinkTarget); l > 0 {
		prefixLen := 8
		if l < prefixLen {
			prefixLen = l
		}
		fmt.Printf("  EncryptedSymlinkTarget: %x... (len=%d)\n", i.EncryptedSymlinkTarget[:prefixLen], l)
	}

	// Print raw signature bytes (truncated)
	if len(i.UserSig) > 0 {
		fmt.Printf("  UserSig: %x... (len=%d)\n", i.UserSig[:8], len(i.UserSig))
	} else {
		fmt.Printf("  UserSig: <empty>\n")
	}

	fmt.Printf("  Links: %v\n", i.Links)
	if len(i.ChunkManifest) > 0 {
		fmt.Printf("  Chunks: %d\n", len(i.ChunkManifest))
	}
	if len(i.ChunkPages) > 0 {
		fmt.Printf("  ChunkPages: %d\n", len(i.ChunkPages))
	}
	if len(i.InlineData) > 0 {
		fmt.Printf("  InlineData: %d bytes\n", len(i.InlineData))
	}
	fmt.Println("")
}
