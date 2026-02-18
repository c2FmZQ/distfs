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

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

var (
	configPath  = flag.String("config", config.DefaultPath(), "Path to config file")
	usePinentry = flag.Bool("use-pinentry", true, "Use pinentry for passphrase input")
	adminFlag   = flag.Bool("admin", false, "Enable admin bypass mode")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
	}

	config.UsePinentry = *usePinentry

	command := flag.Arg(0)
	args := flag.Args()[1:]

	switch command {
	case "init":
		cmdInit(args)
	case "ls":
		cmdLs(args)
	case "mkdir":
		cmdMkdir(args)
	case "put":
		cmdPut(args)
	case "get":
		cmdGet(args)
	case "rm":
		cmdRm(args)
	case "chmod":
		cmdChmod(args)
	case "chgrp":
		cmdChgrp(args)
	case "group-create":
		cmdGroupCreate(args)
	case "group-add":
		cmdGroupAdd(args)
	case "admin":
		cmdAdmin(args)
	case "admin-join":
		cmdAdminJoin(args)
	case "admin-chown":
		cmdAdminChown(args)
	case "admin-chmod":
		cmdAdminChmod(args)
	case "admin-promote":
		cmdAdminPromote(args)
	case "whoami":
		cmdWhoami(args)
	case "dump-inodes":
		cmdDumpInodes(args)
	default:
		usage()
	}
}

func cmdWhoami(args []string) {
	c := loadClient()
	fmt.Println(c.UserID())
}

func usage() {
	fmt.Println("Usage: distfs [-config <path>] [-use-pinentry] [-admin] <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  init [--new] -server <url>      Initialize client config (pulls existing keys by default)")
	fmt.Println("  ls <path>                       List directory")
	fmt.Println("  mkdir <path>                    Create directory")
	fmt.Println("  rm <path>                       Delete file or directory")
	fmt.Println("  chmod <mode> <path>             Change permissions")
	fmt.Println("  chgrp <group_id> <path>         Change group")
	fmt.Println("  group-create <name>             Create a new group")
	fmt.Println("  group-add <group_id> <user_id>  Add user to group")
	fmt.Println("  put <local> <remote>            Upload file")
	fmt.Println("  get <remote> <local>            Download file")
	fmt.Println("  admin                           Open interactive cluster management console")
	fmt.Println("  admin-join <addr>               Add a node to the cluster (discovered via address)")
	fmt.Println("  admin-chown <email>[:<group>] <path> Override ownership (Admin only)")
	fmt.Println("  admin-chmod <mode> <path>       Override permissions (Admin only)")
	fmt.Println("  dump-inodes [path|id]           Recursively dump inode metadata for debugging")
	os.Exit(1)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	serverURL := fs.String("server", "http://localhost:8080", "Metadata Server URL")
	isNew := fs.Bool("new", false, "Initialize a new account")

	// Auth flags
	jwt := fs.String("jwt", "", "OIDC JWT for authentication")
	clientID := fs.String("client-id", "distfs", "The client ID")
	scopes := fs.String("scopes", "openid,email", "The scopes to request (comma separated)")
	authEndpoint := fs.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint := fs.String("token-endpoint", "", "The token endpoint")
	qrCode := fs.Bool("qr", false, "Show a QR code of the verification URL")
	browser := fs.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")

	fs.Parse(args)

	opts := client.OnboardingOptions{
		ConfigPath:    *configPath,
		ServerURL:     *serverURL,
		IsNew:         *isNew,
		JWT:           *jwt,
		ClientID:      *clientID,
		Scopes:        strings.Split(*scopes, ","),
		AuthEndpoint:  *authEndpoint,
		TokenEndpoint: *tokenEndpoint,
		ShowQR:        *qrCode,
		Browser:       *browser,
	}

	if err := client.PerformUnifiedOnboarding(context.Background(), opts); err != nil {
		log.Fatal(err)
	}
}

func loadClient() *client.Client {
	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	c := client.NewClient(conf.ServerURL)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)
	svKey, err := crypto.UnmarshalEncapsulationKey(svKeyBytes)
	if err != nil {
		log.Fatalf("failed to unmarshal server key: %v", err)
	}

	return c.WithIdentity(conf.UserID, dk).
		WithSignKey(sk).
		WithServerKey(svKey).
		WithRootAnchor(conf.RootID, conf.RootOwner, conf.RootVersion).
		WithAdmin(*adminFlag)
}

func saveClient(c *client.Client) {
	conf, err := config.Load(*configPath)
	if err != nil {
		// If we can't load it, we can't save it (need the password for encryption)
		return
	}

	rid, rowner, rver := c.GetRootAnchor()
	if rid == conf.RootID && rowner == conf.RootOwner && rver == conf.RootVersion {
		return // No change
	}

	conf.RootID = rid
	conf.RootOwner = rowner
	conf.RootVersion = rver

	// We need the password. config.Save will prompt for it.
	// This might be annoying for every 'ls' if the version changes often.
	// For now, let's only save if explicitly requested or on 'init'.
	// Actually, let's just NOT save automatically in the CLI for now to avoid UX friction.
	// In distfs-fuse it makes more sense.
}

func cmdLs(args []string) {
	path := "/"
	if len(args) > 0 {
		path = args[0]
	}
	c := loadClient()
	dfs := c.FS()
	entries, err := dfs.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		info, _ := e.Info()
		fmt.Printf("%s\t%d\t%v\n", e.Name(), info.Size(), e.IsDir())
	}
}

func cmdMkdir(args []string) {
	if len(args) < 1 {
		log.Fatal("path required")
	}
	path := args[0]
	c := loadClient()
	if err := c.Mkdir(path); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Directory %s created.\n", path)
}

func cmdRm(args []string) {
	if len(args) < 1 {
		log.Fatal("path required")
	}
	path := args[0]
	c := loadClient()
	if err := c.Remove(path); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Removed %s\n", path)
}

func cmdChmod(args []string) {
	if len(args) < 2 {
		log.Fatal("mode and path required")
	}
	modeStr, path := args[0], args[1]
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		log.Fatalf("invalid mode: %v", err)
	}

	c := loadClient()
	m32 := uint32(mode)
	if err := c.SetAttr(path, metadata.SetAttrRequest{Mode: &m32}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Mode of %s changed to %s\n", path, modeStr)
}

func cmdChgrp(args []string) {
	if len(args) < 2 {
		log.Fatal("group_id and path required")
	}
	groupID, path := args[0], args[1]

	c := loadClient()
	if err := c.SetAttr(path, metadata.SetAttrRequest{GroupID: &groupID}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Group of %s changed to %s\n", path, groupID)
}

func cmdGroupCreate(args []string) {
	if len(args) < 1 {
		log.Fatal("group name required")
	}
	name := args[0]
	c := loadClient()
	group, err := c.CreateGroup(name)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Group %s created. ID: %s\n", name, group.ID)
}

func cmdGroupAdd(args []string) {
	if len(args) < 2 {
		log.Fatal("group_id and user_id required")
	}
	groupID, userID := args[0], args[1]
	c := loadClient()
	if err := c.AddUserToGroup(groupID, userID); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User %s added to group %s\n", userID, groupID)
}

func cmdPut(args []string) {
	if len(args) < 2 {
		log.Fatal("local and remote paths required")
	}
	local, remote := args[0], args[1]
	f, err := os.Open(local)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}

	c := loadClient()
	if err := c.CreateFile(remote, f, info.Size()); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("File %s uploaded to %s.\n", local, remote)
}

func cmdGet(args []string) {
	if len(args) < 2 {
		log.Fatal("remote and local paths required")
	}
	remote, local := args[0], args[1]
	c := loadClient()
	inode, key, err := c.ResolvePath(remote)
	if err != nil {
		log.Fatal(err)
	}

	rc, err := c.ReadFile(inode.ID, key)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()

	f, err := os.Create(local)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err := io.Copy(f, rc); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("File %s downloaded to %s.\n", remote, local)
}
