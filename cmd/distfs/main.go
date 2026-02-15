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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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
	case "register":
		fmt.Println("Warning: 'register' is deprecated. Use 'init --new' instead.")
		cmdRegister(args)
	case "keysync":
		fmt.Println("Warning: 'keysync' is deprecated. Use 'init' instead.")
		if len(args) < 1 {
			log.Fatal("keysync requires a subcommand (push or pull)")
		}
		switch args[0] {
		case "push":
			cmdKeySyncPush(args[1:])
		case "pull":
			cmdKeySyncPull(args[1:])
		default:
			log.Fatalf("unknown keysync subcommand: %s", args[0])
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Println("Usage: distfs [-config <path>] [-use-pinentry] <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  init [--new] -meta <url>        Initialize client config (pulls existing keys by default)")
	fmt.Println("  ls <path>                       List directory")
	fmt.Println("  mkdir <path>                    Create directory")
	fmt.Println("  rm <path>                       Delete file or directory")
	fmt.Println("  chmod <mode> <path>             Change permissions")
	fmt.Println("  chgrp <group_id> <path>         Change group")
	fmt.Println("  group-create <name>             Create a new group")
	fmt.Println("  group-add <group_id> <user_id>  Add user to group")
	fmt.Println("  put <local> <remote>            Upload file")
	fmt.Println("  get <remote> <local>            Download file")
	os.Exit(1)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	metaURL := fs.String("meta", "http://localhost:8080", "Metadata Server URL")
	isNew := fs.Bool("new", false, "Initialize a new account")

	// Auth flags
	jwt := fs.String("jwt", "", "OIDC JWT for authentication")
	clientID := fs.String("client-id", "", "The client ID")
	scopes := fs.String("scopes", "openid,email", "The scopes to request (comma separated)")
	authEndpoint := fs.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint := fs.String("token-endpoint", "", "The token endpoint")
	qrCode := fs.Bool("qr", false, "Show a QR code of the verification URL")
	browser := fs.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")

	fs.Parse(args)

	opts := client.OnboardingOptions{
		ConfigPath:    *configPath,
		MetaURL:       *metaURL,
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

func cmdKeySyncPush(args []string) {
	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	password, err := config.GetPassword("Enter passphrase to encrypt keys for sync: ", true)
	if err != nil {
		log.Fatal(err)
	}

	blob, err := config.Encrypt(*conf, password)
	if err != nil {
		log.Fatal(err)
	}

	c := loadClient()
	if err := c.PushKeySync(blob); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Keys pushed to server successfully.")
}

func cmdKeySyncPull(args []string) {
	fs := flag.NewFlagSet("keysync pull", flag.ExitOnError)
	metaURL := fs.String("meta", "http://localhost:8080", "Metadata Server URL")
	jwt := fs.String("jwt", "", "OIDC JWT for authentication")
	clientID := fs.String("client-id", "", "The client ID")
	scopes := fs.String("scopes", "openid,email", "The scopes to request (comma separated)")
	authEndpoint := fs.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint := fs.String("token-endpoint", "", "The token endpoint")
	qrCode := fs.Bool("qr", false, "Show a QR code of the verification URL")
	browser := fs.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")
	fs.Parse(args)

	opts := client.OnboardingOptions{
		MetaURL:       *metaURL,
		JWT:           *jwt,
		ClientID:      *clientID,
		Scopes:        strings.Split(*scopes, ","),
		AuthEndpoint:  *authEndpoint,
		TokenEndpoint: *tokenEndpoint,
		ShowQR:        *qrCode,
		Browser:       *browser,
	}

	token, err := client.GetOIDCToken(context.Background(), opts)
	if err != nil {
		log.Fatal(err)
	}

	c := client.NewClient(*metaURL, "") // dataURL not needed for pull
	blob, err := c.PullKeySync(token)
	if err != nil {
		log.Fatal(err)
	}

	password, err := config.GetPassword("Enter passphrase to decrypt sync blob: ", false)
	if err != nil {
		log.Fatal(err)
	}

	conf, err := config.Decrypt(*blob, password)
	if err != nil {
		log.Fatal(err)
	}

	if err := config.SaveWithPassword(*conf, *configPath, password); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Keys pulled and configuration restored successfully.")
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	jwt := fs.String("jwt", "", "OIDC JWT for registration")
	clientID := fs.String("client-id", "", "The client ID")
	scopes := fs.String("scopes", "openid,email", "The scopes to request (comma separated)")
	authEndpoint := fs.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint := fs.String("token-endpoint", "", "The token endpoint")
	qrCode := fs.Bool("qr", false, "Show a QR code of the verification URL")
	browser := fs.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")
	fs.Parse(args)

	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	opts := client.OnboardingOptions{
		JWT:           *jwt,
		ClientID:      *clientID,
		Scopes:        strings.Split(*scopes, ","),
		AuthEndpoint:  *authEndpoint,
		TokenEndpoint: *tokenEndpoint,
		ShowQR:        *qrCode,
		Browser:       *browser,
	}

	token, err := client.GetOIDCToken(context.Background(), opts)
	if err != nil {
		log.Fatal(err)
	}

	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	req := map[string]interface{}{
		"jwt":      token,
		"sign_key": sk.Public(),
		"enc_key":  dk.EncapsulationKey().Bytes(),
	}
	body, _ := json.Marshal(req)

	resp, err := http.Post(conf.MetaURL+"/v1/user/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("registration failed: %d %s", resp.StatusCode, string(b))
	}

	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Fatalf("failed to decode response: %v", err)
	}

	conf.UserID = user.ID
	if err := config.Save(*conf, *configPath); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("User registered successfully. ID: %s\n", user.ID)
}

func loadClient() *client.Client {
	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	c := client.NewClient(conf.MetaURL, conf.DataURL)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)
	svKey, err := crypto.UnmarshalEncapsulationKey(svKeyBytes)
	if err != nil {
		log.Fatalf("failed to unmarshal server key: %v", err)
	}

	return c.WithIdentity(conf.UserID, dk).WithSignKey(sk).WithServerKey(svKey)
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
