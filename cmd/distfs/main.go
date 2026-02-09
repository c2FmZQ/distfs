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
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
)

type Config struct {
	MetaURL   string `json:"meta_url"`
	DataURL   string `json:"data_url"`
	UserID    string `json:"user_id"`
	EncKey    string `json:"enc_key"`    // Hex private KEM
	SignKey   string `json:"sign_key"`   // Hex private sign
	ServerKey string `json:"server_key"` // Hex public KEM
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "init":
		cmdInit(args)
	case "register":
		cmdRegister(args)
	case "ls":
		cmdLs(args)
	case "mkdir":
		cmdMkdir(args)
	case "put":
		cmdPut(args)
	case "get":
		cmdGet(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Println("Usage: distfs <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  init -meta <url> -id <user_id>  Initialize client config")
	fmt.Println("  register -jwt <jwt>             Register user with server")
	fmt.Println("  ls <path>                       List directory")
	fmt.Println("  mkdir <path>                    Create directory")
	fmt.Println("  put <local> <remote>            Upload file")
	fmt.Println("  get <remote> <local>            Download file")
	os.Exit(1)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	metaURL := fs.String("meta", "http://localhost:8080", "Metadata Server URL")
	userID := fs.String("id", "", "User ID (e.g. email)")
	fs.Parse(args)

	if *userID == "" {
		log.Fatal("-id is required")
	}

	// Fetch Server Key
	resp, err := http.Get(*metaURL + "/v1/meta/key")
	if err != nil {
		log.Fatalf("failed to fetch server key: %v", err)
	}
	defer resp.Body.Close()
	sKey, _ := io.ReadAll(resp.Body)

	// Generate local keys
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()

	conf := Config{
		MetaURL:   *metaURL,
		DataURL:   *metaURL, // Assume unified by default
		UserID:    *userID,
		EncKey:    hex.EncodeToString(crypto.MarshalDecapsulationKey(dk)),
		SignKey:   hex.EncodeToString(sk.MarshalPrivate()),
		ServerKey: hex.EncodeToString(sKey),
	}

	saveConfig(conf)
	fmt.Printf("Config initialized for %s. Server key: %s\n", *userID, hex.EncodeToString(sKey[:8]))
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	jwt := fs.String("jwt", "", "OIDC JWT for registration")
	fs.Parse(args)

	if *jwt == "" {
		log.Fatal("-jwt is required")
	}

	conf := loadConfig()
	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	req := map[string]interface{}{
		"jwt":      *jwt,
		"sign_key": sk.Public(),
		"enc_key":  dk.EncapsulationKey().Bytes(),
		"name":     conf.UserID,
	}
	body, _ := json.Marshal(req)

	resp, err := http.Post(conf.MetaURL+"/v1/user/register", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("registration failed: %d %s", resp.StatusCode, string(b))
	}

	fmt.Println("User registered successfully.")
}

func loadClient() *client.Client {
	conf := loadConfig()
	c := client.NewClient(conf.MetaURL, conf.DataURL)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)
	svKey, _ := crypto.UnmarshalEncapsulationKey(svKeyBytes)

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

func cmdPut(args []string) {
	if len(args) < 2 {
		log.Fatal("local and remote paths required")
	}
	local, remote := args[0], args[1]
	data, err := os.ReadFile(local)
	if err != nil {
		log.Fatal(err)
	}
	c := loadClient()
	if err := c.CreateFile(remote, data); err != nil {
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
	data, err := c.ReadFile(inode.ID, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(local, data, 0644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("File %s downloaded to %s.\n", remote, local)
}

func saveConfig(c Config) {
	dir := filepath.Join(os.Getenv("HOME"), ".distfs")
	os.MkdirAll(dir, 0700)
	b, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(filepath.Join(dir, "config.json"), b, 0600)
}

func loadConfig() Config {
	dir := filepath.Join(os.Getenv("HOME"), ".distfs")
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config not found, run 'distfs init': %v", err)
	}
	var c Config
	json.Unmarshal(b, &c)
	return c
}
