// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	distfuse "github.com/c2FmZQ/distfs/pkg/fuse"
)

type Config struct {
	MetaURL   string `json:"meta_url"`
	DataURL   string `json:"data_url"`
	UserID    string `json:"user_id"`
	EncKey    string `json:"enc_key"`
	SignKey   string `json:"sign_key"`
	ServerKey string `json:"server_key"`
}

func main() {
	mountpoint := flag.String("mount", "", "Mount point")
	flag.Parse()

	if *mountpoint == "" {
		log.Fatal("-mount is required")
	}

	conf := loadConfig()
	c := loadClient(conf)

	conn, err := fuse.Mount(
		*mountpoint,
		fuse.FSName("distfs"),
		fuse.Subtype("distfs"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Handle interrupts to unmount
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Unmounting...")
		fuse.Unmount(*mountpoint)
		os.Exit(0)
	}()

	filesys := distfuse.NewFS(c)

	if err := fs.Serve(conn, filesys); err != nil {
		log.Fatal(err)
	}
}

func loadClient(conf Config) *client.Client {
	c := client.NewClient(conf.MetaURL, conf.DataURL)
	
	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)
	
	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)
	
	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)
	svKey, _ := crypto.UnmarshalEncapsulationKey(svKeyBytes)

	return c.WithIdentity(conf.UserID, dk).WithSignKey(sk).WithServerKey(svKey)
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
