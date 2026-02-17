// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	distfuse "github.com/c2FmZQ/distfs/pkg/fuse"
)

func main() {
	mountpoint := flag.String("mount", "", "Mount point")
	configPath := flag.String("config", config.DefaultPath(), "Path to config file")
	usePinentry := flag.Bool("use-pinentry", true, "Use pinentry for passphrase input")

	serverURL := flag.String("server", "http://localhost:8080", "Metadata Server URL (only used if config is missing)")
	isNew := flag.Bool("new", false, "Initialize a new account if config is missing")

	// Auth flags
	jwt := flag.String("jwt", "", "OIDC JWT for registration")
	clientID := flag.String("client-id", "distfs", "The client ID")
	scopes := flag.String("scopes", "openid,email", "The scopes to request (comma separated)")
	authEndpoint := flag.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint := flag.String("token-endpoint", "", "The token endpoint")
	qrCode := flag.Bool("qr", false, "Show a QR code of the verification URL")
	browser := flag.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")

	flag.Parse()
	config.UsePinentry = *usePinentry

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		fmt.Println("Configuration missing. Starting unified onboarding...")
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
		// Small delay for Raft propagation
		time.Sleep(2 * time.Second)
	}

	if *mountpoint == "" {
		log.Fatal("-mount is required")
	}

	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
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

func loadClient(conf *config.Config) *client.Client {
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
		WithRootAnchor(conf.RootID, conf.RootOwner, conf.RootVersion)
}
