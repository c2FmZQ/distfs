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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	distfuse "github.com/c2FmZQ/distfs/pkg/fuse"
	"github.com/c2FmZQ/tpm"
)

func setupTPMHasher(configPath string) {
	config.TPMHasher = func(password []byte) ([]byte, error) {
		tpmDev, err := tpm.New()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TPM: %w", err)
		}
		defer tpmDev.Close()

		baseDir := filepath.Dir(configPath)
		hmacKeyPath := filepath.Join(baseDir, "tpm_hmac.key")
		var hmacKey *tpm.Key

		if b, err := os.ReadFile(hmacKeyPath); err == nil {
			hmacKey, err = tpmDev.UnmarshalKey(b)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal TPM HMAC key: %w", err)
			}
		} else {
			hmacKey, err = tpmDev.CreateKey(tpm.WithHMAC(256))
			if err != nil {
				return nil, fmt.Errorf("failed to create TPM HMAC key: %w", err)
			}
			marshaled, err := hmacKey.Marshal()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal TPM HMAC key: %w", err)
			}
			if err := os.WriteFile(hmacKeyPath, marshaled, 0600); err != nil {
				return nil, fmt.Errorf("failed to save TPM HMAC key: %w", err)
			}
		}

		boundHash, err := hmacKey.HMAC(password)
		if err != nil {
			return nil, fmt.Errorf("failed to compute TPM HMAC: %w", err)
		}
		return []byte(hex.EncodeToString(boundHash)), nil
	}
}

func main() {
	mountpoint := flag.String("mount", "", "Mount point")
	configPath := flag.String("config", config.DefaultPath(), "Path to config file")
	usePinentry := flag.Bool("use-pinentry", true, "Use pinentry for passphrase input")
	useTPM := flag.Bool("use-tpm", false, "Use TPM to securely bind the master passphrase to this hardware")
	disableDoH := flag.Bool("disable-doh", false, "Disable DNS-over-HTTPS and use system resolver")

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
	rootID := flag.String("root-id", "", "Root inode ID to mount (chroot)")
	flag.Parse()

	config.UsePinentry = *usePinentry

	if *useTPM {
		setupTPMHasher(*configPath)
	}

	ctx := context.Background()
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
			DisableDoH:    *disableDoH,
		}
		if err := client.PerformUnifiedOnboarding(ctx, opts); err != nil {
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
	c := loadClient(conf, *rootID, *disableDoH)

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

func loadClient(conf *config.Config, rootID string, disableDoH bool) *client.Client {
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

	c = c.WithIdentity(conf.UserID, dk).
		WithSignKey(sk).
		WithServerKey(svKey).
		WithRootAnchor(conf.RootID, conf.RootOwner, conf.RootVersion).
		WithDisableDoH(disableDoH)

	if rootID != "" {
		c = c.WithRootID(rootID)
	}
	return c
}
