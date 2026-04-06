// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"context"
	"encoding/hex"
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
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/tpm"
	"github.com/urfave/cli/v3"
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
	cmd := &cli.Command{
		Name:  "distfs-fuse",
		Usage: "DistFS FUSE Mount Client",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "mount", Usage: "Mount point", Required: true},
			&cli.StringFlag{Name: "config", Value: config.DefaultPath(), Usage: "Path to config file"},
			&cli.BoolFlag{Name: "use-pinentry", Value: true, Usage: "Use pinentry for passphrase input"},
			&cli.BoolFlag{Name: "use-tpm", Value: false, Usage: "Use TPM to securely bind the master passphrase to this hardware"},
			&cli.BoolFlag{Name: "disable-doh", Value: false, Usage: "Disable DNS-over-HTTPS and use system resolver"},
			&cli.StringFlag{Name: "server", Value: "http://localhost:8080", Usage: "Metadata Server URL (only used if config is missing)"},
			&cli.BoolFlag{Name: "new", Value: false, Usage: "Initialize a new account if config is missing"},
			&cli.StringFlag{Name: "jwt", Value: "", Usage: "OIDC JWT for registration"},
			&cli.StringFlag{Name: "client-id", Value: "distfs", Usage: "The client ID"},
			&cli.StringFlag{Name: "scopes", Value: "openid", Usage: "The scopes to request (comma separated)"},
			&cli.StringFlag{Name: "auth-endpoint", Value: "", Usage: "The authorization endpoint"},
			&cli.StringFlag{Name: "token-endpoint", Value: "", Usage: "The token endpoint"},
			&cli.BoolFlag{Name: "qr", Value: false, Usage: "Show a QR code of the verification URL"},
			&cli.StringFlag{Name: "browser", Value: os.Getenv("BROWSER"), Usage: "The command to use to open the verification URL"},
			&cli.StringFlag{Name: "root-id", Value: "", Usage: "Root inode ID to mount (chroot)"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			mountpoint := cmd.String("mount")
			configPath := cmd.String("config")
			usePinentry := cmd.Bool("use-pinentry")
			useTPM := cmd.Bool("use-tpm")
			disableDoH := cmd.Bool("disable-doh")
			serverURL := cmd.String("server")
			isNew := cmd.Bool("new")
			jwt := cmd.String("jwt")
			clientID := cmd.String("client-id")
			scopes := cmd.String("scopes")
			authEndpoint := cmd.String("auth-endpoint")
			tokenEndpoint := cmd.String("token-endpoint")
			qrCode := cmd.Bool("qr")
			browser := cmd.String("browser")
			rootID := cmd.String("root-id")

			startPprofServer()

			config.UsePinentry = usePinentry

			if useTPM {
				setupTPMHasher(configPath)
			}

			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				fmt.Println("Configuration missing. Starting unified onboarding...")
				opts := client.OnboardingOptions{
					ConfigPath:    configPath,
					ServerURL:     serverURL,
					IsNew:         isNew,
					JWT:           jwt,
					ClientID:      clientID,
					Scopes:        strings.Split(scopes, ","),
					AuthEndpoint:  authEndpoint,
					TokenEndpoint: tokenEndpoint,
					ShowQR:        qrCode,
					Browser:       browser,
					DisableDoH:    disableDoH,
				}
				if err := client.PerformUnifiedOnboarding(ctx, opts); err != nil {
					return err
				}
				// Small delay for Raft propagation
				time.Sleep(2 * time.Second)
			}

			conf, err := config.Load(configPath)
			if err != nil {
				return err
			}
			c := loadClient(conf, rootID, disableDoH)

			conn, err := fuse.Mount(
				mountpoint,
				fuse.FSName("distfs"),
				fuse.Subtype("distfs"),
				fuse.DefaultPermissions(),
			)
			if err != nil {
				return err
			}
			defer conn.Close()

			// Handle interrupts to unmount
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				log.Println("Unmounting...")
				fuse.Unmount(mountpoint)
				os.Exit(0)
			}()

			filesys := client.NewFS(c)

			if err := fs.Serve(conn, filesys); err != nil {
				return err
			}
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func loadClient(conf *config.Config, rootID string, disableDoH bool) *client.Client {
	c := client.NewClient(conf.ServerURL).
		WithDisableDoH(disableDoH)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	skBytes, _ := hex.DecodeString(conf.SignKey)
	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)

	rid := conf.DefaultRootID
	if rid == "" {
		rid = metadata.RootID
	}
	if rootID != "" {
		rid = rootID
	}

	var rowner string
	var rpk, rek []byte
	var rver uint64

	if anchor, ok := conf.Roots[rid]; ok {
		rowner = anchor.RootOwner
		rpk = anchor.RootOwnerPublicKey
		rek = anchor.RootOwnerEncryptionKey
		rver = anchor.RootVersion
	}

	var err error
	c, err = c.WithIdentityBytes(conf.UserID, dkBytes)
	if err != nil {
		log.Fatalf("failed to set identity: %v", err)
	}
	c, err = c.WithSignKeyBytes(skBytes)
	if err != nil {
		log.Fatalf("failed to set sign key: %v", err)
	}
	c, err = c.WithServerKeyBytes(svKeyBytes)
	if err != nil {
		log.Fatalf("failed to set server key: %v", err)
	}
	c = c.WithRootAnchorBytes(rid, rowner, rpk, rek, rver)

	return c
}
