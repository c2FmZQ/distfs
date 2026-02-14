// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/auth"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	distfuse "github.com/c2FmZQ/distfs/pkg/fuse"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func main() {
	mountpoint := flag.String("mount", "", "Mount point")
	configPath := flag.String("config", config.DefaultPath(), "Path to config file")
	usePinentry := flag.Bool("use-pinentry", true, "Use pinentry for passphrase input")

	// Registration flags
	doRegister := flag.Bool("register", false, "Register user with server")
	jwt := flag.String("jwt", "", "OIDC JWT for registration")
	clientID := flag.String("client-id", "", "The client ID")
	scopes := flag.String("scopes", "", "The scopes to request (comma separated)")
	authEndpoint := flag.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint := flag.String("token-endpoint", "", "The token endpoint")
	qrCode := flag.Bool("qr", false, "Show a QR code of the verification URL")
	browser := flag.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")

	flag.Parse()
	config.UsePinentry = *usePinentry

	if *doRegister {
		performRegistration(*configPath, *jwt, *clientID, *scopes, *authEndpoint, *tokenEndpoint, *qrCode, *browser)
		// Small delay for Raft propagation
		time.Sleep(2 * time.Second)
		if *mountpoint == "" {
			return
		}
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
	c := client.NewClient(conf.MetaURL, conf.DataURL)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)
	svKey, _ := crypto.UnmarshalEncapsulationKey(svKeyBytes)

	return c.WithIdentity(conf.UserID, dk).WithSignKey(sk).WithServerKey(svKey)
}

func performRegistration(configPath, jwt, clientID, scopes, authEndpoint, tokenEndpoint string, qrCode bool, browser string) {
	if jwt == "" {
		if clientID == "" || authEndpoint == "" || tokenEndpoint == "" {
			log.Fatal("-jwt or (-client-id, -auth-endpoint, -token-endpoint) is required for registration")
		}

		var scopeList []string
		if scopes != "" {
			for _, s := range strings.Split(scopes, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					scopeList = append(scopeList, s)
				}
			}
		}

		ctx := context.Background()
		token, err := auth.GetToken(ctx, auth.Config{
			ClientID:      clientID,
			AuthEndpoint:  authEndpoint,
			TokenEndpoint: tokenEndpoint,
			Scopes:        scopeList,
			ShowQR:        qrCode,
			Browser:       browser,
		})
		if err != nil {
			log.Fatalf("device auth failed: %v", err)
		}
		jwt = token.AccessToken
	}

	conf, err := config.Load(configPath)
	if err != nil {
		log.Fatal(err)
	}

	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	req := map[string]interface{}{
		"jwt":      jwt,
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

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("registration failed: %d %s", resp.StatusCode, string(b))
	}

	var user metadata.User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Fatalf("failed to decode user response: %v", err)
	}

	conf.UserID = user.ID
	if err := config.Save(*conf, configPath); err != nil {
		log.Fatalf("failed to save config: %v", err)
	}

	if resp.StatusCode == http.StatusOK {
		log.Println("User already registered. ID:", user.ID)
	} else {
		log.Println("User registered successfully. ID:", user.ID)
	}
}
