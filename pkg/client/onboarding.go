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

package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/c2FmZQ/distfs/pkg/auth"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// OnboardingOptions holds parameters for the unified onboarding flow.
type OnboardingOptions struct {
	ConfigPath    string
	ServerURL     string
	IsNew         bool
	JWT           string
	ClientID      string
	Scopes        []string
	AuthEndpoint  string
	TokenEndpoint string
	ShowQR        bool
	Browser       string
}

// GetOIDCToken retrieves an OIDC token using the device flow or returns the provided JWT.
// It prioritizes returning the ID Token if available.
func GetOIDCToken(ctx context.Context, opts OnboardingOptions) (string, error) {
	if opts.JWT != "" {
		return opts.JWT, nil
	}

	authEndpoint := opts.AuthEndpoint
	tokenEndpoint := opts.TokenEndpoint

	if authEndpoint == "" || tokenEndpoint == "" {
		// Discovery from server
		resp, err := http.Get(opts.ServerURL + "/v1/auth/config")
		if err != nil {
			return "", fmt.Errorf("failed to fetch auth config: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("auth config unavailable: %d", resp.StatusCode)
		}
		var conf metadata.OIDCConfig
		if err := json.NewDecoder(resp.Body).Decode(&conf); err != nil {
			return "", fmt.Errorf("failed to decode auth config: %w", err)
		}
		authEndpoint = conf.DeviceAuthorizationEndpoint
		tokenEndpoint = conf.TokenEndpoint
	}

	if opts.ClientID == "" || authEndpoint == "" || tokenEndpoint == "" {
		return "", fmt.Errorf("-jwt or (-client-id, -auth-endpoint, -token-endpoint) is required")
	}

	token, err := auth.GetToken(ctx, auth.Config{
		ClientID:      opts.ClientID,
		AuthEndpoint:  authEndpoint,
		TokenEndpoint: tokenEndpoint,
		Scopes:        opts.Scopes,
		ShowQR:        opts.ShowQR,
		Browser:       opts.Browser,
	})
	if err != nil {
		return "", err
	}

	if idToken, ok := token.Extra("id_token").(string); ok {
		return idToken, nil
	}
	return token.AccessToken, nil
}

// PerformUnifiedOnboarding executes the unified onboarding flow.
func PerformUnifiedOnboarding(ctx context.Context, opts OnboardingOptions) error {
	token, err := GetOIDCToken(ctx, opts)
	if err != nil {
		return err
	}

	// Fetch Server Key
	resp, err := http.Get(opts.ServerURL + "/v1/meta/key")
	if err != nil {
		return fmt.Errorf("failed to fetch server key: %w", err)
	}
	defer resp.Body.Close()
	sKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read server key: %w", err)
	}

	if opts.IsNew {
		// New account flow
		dk, _ := crypto.GenerateEncryptionKey()
		sk, _ := crypto.GenerateIdentityKey()

		req := map[string]interface{}{
			"jwt":      token,
			"sign_key": sk.Public(),
			"enc_key":  dk.EncapsulationKey().Bytes(),
		}
		body, _ := json.Marshal(req)

		resp, err := http.Post(opts.ServerURL+"/v1/user/register", "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("registration failed: %d %s", resp.StatusCode, string(b))
		}

		var user struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		conf := config.Config{
			ServerURL: opts.ServerURL,
			UserID:    user.ID,
			EncKey:    hex.EncodeToString(crypto.MarshalDecapsulationKey(dk)),
			SignKey:   hex.EncodeToString(sk.MarshalPrivate()),
			ServerKey: hex.EncodeToString(sKey),
		}

		c := NewClient(opts.ServerURL)
		svKey, err := crypto.UnmarshalEncapsulationKey(sKey)
		if err != nil {
			return fmt.Errorf("failed to unmarshal server key: %w", err)
		}
		c = c.WithIdentity(conf.UserID, dk).WithSignKey(sk).WithServerKey(svKey)

		// Ensure root exists and capture anchor
		if err := c.EnsureRoot(ctx); err != nil && err != metadata.ErrExists {
			return fmt.Errorf("failed to ensure root: %w", err)
		}
		rid, rowner, rver := c.GetRootAnchor()
		conf.RootID = rid
		conf.RootOwner = rowner
		conf.RootVersion = rver

		// Capture passphrase once
		password, err := config.GetPassword("Enter passphrase to protect your account: ", true)
		if err != nil {
			return err
		}

		// Save locally
		if err := config.SaveWithPassword(conf, opts.ConfigPath, password); err != nil {
			return err
		}

		// Cloud Backup
		blob, err := config.Encrypt(conf, password)
		if err != nil {
			return err
		}

		if err := c.PushKeySync(ctx, blob); err != nil {
			fmt.Printf("Warning: cloud backup failed: %v\n", err)
		} else {
			fmt.Println("Cloud backup (KeySync) successful.")
		}

		fmt.Printf("New account initialized successfully. User ID: %s\n", user.ID)
	} else {
		// Existing account flow (Pull)
		c := NewClient(opts.ServerURL)
		blob, err := c.PullKeySync(ctx, token)
		if err != nil {
			return fmt.Errorf("failed to pull keys: %w (did you mean --new?)", err)
		}

		password, err := config.GetPassword("Enter passphrase to decrypt sync blob: ", false)
		if err != nil {
			return err
		}

		conf, err := config.Decrypt(*blob, password)
		if err != nil {
			return err
		}

		// Update URLs and Server Key from current run
		conf.ServerURL = opts.ServerURL
		conf.ServerKey = hex.EncodeToString(sKey)

		if err := config.SaveWithPassword(*conf, opts.ConfigPath, password); err != nil {
			return err
		}
		fmt.Println("Configuration restored successfully from cloud backup.")
	}
	return nil
}
