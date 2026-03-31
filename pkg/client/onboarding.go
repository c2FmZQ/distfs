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
	DisableDoH    bool
	AllowInsecure bool
}

// RegisterUser registers a new user with the server.
func (c *Client) RegisterUser(ctx context.Context, jwt string, signKeyPub, encKeyPub, signature []byte) (string, error) {
	payload := metadata.RegisterUserRequest{
		JWT:       jwt,
		SignKey:   signKeyPub,
		EncKey:    encKeyPub,
		Signature: signature,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", c.serverAddr+"/v1/user/register", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpCli.Do(req)
	if err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("registration failed: %d %s", resp.StatusCode, string(b))
	}

	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	return user.ID, nil
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
		httpClient := NewClient(opts.ServerURL).
			WithDisableDoH(opts.DisableDoH).
			WithAllowInsecure(opts.AllowInsecure).httpClient()
		req, err := http.NewRequestWithContext(ctx, "GET", opts.ServerURL+"/v1/auth/config", nil)
		if err != nil {
			return "", fmt.Errorf("failed to create auth config request: %w", err)
		}
		resp, err := httpClient.Do(req)
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

	httpClient := NewClient(opts.ServerURL).
		WithDisableDoH(opts.DisableDoH).
		WithAllowInsecure(opts.AllowInsecure).httpClient()

	// Fetch Server Key
	req, err := http.NewRequestWithContext(ctx, "GET", opts.ServerURL+"/v1/meta/key", nil)
	if err != nil {
		return fmt.Errorf("failed to create server key request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch server key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to fetch server key: status %d: %s", resp.StatusCode, string(b))
	}
	sKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read server key: %w", err)
	}
	svKey, err := crypto.UnmarshalEncapsulationKey(sKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal server key: %w", err)
	}

	if opts.IsNew {
		// New account flow
		dk, _ := crypto.GenerateEncryptionKey()
		sk, _ := crypto.GenerateIdentityKey()

		// Sign the registration (SignKey || EncKey)
		userForHash := metadata.User{
			SignKey: sk.Public(),
			EncKey:  dk.EncapsulationKey().Bytes(),
		}
		sig := sk.Sign(userForHash.Hash())

		payload := metadata.RegisterUserRequest{
			JWT:       token,
			SignKey:   sk.Public(),
			EncKey:    dk.EncapsulationKey().Bytes(),
			Signature: sig,
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, "POST", opts.ServerURL+"/v1/user/register", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create registration request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
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

		c := NewClient(opts.ServerURL).WithDisableDoH(opts.DisableDoH)
		c = c.withIdentity(conf.UserID, dk).withSignKey(sk).withServerKey(svKey)

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

		if err := c.pushKeySync(ctx, blob); err != nil {
			fmt.Printf("Warning: cloud backup failed: %v\n", err)
		} else {
			fmt.Println("Cloud backup (KeySync) successful.")
		}

		fmt.Printf("New account initialized successfully. User ID: %s\n", user.ID)
	} else {
		// Existing account flow (Pull)
		c := NewClient(opts.ServerURL).WithDisableDoH(opts.DisableDoH)
		blob, err := c.pullKeySync(ctx, token)
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
