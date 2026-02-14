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

package auth

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/oauth2"
)

// Config holds the parameters for the OAuth2 device flow.
type Config struct {
	ClientID      string
	AuthEndpoint  string
	TokenEndpoint string
	Scopes        []string
	ShowQR        bool
	Browser       string
}

// GetToken executes the OAuth2 device authorization flow.
func GetToken(ctx context.Context, conf Config) (*oauth2.Token, error) {
	c := &oauth2.Config{
		ClientID: conf.ClientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: conf.AuthEndpoint,
			TokenURL:      conf.TokenEndpoint,
		},
		Scopes: conf.Scopes,
	}

	resp, err := c.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("device auth failed: %w", err)
	}

	url := resp.VerificationURIComplete
	if url == "" {
		url = resp.VerificationURI
	}

	if conf.ShowQR {
		qrterminal.GenerateHalfBlock(url, qrterminal.L, os.Stdout)
	}

	fmt.Printf("Open this URL and enter %s as User Code to authorize access:\n\n  %s\n\n", resp.UserCode, url)

	if conf.Browser != "" {
		cmd := exec.Command(conf.Browser, url)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to open browser: %v\n", err)
		}
	}

	token, err := c.DeviceAccessToken(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("device access token failed: %w", err)
	}

	return token, nil
}
