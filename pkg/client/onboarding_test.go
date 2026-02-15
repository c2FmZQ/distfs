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
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestPerformUnifiedOnboarding_NewAccount(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	os.Setenv("DISTFS_PASSWORD", "testpass")
	defer os.Unsetenv("DISTFS_PASSWORD")

	// 1. Mock Metadata Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/config":
			json.NewEncoder(w).Encode(metadata.OIDCConfig{
				DeviceAuthorizationEndpoint: "http://auth/device",
				TokenEndpoint:               "http://auth/token",
			})
		case "/v1/meta/key":
			dk, _ := crypto.GenerateEncryptionKey()
			w.Write(dk.EncapsulationKey().Bytes())
		case "/v1/user/register":
			json.NewEncoder(w).Encode(map[string]string{"id": "user-123"})
		case "/v1/user/keysync":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	opts := OnboardingOptions{
		ConfigPath: configPath,
		ServerURL:  ts.URL,
		IsNew:      true,
		JWT:        "mock-jwt",
	}

	err := PerformUnifiedOnboarding(context.Background(), opts)
	if err != nil {
		t.Fatalf("Onboarding failed: %v", err)
	}

	// Verify config exists
	conf, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load created config: %v", err)
	}
	if conf.UserID != "user-123" {
		t.Errorf("expected UserID user-123, got %s", conf.UserID)
	}
}

func TestPerformUnifiedOnboarding_Restore(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	os.Setenv("DISTFS_PASSWORD", "testpass")
	defer os.Unsetenv("DISTFS_PASSWORD")

	// 1. Prepare valid sync blob
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()

	initialConf := config.Config{
		ServerURL: "http://old-url",
		UserID:    "user-restored",
		EncKey:    hex.EncodeToString(crypto.MarshalDecapsulationKey(dk)),
		SignKey:   hex.EncodeToString(sk.MarshalPrivate()),
		ServerKey: hex.EncodeToString(make([]byte, 32)),
	}
	blob, _ := config.Encrypt(initialConf, []byte("testpass"))

	// 2. Mock Metadata Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/config":
			json.NewEncoder(w).Encode(metadata.OIDCConfig{
				TokenEndpoint: "http://auth/token",
			})
		case "/v1/meta/key":
			dk, _ := crypto.GenerateEncryptionKey()
			w.Write(dk.EncapsulationKey().Bytes())
		case "/v1/user/keysync":
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(blob)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	opts := OnboardingOptions{
		ConfigPath: configPath,
		ServerURL:  ts.URL,
		IsNew:      false,
		JWT:        "mock-jwt",
	}

	err := PerformUnifiedOnboarding(context.Background(), opts)
	if err != nil {
		t.Fatalf("Restore onboarding failed: %v", err)
	}

	// Verify config was restored and URL was UPDATED to the current server
	conf, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load restored config: %v", err)
	}
	if conf.UserID != "user-restored" {
		t.Errorf("expected UserID user-restored, got %s", conf.UserID)
	}
	if conf.ServerURL != ts.URL {
		t.Errorf("expected ServerURL %s, got %s", ts.URL, conf.ServerURL)
	}
}
