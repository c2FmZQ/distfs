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
	signKey, _ := crypto.GenerateIdentityKey()
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
		case "/v1/meta/key/sign":
			w.Write(signKey.Public())
		case "/v1/meta/key/world":
			dk, _ := crypto.GenerateEncryptionKey()
			w.Write(dk.EncapsulationKey().Bytes())
		case "/v1/user/register":
			json.NewEncoder(w).Encode(map[string]string{"id": "user-123"})
		case "/v1/user/keysync":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			}
		case "/v1/auth/challenge":
			chal := make([]byte, 32)
			sig := signKey.Sign(chal)
			resp := metadata.AuthChallengeResponse{
				Challenge: chal,
				Signature: sig,
			}
			json.NewEncoder(w).Encode(resp)
		case "/v1/login":
			json.NewEncoder(w).Encode(metadata.SessionResponse{Token: "mock-session"})
		case "/v1/meta/inode/" + metadata.RootID:
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
			}
		case "/v1/meta/batch":
			if r.Method == http.MethodPost {
				// We expect a create root command
				res := []interface{}{
					metadata.Inode{ID: metadata.RootID, OwnerID: "user-123", Version: 1, NLink: 1},
				}
				json.NewEncoder(w).Encode(res)
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

	err := PerformUnifiedOnboarding(t.Context(), opts)
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
	signKey, _ := crypto.GenerateIdentityKey()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/config":
			json.NewEncoder(w).Encode(metadata.OIDCConfig{
				TokenEndpoint: "http://auth/token",
			})
		case "/v1/meta/key":
			dk, _ := crypto.GenerateEncryptionKey()
			w.Write(dk.EncapsulationKey().Bytes())
		case "/v1/meta/key/sign":
			w.Write(signKey.Public())
		case "/v1/meta/key/world":
			dk, _ := crypto.GenerateEncryptionKey()
			w.Write(dk.EncapsulationKey().Bytes())
		case "/v1/user/keysync":
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(blob)
			}
		case "/v1/auth/challenge":
			chal := make([]byte, 32)
			sig := signKey.Sign(chal)
			resp := metadata.AuthChallengeResponse{
				Challenge: chal,
				Signature: sig,
			}
			json.NewEncoder(w).Encode(resp)
		case "/v1/login":
			json.NewEncoder(w).Encode(metadata.SessionResponse{Token: "mock-session"})
		case "/v1/meta/inode/" + metadata.RootID:
			inode := metadata.Inode{
				ID:      metadata.RootID,
				OwnerID: "user-restored",
				Version: 1,
			}
			json.NewEncoder(w).Encode(inode)
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

	err := PerformUnifiedOnboarding(t.Context(), opts)
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
