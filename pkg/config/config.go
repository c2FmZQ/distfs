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

package config

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// Config represents the client-side configuration.
type Config struct {
	ServerURL   string `json:"server_url"`
	UserID      string `json:"user_id"`
	EncKey      string `json:"enc_key"`
	SignKey     string `json:"sign_key"`
	ServerKey   string `json:"server_key"`
	RootID      string `json:"root_id,omitempty"`
	RootOwner   string `json:"root_owner,omitempty"`
	RootVersion uint64 `json:"root_version,omitempty"`
}

// Encrypt wraps a config into an encrypted blob.
func Encrypt(c Config, password []byte) (*metadata.KeySyncBlob, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := deriveKey(password, salt)

	plaintext, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.EncryptDEM(key, plaintext)
	if err != nil {
		return nil, err
	}

	return &metadata.KeySyncBlob{
		KDF:        "argon2id",
		Salt:       salt,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt unwraps an encrypted blob into a config.
func Decrypt(blob metadata.KeySyncBlob, password []byte) (*Config, error) {
	if blob.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported KDF: %s", blob.KDF)
	}

	key := deriveKey(password, blob.Salt)
	plaintext, err := crypto.DecryptDEM(key, blob.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	var c Config
	if err := json.Unmarshal(plaintext, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// DefaultDir returns the default directory for DistFS configuration.
func DefaultDir() string {
	return filepath.Join(os.Getenv("HOME"), ".distfs")
}

// DefaultPath returns the default path for the configuration file.
func DefaultPath() string {
	return filepath.Join(DefaultDir(), "config.json")
}

// Save encrypts and saves the configuration to the specified path.
func Save(c Config, path string) error {
	password, err := GetPassword("Enter passphrase to encrypt config: ", true)
	if err != nil {
		return err
	}
	return SaveWithPassword(c, path, password)
}

// SaveWithPassword saves the configuration using the provided password.
func SaveWithPassword(c Config, path string, password []byte) error {
	blob, err := Encrypt(c, password)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return os.WriteFile(path, b, 0600)
}

// Load decrypts and loads the configuration from the specified path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try to unmarshal as KeySyncBlob
	var blob metadata.KeySyncBlob
	if err := json.Unmarshal(b, &blob); err == nil && blob.KDF == "argon2id" {
		// It is encrypted
		password, err := GetPassword("Enter passphrase to decrypt config: ", false)
		if err != nil {
			return nil, err
		}

		return Decrypt(blob, password)
	}

	return nil, fmt.Errorf("invalid config format: encryption mandatory")
}

// TPMHasher is an optional callback to cryptographically bind the passphrase to a local TPM.
var TPMHasher func(password []byte) ([]byte, error)

func deriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GetPassword prompts the user for a passphrase.
func GetPassword(prompt string, confirm bool) ([]byte, error) {
	var pass []byte
	var err error

	if envPass := os.Getenv("DISTFS_PASSWORD"); envPass != "" {
		pass = []byte(envPass)
	} else if UsePinentry {
		pass, err = getPasswordPinentry(prompt, confirm)
	} else {
		fmt.Fprint(os.Stderr, prompt)
		pass, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err == nil && confirm {
			fmt.Fprint(os.Stderr, "Confirm passphrase: ")
			byteConfirm, errConf := term.ReadPassword(int(syscall.Stdin))
			fmt.Fprintln(os.Stderr)
			if errConf != nil {
				err = errConf
			} else if !bytes.Equal(pass, byteConfirm) {
				err = fmt.Errorf("passwords do not match")
			}
		}
	}

	if err != nil {
		return nil, err
	}

	if TPMHasher != nil {
		return TPMHasher(pass)
	}
	return pass, nil
}
