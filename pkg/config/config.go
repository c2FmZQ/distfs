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
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

type Config struct {
	MetaURL   string `json:"meta_url"`
	DataURL   string `json:"data_url"`
	UserID    string `json:"user_id"`
	EncKey    string `json:"enc_key"`
	SignKey   string `json:"sign_key"`
	ServerKey string `json:"server_key"`
}

type EncryptedConfig struct {
	KDF        string `json:"kdf"` // "argon2id"
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}

func DefaultDir() string {
	return filepath.Join(os.Getenv("HOME"), ".distfs")
}

func DefaultPath() string {
	return filepath.Join(DefaultDir(), "config.json")
}

func Save(c Config, path string) error {
	password, err := getPassword("Enter passphrase to encrypt config: ", true)
	if err != nil {
		return err
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key := deriveKey(password, salt)

	plaintext, err := json.Marshal(c)
	if err != nil {
		return err
	}

	ciphertext, err := crypto.EncryptDEM(key, plaintext)
	if err != nil {
		return err
	}

	ec := EncryptedConfig{
		KDF:        "argon2id",
		Salt:       salt,
		Ciphertext: ciphertext,
	}

	b, err := json.MarshalIndent(ec, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return os.WriteFile(path, b, 0600)
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try to unmarshal as EncryptedConfig
	var ec EncryptedConfig
	if err := json.Unmarshal(b, &ec); err == nil && ec.KDF == "argon2id" {
		// It is encrypted
		password, err := getPassword("Enter passphrase to decrypt config: ", false)
		if err != nil {
			return nil, err
		}

		key := deriveKey(password, ec.Salt)
		plaintext, err := crypto.DecryptDEM(key, ec.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
		}

		var c Config
		if err := json.Unmarshal(plaintext, &c); err != nil {
			return nil, err
		}
		return &c, nil
	}

	// Fallback: Try plaintext (migration)
	var c Config
	if err := json.Unmarshal(b, &c); err == nil && c.UserID != "" {
		fmt.Println("Warning: Config is unencrypted. It will be encrypted on next save.")
		return &c, nil
	}

	return nil, fmt.Errorf("invalid config format")
}

func deriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func getPassword(prompt string, confirm bool) ([]byte, error) {
	if envPass := os.Getenv("DISTFS_PASSWORD"); envPass != "" {
		return []byte(envPass), nil
	}

	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, err
	}

	if confirm {
		fmt.Print("Confirm passphrase: ")
		byteConfirm, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(bytePassword, byteConfirm) {
			return nil, fmt.Errorf("passwords do not match")
		}
	}
	return bytePassword, nil
}
