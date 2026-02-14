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

//go:build !nopinentry

package config

import (
	"fmt"
	"os"
	"regexp"

	"github.com/twpayne/go-pinentry/v4"
)

var (
	// UsePinentry can be set to true to enable pinentry support.
	UsePinentry bool

	// ttyRegex is used to validate GPG_TTY to prevent command injection in go-pinentry.
	// Assuan protocol uses \n as delimiter, so we must exclude it and other suspicious chars.
	// A typical TTY is /dev/pts/N or /dev/ttyN.
	ttyRegex = regexp.MustCompile(`^[a-zA-Z0-9/_.-]+$`)
)

func getPasswordPinentry(prompt string, confirm bool) ([]byte, error) {
	options := []pinentry.ClientOption{
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithDesc("DistFS Passphrase Entry"),
		pinentry.WithPrompt(prompt),
		pinentry.WithTitle("DistFS"),
	}

	if gpgTTY, ok := os.LookupEnv("GPG_TTY"); ok {
		if !ttyRegex.MatchString(gpgTTY) {
			return nil, fmt.Errorf("invalid GPG_TTY environment variable")
		}
		// Securely pass GPG_TTY using WithOption which escapes.
		options = append(options, pinentry.WithOption("ttyname="+gpgTTY))
	}

	if confirm {
		options = append(options, pinentry.WithRepeat("Confirm "+prompt))
	}

	client, err := pinentry.NewClient(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to start pinentry: %w", err)
	}
	defer client.Close()

	result, err := client.GetPIN()
	if err != nil {
		if pinentry.IsCancelled(err) {
			return nil, fmt.Errorf("passphrase entry cancelled")
		}
		return nil, err
	}

	if confirm && !result.PINRepeated {
		return nil, fmt.Errorf("passwords do not match")
	}

	return []byte(result.PIN), nil
}
