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

//go:build nopinentry

package config

import "fmt"

var (
	// UsePinentry is always false when built with nopinentry.
	UsePinentry = false
)

func getPasswordPinentry(prompt string, confirm bool) ([]byte, error) {
	return nil, fmt.Errorf("pinentry support is disabled in this build")
}
