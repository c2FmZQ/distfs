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

package crypto

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestSignatureCache_Basic(t *testing.T) {
	// Ensure cache is initialized with default size
	sigCache = nil
	sigCacheInit = sync.Once{}

	k, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello signature cache")
	sig := k.Sign(msg)

	// First verification (miss)
	start := time.Now()
	if !VerifySignature(k.Public(), msg, sig) {
		t.Fatal("first verification failed")
	}
	firstDuration := time.Since(start)

	// Second verification (hit)
	start = time.Now()
	if !VerifySignature(k.Public(), msg, sig) {
		t.Fatal("second verification failed")
	}
	secondDuration := time.Since(start)

	t.Logf("First verify: %v, Second verify: %v", firstDuration, secondDuration)

	// Verify that modifying any input causes a miss/failure
	if VerifySignature(k.Public(), []byte("modified msg"), sig) {
		t.Fatal("verification should have failed for modified message")
	}
	// Verify that a bad signature fails
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if VerifySignature(k.Public(), msg, badSig) {
		t.Fatal("verification should have failed for bad signature")
	}
}

func TestSignatureCache_Disabled(t *testing.T) {
	os.Setenv("DISTFS_SIG_CACHE_SIZE", "0")
	defer os.Unsetenv("DISTFS_SIG_CACHE_SIZE")

	// Reset cache
	sigCache = nil
	sigCacheInit = sync.Once{}

	k, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("disabled cache test")
	sig := k.Sign(msg)

	if !VerifySignature(k.Public(), msg, sig) {
		t.Fatal("verification failed when cache disabled")
	}

	if getSigCache() != nil {
		t.Fatal("cache should be nil when size is 0")
	}
}

func TestSignatureCache_CustomSize(t *testing.T) {
	os.Setenv("DISTFS_SIG_CACHE_SIZE", "2")
	defer os.Unsetenv("DISTFS_SIG_CACHE_SIZE")

	// Reset cache
	sigCache = nil
	sigCacheInit = sync.Once{}

	c := getSigCache()
	if c == nil {
		t.Fatal("cache should not be nil")
	}

	k, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	// Sign 3 different messages
	msg1 := []byte("msg1")
	msg2 := []byte("msg2")
	msg3 := []byte("msg3")
	sig1 := k.Sign(msg1)
	sig2 := k.Sign(msg2)
	sig3 := k.Sign(msg3)

	// Verify 1 and 2 (adds them to cache, filling it since size is 2)
	VerifySignature(k.Public(), msg1, sig1)
	VerifySignature(k.Public(), msg2, sig2)

	key1 := computeCacheKey(k.Public(), msg1, sig1)

	if !c.Contains(key1) {
		t.Fatal("msg1 should be in cache")
	}

	// Verify 3 (should evict msg1 because it's LRU and msg2 was most recently accessed/added)
	VerifySignature(k.Public(), msg3, sig3)

	if c.Contains(key1) {
		t.Fatal("msg1 should have been evicted")
	}
}
