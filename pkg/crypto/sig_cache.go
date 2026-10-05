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
	"crypto/sha256"
	"hash"
	"os"
	"strconv"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

var (
	sigCache     *lru.Cache[[32]byte, struct{}]
	sigCacheInit sync.Once
)

const defaultSigCacheSize = 8192

// getSigCache retrieves the initialized LRU signature cache,
// returning nil if the cache is disabled or failed to initialize.
func getSigCache() *lru.Cache[[32]byte, struct{}] {
	sigCacheInit.Do(func() {
		size := defaultSigCacheSize
		if val := os.Getenv("DISTFS_SIG_CACHE_SIZE"); val != "" {
			if parsed, err := strconv.Atoi(val); err == nil && parsed >= 0 {
				size = parsed
			}
		}
		if size == 0 {
			return
		}
		c, err := lru.New[[32]byte, struct{}](size)
		if err != nil {
			return
		}
		sigCache = c
	})
	return sigCache
}

var sha256Pool = sync.Pool{
	New: func() any {
		return sha256.New()
	},
}

// computeCacheKey generates a 32-byte hash of (PubKey || Msg || Signature).
// Uses a sync.Pool of SHA-256 hashes to guarantee zero heap allocations.
func computeCacheKey(pubKey, msg, sig []byte) [32]byte {
	h := sha256Pool.Get().(hash.Hash)
	h.Reset()
	h.Write(pubKey)
	h.Write(msg)
	h.Write(sig)
	var sum [32]byte
	h.Sum(sum[:0])
	sha256Pool.Put(h)
	return sum
}

// verifyCacheGet queries the signature cache. Returns true on cache hit.
func verifyCacheGet(pubKey, msg, sig []byte) bool {
	c := getSigCache()
	if c == nil {
		return false
	}
	key := computeCacheKey(pubKey, msg, sig)
	_, found := c.Get(key)
	return found
}

// verifyCachePut records a successful signature verification in the cache.
func verifyCachePut(pubKey, msg, sig []byte) {
	c := getSigCache()
	if c == nil {
		return
	}
	key := computeCacheKey(pubKey, msg, sig)
	c.Add(key, struct{}{})
}
