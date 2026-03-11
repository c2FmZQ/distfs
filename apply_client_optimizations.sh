#!/bin/bash
set -e

# Apply downloadBufPool
sed -i '/func (c \*Client) downloadChunk/i \
var downloadBufPool = sync.Pool{\
	New: func() interface{} {\
		b := bytes.NewBuffer(make([]byte, 0, crypto.ChunkSize+4096))\
		return b\
	},\
}\
' pkg/client/client.go

sed -i 's/d, err := io.ReadAll(io.LimitReader(resp.Body, limit))/buf := downloadBufPool.Get().(*bytes.Buffer)\
				buf.Reset()\
				_, err = io.Copy(buf, io.LimitReader(resp.Body, limit))\
				var d []byte\
				if err == nil {\
					d = make([]byte, buf.Len())\
					copy(d, buf.Bytes())\
				}\
				downloadBufPool.Put(buf)/' pkg/client/client.go

# Apply sequential heuristic
sed -i 's/readAhead   map\[int64\]\*readAheadResult/readAhead   map[int64]*readAheadResult\
	lastChunkIdx   int64\
	sequentialHits int/' pkg/client/client.go

sed -i 's/currentChunkIdx: -1,/currentChunkIdx: -1,\
		lastChunkIdx:    -1,/' pkg/client/client.go

sed -i '/\/\/ Trigger prefetch for next few chunks/c \
			// Phase 52.5: FUSE Pre-fetching Thresholds (Sequential Heuristic)\
			if chunkIdx == r.lastChunkIdx+1 || chunkIdx == r.lastChunkIdx {\
				if chunkIdx != r.lastChunkIdx {\
					r.sequentialHits++\
				}\
			} else {\
				r.sequentialHits = 0\
			}\
			r.lastChunkIdx = chunkIdx\
\
			if r.sequentialHits >= 1 {\
				for i := int64(1); i <= 3; i++ {\
					r.triggerPrefetch(chunkIdx + i)\
				}\
			}' pkg/client/client.go

# Fix ReadAt deadlock
sed -i '/func (r \*FileReader) ReadAt/,/^}/c \
func (r *FileReader) ReadAt(p []byte, off int64) (int, error) {\
	r.mu.Lock()\
	originalOffset := r.offset\
	r.offset = off\
	n, err := r.read(p)\
	r.offset = originalOffset\
	r.mu.Unlock()\
	return n, err\
}' pkg/client/client.go

# Apply Reverse PathCache
sed -i 's/pathCache map\[string\]pathCacheEntry/pathCache map[string]pathCacheEntry\
	pathCacheReverse map[string]map[string]bool/' pkg/client/client.go

sed -i 's/pathCache:      make(map\[string\]pathCacheEntry),/pathCache:      make(map[string]pathCacheEntry),\
		pathCacheReverse: make(map[string]map[string]bool),/' pkg/client/client.go
sed -i 's/pathCache:     make(map\[string\]pathCacheEntry),/pathCache:     make(map[string]pathCacheEntry),\
		pathCacheReverse: make(map[string]map[string]bool),/' pkg/client/client.go
sed -i 's/c2.pathCache = make(map\[string\]pathCacheEntry)/c2.pathCache = make(map[string]pathCacheEntry)\
	c2.pathCacheReverse = make(map[string]map[string]bool)/' pkg/client/client.go

sed -i '/func (c \*Client) putPathCache/,/^}/c \
func (c *Client) putPathCache(path string, entry pathCacheEntry) {\
	c.pathMu.Lock()\
	defer c.pathMu.Unlock()\
	if old, exists := c.pathCache[path]; exists {\
		if old.inodeID != entry.inodeID {\
			if paths, ok := c.pathCacheReverse[old.inodeID]; ok {\
				delete(paths, path)\
				if len(paths) == 0 {\
					delete(c.pathCacheReverse, old.inodeID)\
				}\
			}\
		}\
	}\
	c.pathCache[path] = entry\
	if c.pathCacheReverse[entry.inodeID] == nil {\
		c.pathCacheReverse[entry.inodeID] = make(map[string]bool)\
	}\
	c.pathCacheReverse[entry.inodeID][path] = true\
}' pkg/client/client.go

sed -i '/func (c \*Client) invalidatePathCache(path string) {/,/^}/c \
func (c *Client) invalidatePathCache(path string) {\
	c.pathMu.Lock()\
	defer c.pathMu.Unlock()\
	if old, exists := c.pathCache[path]; exists {\
		if paths, ok := c.pathCacheReverse[old.inodeID]; ok {\
			delete(paths, path)\
			if len(paths) == 0 {\
				delete(c.pathCacheReverse, old.inodeID)\
			}\
		}\
	}\
	delete(c.pathCache, path)\
}' pkg/client/client.go

sed -i '/func (c \*Client) invalidatePathCacheByID(id string) {/,/^}/c \
func (c *Client) invalidatePathCacheByID(id string) {\
	c.pathMu.Lock()\
	defer c.pathMu.Unlock()\
	if paths, ok := c.pathCacheReverse[id]; ok {\
		for path := range paths {\
			delete(c.pathCache, path)\
		}\
		delete(c.pathCacheReverse, id)\
	}\
}' pkg/client/client.go

sed -i '/func (c \*Client) clearPathCache() {/,/^}/c \
func (c *Client) clearPathCache() {\
	c.pathMu.Lock()\
	defer c.pathMu.Unlock()\
	clear(c.pathCache)\
	clear(c.pathCacheReverse)\
}' pkg/client/client.go

# Ensure putPathCache is used everywhere instead of direct map assignment
sed -i '/w.client.pathMu.Lock()/,/w.client.pathMu.Unlock()/c \
			w.client.putPathCache(w.swapPath, pathCacheEntry{\
				inodeID: w.inode.ID,\
				key:     w.fileKey,\
				linkTag: w.parentID + ":" + w.nameHMAC,\
			})' pkg/client/client.go

sed -i '/c.pathCache\[w.swapPath\] = pathCacheEntry{/,/}/c \
		c.putPathCache(w.swapPath, pathCacheEntry{\
			inodeID: w.inode.ID,\
			key:     w.fileKey,\
			linkTag: w.parentID + ":" + w.nameHMAC,\
			inode:   \&w.inode,\
		})' pkg/client/client.go

sed -i 's/c.pathMu.Lock()/c.clearPathCache()/' pkg/client/path_cache_test.go
sed -i 's/c.pathCache = make(map\[string\]pathCacheEntry)//' pkg/client/path_cache_test.go
sed -i '/c.pathMu.Unlock()/d' pkg/client/path_cache_test.go

# Apply Signature Caching
sed -i 's/sigCache map\[string\]bool//' pkg/client/client.go
sed -i 's/sigMu    \*sync.RWMutex//' pkg/client/client.go

sed -i 's/registryDir string/registryDir string\
\
	sigCache map[string]bool\
	sigMu    *sync.RWMutex/' pkg/client/client.go

sed -i 's/rootMu:        &sync.RWMutex{},/rootMu:        \&sync.RWMutex{},\
		sigCache:      make(map[string]bool),\
		sigMu:         \&sync.RWMutex{},/' pkg/client/client.go

sed -i 's/c2.pathMu = &sync.RWMutex{}/c2.pathMu = \&sync.RWMutex{}\
	c2.sigCache = make(map[string]bool)\
	c2.sigMu = \&sync.RWMutex{}/' pkg/client/client.go

sed -i '/func (c \*Client) clearPathCache() {/,/^}/c \
func (c *Client) clearPathCache() {\
	c.pathMu.Lock()\
	defer c.pathMu.Unlock()\
	clear(c.pathCache)\
	clear(c.pathCacheReverse)\
	c.sigMu.Lock()\
	defer c.sigMu.Unlock()\
	clear(c.sigCache)\
}' pkg/client/client.go

sed -i '/\/\/ 2. Verify Signatures/,/if !crypto.VerifySignature(user.SignKey, hash, inode.UserSig) {/c \
	// 2. Verify Signatures\
	hash := inode.ManifestHash()\
	sigHash := sha256.Sum256(inode.UserSig)\
	cacheKey := string(hash) + ":" + string(sigHash[:])\
	\
	c.sigMu.RLock()\
	cachedValid, hasCache := c.sigCache[cacheKey]\
	c.sigMu.RUnlock()\
\
	user, err := c.GetUser(ctx, signerID)\
	if err != nil {\
		return fmt.Errorf("failed to fetch signer %s: %w", signerID, err)\
	}\
\
	if hasCache {\
		if !cachedValid {\
			return fmt.Errorf("invalid manifest signature by %s (cached)", signerID)\
		}\
	} else {\
		valid := crypto.VerifySignature(user.SignKey, hash, inode.UserSig)\
		c.sigMu.Lock()\
		if len(c.sigCache) > 10000 {\
			for k := range c.sigCache {\
				delete(c.sigCache, k)\
				break\
			}\
		}\
		c.sigCache[cacheKey] = valid\
		c.sigMu.Unlock()\
\
		if !valid {' pkg/client/client.go

