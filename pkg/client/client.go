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
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func (c *Client) GetServerKey() (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	sk := c.serverKey
	c.keyMu.RUnlock()
	if sk != nil {
		return sk, nil
	}

	resp, err := c.httpClient.Get(c.metaURL + "/v1/meta/key")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch server key: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	pk, err := crypto.UnmarshalEncapsulationKey(b)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.serverKey = pk
	c.keyMu.Unlock()
	return pk, nil
}

type Client struct {
	metaURL    string
	dataURL    string
	httpClient *http.Client
	userID     string
	decKey     *mlkem.DecapsulationKey768
	signKey    *crypto.IdentityKey
	serverKey  *mlkem.EncapsulationKey768
	keyCache   map[string][]byte
	keyMu      sync.RWMutex

	worldPublic  *mlkem.EncapsulationKey768
	worldPrivate *mlkem.DecapsulationKey768
	groupKeys    map[string]*mlkem.DecapsulationKey768

	sessionToken  string
	sessionExpiry time.Time
	sessionMu     *sync.RWMutex
	loginMu       *sync.Mutex
}

func NewClient(metaAddr, dataAddr string) *Client {
	t := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}
	return &Client{
		metaURL:    metaAddr,
		dataURL:    dataAddr,
		httpClient: &http.Client{Transport: t},
		keyCache:   make(map[string][]byte),
		groupKeys:  make(map[string]*mlkem.DecapsulationKey768),
		sessionMu:  &sync.RWMutex{},
		loginMu:    &sync.Mutex{},
	}
}

func (c *Client) WithIdentity(userID string, key *mlkem.DecapsulationKey768) *Client {
	c2 := *c
	c2.userID = userID
	c2.decKey = key
	c2.keyCache = make(map[string][]byte) // New cache for new identity
	return &c2
}

func (c *Client) WithSignKey(key *crypto.IdentityKey) *Client {
	c2 := *c
	c2.signKey = key
	return &c2
}

func (c *Client) WithServerKey(key *mlkem.EncapsulationKey768) *Client {
	c2 := *c
	c2.serverKey = key
	return &c2
}

func (c *Client) Login() error {
	// 1. Get Challenge
	reqData := metadata.AuthChallengeRequest{UserID: c.userID}
	b, _ := json.Marshal(reqData)
	resp, err := c.httpClient.Post(c.metaURL+"/v1/auth/challenge", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("challenge request failed: %d %s", resp.StatusCode, string(b))
	}

	var challengeRes metadata.AuthChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeRes); err != nil {
		return err
	}

	// 2. Verify server signature over challenge
	// (Skipped for now as we don't have server's sign public key readily available in Client)

	// 3. Solve Challenge (Sign it)
	sig := c.signKey.Sign(challengeRes.Challenge)

	solve := metadata.AuthChallengeSolve{
		UserID:    c.userID,
		Challenge: challengeRes.Challenge,
		Signature: sig,
	}
	b, _ = json.Marshal(solve)

	resp, err = c.httpClient.Post(c.metaURL+"/v1/login", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: %d %s", resp.StatusCode, string(b))
	}

	var res metadata.SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}

	c.sessionMu.Lock()
	c.sessionToken = res.Token
	c.sessionExpiry = time.Now().Add(55 * time.Minute) // Buffer
	c.sessionMu.Unlock()
	return nil
}

func (c *Client) authenticateRequest(req *http.Request) error {
	// 1. Special cases: registration, login, and keys don't need session auth.
	if strings.HasSuffix(req.URL.Path, "/v1/user/register") ||
		strings.HasSuffix(req.URL.Path, "/v1/auth/challenge") ||
		strings.HasSuffix(req.URL.Path, "/v1/login") ||
		strings.HasSuffix(req.URL.Path, "/v1/meta/key") {
		if strings.HasSuffix(req.URL.Path, "/v1/user/register") {
			return c.authenticatePQC(req)
		}
		return nil
	}

	// If no identity is configured, we can't authenticate.
	if c.userID == "" || c.signKey == nil || c.decKey == nil {
		return nil
	}

	// 2. For all other requests, use the Session Token.
	c.sessionMu.RLock()
	token := c.sessionToken
	expiry := c.sessionExpiry
	c.sessionMu.RUnlock()

	// If token is missing or about to expire, perform a login handshake.
	if token == "" || time.Now().Add(5*time.Minute).After(expiry) {
		// Acquire login lock to serialize handshakes
		c.loginMu.Lock()
		defer c.loginMu.Unlock()

		// Double check under RLock after acquiring loginMu
		c.sessionMu.RLock()
		token = c.sessionToken
		expiry = c.sessionExpiry
		c.sessionMu.RUnlock()

		if token == "" || time.Now().Add(5*time.Minute).After(expiry) {
			if err := c.Login(); err != nil {
				return fmt.Errorf("session login failed: %w", err)
			}
			c.sessionMu.RLock()
			token = c.sessionToken
			c.sessionMu.RUnlock()
		}
	}

	req.Header.Set("Session-Token", token)
	return nil
}

func (c *Client) authenticatePQC(req *http.Request) error {
	if c.signKey == nil || c.serverKey == nil {
		return fmt.Errorf("client keys (sign/server) not configured")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	token := metadata.AuthToken{
		UserID: c.userID,
		Time:   time.Now().UnixNano(),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
	}
	payload, _ := json.Marshal(token)

	sig := c.signKey.Sign(payload)

	signed := metadata.SignedAuthToken{
		Payload:   payload,
		Signature: sig,
	}
	signedB, _ := json.Marshal(signed)

	ss, kemCT := crypto.Encapsulate(c.serverKey)
	demCT, err := crypto.EncryptDEM(ss, signedB)
	if err != nil {
		return err
	}

	fullToken := append(kemCT, demCT...)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(fullToken))
	return nil
}

func (c *Client) allocateNodes() ([]metadata.Node, error) {
	req, err := http.NewRequest("POST", c.metaURL+"/v1/meta/allocate", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("allocate failed: %d", resp.StatusCode)
	}
	var nodes []metadata.Node
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

func (c *Client) issueToken(inodeID string, chunks []string, mode string) (string, error) {
	reqData := map[string]interface{}{
		"inode_id": inodeID,
		"chunks":   chunks,
		"mode":     mode,
	}
	body, _ := json.Marshal(reqData)

	req, err := http.NewRequest("POST", c.metaURL+"/v1/meta/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	if err := c.authenticateRequest(req); err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("issueToken failed: %d %s", resp.StatusCode, string(b))
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(respBytes), nil
}

func (c *Client) uploadChunk(id string, data []byte, nodes []metadata.Node, token string) error {
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes allocated")
	}
	primary := nodes[0]

	url := fmt.Sprintf("%s/v1/data/%s", primary.Address, id)
	if len(nodes) > 1 {
		var replicas []string
		for _, n := range nodes[1:] {
			replicas = append(replicas, n.Address)
		}
		url += "?replicas=" + strings.Join(replicas, ",")
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("upload failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) downloadChunk(id string, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", c.dataURL+"/v1/data/"+id, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download chunk failed: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error: %d %s", e.StatusCode, e.Message)
}

func (c *Client) createInode(inode metadata.Inode) (*metadata.Inode, error) {
	data, err := json.Marshal(inode)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.metaURL+"/v1/meta/inode", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(b)}
	}

	var created metadata.Inode
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) updateInode(inode metadata.Inode) (*metadata.Inode, error) {
	data, err := json.Marshal(inode)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("PUT", c.metaURL+"/v1/meta/inode/"+inode.ID, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(b)}
	}

	var updated metadata.Inode
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func (c *Client) getInode(id string) (*metadata.Inode, error) {
	req, err := http.NewRequest("GET", c.metaURL+"/v1/meta/inode/"+id, nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(b)}
	}
	var inode metadata.Inode
	if err := json.NewDecoder(resp.Body).Decode(&inode); err != nil {
		return nil, err
	}
	return &inode, nil
}

func (c *Client) getInodes(ids []string) ([]*metadata.Inode, error) {
	body, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.metaURL+"/v1/meta/inodes", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get inodes failed: %d", resp.StatusCode)
	}
	var inodes []*metadata.Inode
	if err := json.NewDecoder(resp.Body).Decode(&inodes); err != nil {
		return nil, err
	}
	return inodes, nil
}

func (c *Client) writeInodeContent(id string, iType metadata.InodeType, fileKey []byte, r io.Reader, size int64, encryptedName []byte, mode uint32, groupID string) error {
	if r == nil {
		r = bytes.NewReader(nil)
	}

	var inode metadata.Inode
	// Try to get existing inode
	existing, err := c.getInode(id)
	if err == nil {
		inode = *existing
		// Preserve existing Lockbox entries if possible
		if inode.Lockbox == nil {
			inode.Lockbox = crypto.NewLockbox()
		}
		if c.decKey != nil {
			if err := inode.Lockbox.AddRecipient(c.userID, c.decKey.EncapsulationKey(), fileKey); err != nil {
				return err
			}
		}
		if (mode & 0004) != 0 {
			wpk, err := c.GetWorldPublicKey()
			if err == nil {
				inode.Lockbox.AddRecipient(metadata.WorldID, wpk, fileKey)
			}
		}
		if groupID != "" && (mode&0060) != 0 {
			group, err := c.GetGroup(groupID)
			if err == nil {
				gpk, _ := crypto.UnmarshalEncapsulationKey(group.EncKey)
				inode.Lockbox.AddRecipient(groupID, gpk, fileKey)
			}
		}
		if encryptedName != nil {
			inode.EncryptedName = encryptedName
		}
	} else if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
		lb := c.createLockbox(fileKey, mode, groupID)

		// Assume not found, create new
		inode = metadata.Inode{
			ID:            id,
			Type:          iType,
			Mode:          mode,
			Size:          uint64(size),
			ChunkManifest: nil,
			Lockbox:       lb,
			EncryptedName: encryptedName,
			OwnerID:       c.userID,
			GroupID:       groupID,
		}
		created, err := c.createInode(inode)
		if err != nil {
			return err
		}
		inode = *created
	} else {
		return err
	}

	var chunkEntries []metadata.ChunkEntry
	buf := make([]byte, crypto.ChunkSize)

	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			chunkData := buf[:n]
			cid, ct, err := crypto.EncryptChunk(fileKey, chunkData)
			if err != nil {
				return err
			}

			token, err := c.issueToken(id, []string{cid}, "W")
			if err != nil {
				return fmt.Errorf("token issue failed: %v", err)
			}

			nodes, err := c.allocateNodes()
			if err != nil {
				if c.dataURL != "" {
					nodes = []metadata.Node{{Address: c.dataURL}}
				} else {
					return fmt.Errorf("allocation failed: %v", err)
				}
			}

			if err := c.uploadChunk(cid, ct, nodes, token); err != nil {
				return err
			}

			var nodeIDs []string
			for _, node := range nodes {
				nodeIDs = append(nodeIDs, node.ID)
			}
			chunkEntries = append(chunkEntries, metadata.ChunkEntry{ID: cid, Nodes: nodeIDs})
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}

	// Final update using updateInode (uses version check)
	inode.ChunkManifest = chunkEntries
	inode.Size = uint64(size)
	_, err = c.updateInode(inode)
	if err == nil {
		c.keyMu.Lock()
		c.keyCache[id] = fileKey
		c.keyMu.Unlock()
	}
	return err
}

// WriteFile writes a file. Returns the FileKey used.
func (c *Client) WriteFile(id string, r io.Reader, size int64, mode uint32) ([]byte, error) {
	c.keyMu.RLock()
	fileKey, ok := c.keyCache[id]
	c.keyMu.RUnlock()

	var groupID string
	if !ok {
		if inode, err := c.GetInode(id); err == nil {
			if key, err := c.UnlockInode(inode); err == nil {
				fileKey = key
				groupID = inode.GroupID
			}
		}
	}

	if fileKey == nil {
		fileKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
			return nil, err
		}
	}

	if err := c.writeInodeContent(id, metadata.FileType, fileKey, r, size, nil, mode, groupID); err != nil {
		return nil, err
	}
	return fileKey, nil
}

type readAheadResult struct {
	data  []byte
	err   error
	ready chan struct{}
}

type FileReader struct {
	client          *Client
	inode           *metadata.Inode
	fileKey         []byte
	offset          int64
	currentChunkIdx int64
	currentChunk    []byte
	token           string
	mu              sync.Mutex

	readAhead   map[int64]readAheadResult
	readAheadMu sync.Mutex
}

func (c *Client) NewReader(id string, fileKey []byte) (*FileReader, error) {
	inode, err := c.getInode(id)
	if err != nil {
		return nil, err
	}

	if fileKey == nil {
		c.keyMu.RLock()
		fileKey = c.keyCache[id]
		c.keyMu.RUnlock()
	}

	if fileKey == nil {
		if c.decKey == nil {
			return nil, fmt.Errorf("client has no identity to unlock file")
		}
		key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
		if err != nil {
			return nil, err
		}
		fileKey = key
		c.keyMu.Lock()
		c.keyCache[id] = fileKey
		c.keyMu.Unlock()
	}

	token, _ := c.issueToken(id, nil, "R")

	return &FileReader{
		client:          c,
		inode:           inode,
		fileKey:         fileKey,
		offset:          0,
		currentChunkIdx: -1,
		token:           token,
		readAhead:       make(map[int64]readAheadResult),
	}, nil
}

func (r *FileReader) triggerPrefetch(idx int64) {
	if idx < 0 || idx >= int64(len(r.inode.ChunkManifest)) {
		return
	}

	r.readAheadMu.Lock()
	if _, exists := r.readAhead[idx]; exists {
		r.readAheadMu.Unlock()
		return
	}
	res := readAheadResult{ready: make(chan struct{})}
	r.readAhead[idx] = res
	r.readAheadMu.Unlock()

	go func() {
		chunkEntry := r.inode.ChunkManifest[idx]
		ct, err := r.client.downloadChunk(chunkEntry.ID, r.token)
		var pt []byte
		if err == nil {
			pt, err = crypto.DecryptChunk(r.fileKey, ct)
		}

		r.readAheadMu.Lock()
		res := r.readAhead[idx]
		res.data = pt
		res.err = err
		close(res.ready)
		r.readAhead[idx] = res
		r.readAheadMu.Unlock()
	}()
}

func (r *FileReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.read(p)
}

func (r *FileReader) read(p []byte) (int, error) {
	if r.offset >= int64(r.inode.Size) {
		return 0, io.EOF
	}

	remaining := int64(r.inode.Size) - r.offset
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	totalRead := 0
	chunkSize := int64(crypto.ChunkSize)

	for len(p) > 0 {
		chunkIdx := r.offset / chunkSize
		chunkOffset := r.offset % chunkSize

		// Detect seek/random access and clear cache
		if r.currentChunkIdx != -1 && chunkIdx != r.currentChunkIdx+1 && chunkIdx != r.currentChunkIdx {
			r.readAheadMu.Lock()
			// Clear cache to prevent leaks during random access
			for k := range r.readAhead {
				delete(r.readAhead, k)
			}
			r.readAheadMu.Unlock()
		}

		var pt []byte
		if chunkIdx == r.currentChunkIdx && r.currentChunk != nil {
			pt = r.currentChunk
		} else {
			// Trigger prefetch for next few chunks
			for i := int64(1); i <= 3; i++ {
				r.triggerPrefetch(chunkIdx + i)
			}

			// Check Cache
			r.readAheadMu.Lock()
			res, exists := r.readAhead[chunkIdx]
			r.readAheadMu.Unlock()

			if exists {
				// Wait for it
				r.mu.Unlock()
				<-res.ready
				r.mu.Lock()

				r.readAheadMu.Lock()
				res = r.readAhead[chunkIdx]
				r.readAheadMu.Unlock()

				if res.err != nil {
					return totalRead, res.err
				}
				pt = res.data
			} else {
				if chunkIdx >= int64(len(r.inode.ChunkManifest)) {
					break
				}
				chunkEntry := r.inode.ChunkManifest[chunkIdx]

				// Unlock during network I/O
				r.mu.Unlock()
				ct, err := r.client.downloadChunk(chunkEntry.ID, r.token)
				r.mu.Lock()

				if err != nil {
					return totalRead, err
				}
				pt, err = crypto.DecryptChunk(r.fileKey, ct)
				if err != nil {
					return totalRead, err
				}
			}

			// Cleanup old
			r.readAheadMu.Lock()
			delete(r.readAhead, chunkIdx-1)
			delete(r.readAhead, chunkIdx-2)
			r.readAheadMu.Unlock()

			r.currentChunk = pt
			r.currentChunkIdx = chunkIdx
		}

		available := int64(len(pt)) - chunkOffset
		if available <= 0 {
			return totalRead, fmt.Errorf("chunk offset out of bounds")
		}

		toCopy := int64(len(p))
		if toCopy > available {
			toCopy = available
		}

		copy(p, pt[chunkOffset:chunkOffset+toCopy])

		n := int(toCopy)
		p = p[n:]
		r.offset += int64(n)
		totalRead += n
	}
	return totalRead, nil
}

func (r *FileReader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offset = off
	return r.read(p)
}

func (r *FileReader) Stat() *metadata.Inode {
	return r.inode
}

func (c *Client) ReadFile(id string, fileKey []byte) (io.ReadCloser, error) {
	r, err := c.NewReader(id, fileKey)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(r), nil
}

// GetInode fetches the inode metadata.
func (c *Client) GetInode(id string) (*metadata.Inode, error) {
	return c.getInode(id)
}

// GetInodes fetches metadata for multiple inodes in a single batch call.
func (c *Client) GetInodes(ids []string) ([]*metadata.Inode, error) {
	return c.getInodes(ids)
}

// UnlockInode attempts to decrypt the file key for the inode using the client's identity.
func (c *Client) UnlockInode(inode *metadata.Inode) ([]byte, error) {
	if c.decKey == nil {
		return nil, fmt.Errorf("client has no identity to unlock file")
	}

	var lastErr error

	// 1. Try personal access
	key, err := inode.Lockbox.GetFileKey(c.userID, c.decKey)
	if err == nil {
		return key, nil
	}
	lastErr = err

	// 2. Try group access if personal failed
	if inode.GroupID != "" {
		if _, exists := inode.Lockbox[inode.GroupID]; exists {
			gk, gerr := c.GetGroupPrivateKey(inode.GroupID)
			if gerr == nil {
				key, err = inode.Lockbox.GetFileKey(inode.GroupID, gk)
				if err == nil {
					return key, nil
				}
				lastErr = err
			} else {
				lastErr = gerr
			}
		}
	}

	// 3. Try world access if group failed
	if _, exists := inode.Lockbox[metadata.WorldID]; exists {
		wk, err := c.GetWorldPrivateKey()
		if err == nil {
			key, err = inode.Lockbox.GetFileKey(metadata.WorldID, wk)
			if err == nil {
				return key, nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("access denied: no applicable recipient in lockbox")
	}
	return nil, lastErr
}

func (c *Client) GetGroupPrivateKey(groupID string) (*mlkem.DecapsulationKey768, error) {
	c.keyMu.RLock()
	gk, ok := c.groupKeys[groupID]
	c.keyMu.RUnlock()
	if ok {
		return gk, nil
	}

	req, err := http.NewRequest("GET", c.metaURL+"/v1/group/"+groupID+"/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch group private key: %d", resp.StatusCode)
	}

	var entry crypto.LockboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		return nil, err
	}

	// Group Private Key is encrypted for Client's identity
	secret, err := crypto.Decapsulate(c.decKey, entry.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("group key decapsulate failed: %w", err)
	}
	privBytes, err := crypto.DecryptDEM(secret, entry.DEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("group key decrypt failed: %w", err)
	}

	gk, err = crypto.UnmarshalDecapsulationKey(privBytes)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.groupKeys[groupID] = gk
	c.keyMu.Unlock()
	return gk, nil
}

func (c *Client) GetWorldPublicKey() (*mlkem.EncapsulationKey768, error) {
	c.keyMu.RLock()
	wp := c.worldPublic
	c.keyMu.RUnlock()
	if wp != nil {
		return wp, nil
	}

	resp, err := c.httpClient.Get(c.metaURL + "/v1/meta/key/world")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch world pub key: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	pk, err := crypto.UnmarshalEncapsulationKey(b)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.worldPublic = pk
	c.keyMu.Unlock()
	return pk, nil
}

func (c *Client) GetWorldPrivateKey() (*mlkem.DecapsulationKey768, error) {
	c.keyMu.RLock()
	wp := c.worldPrivate
	c.keyMu.RUnlock()
	if wp != nil {
		return wp, nil
	}

	req, err := http.NewRequest("GET", c.metaURL+"/v1/meta/key/world/private", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch world private key: %d", resp.StatusCode)
	}

	var data struct {
		KEM string `json:"kem"`
		DEM string `json:"dem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	kemCT, _ := base64.StdEncoding.DecodeString(data.KEM)
	demCT, _ := base64.StdEncoding.DecodeString(data.DEM)

	// Decrypt using Client's identity
	ss, err := crypto.Decapsulate(c.decKey, kemCT)
	if err != nil {
		return nil, fmt.Errorf("world key decapsulate failed: %w", err)
	}
	privBytes, err := crypto.DecryptDEM(ss, demCT)
	if err != nil {
		return nil, fmt.Errorf("world key decrypt failed: %w", err)
	}

	wk, err := crypto.UnmarshalDecapsulationKey(privBytes)
	if err != nil {
		return nil, err
	}

	c.keyMu.Lock()
	c.worldPrivate = wk
	c.keyMu.Unlock()
	return wk, nil
}

func (c *Client) GetGroup(id string) (*metadata.Group, error) {
	req, err := http.NewRequest("GET", c.metaURL+"/v1/group/"+id, nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get group failed: %d", resp.StatusCode)
	}

	var group metadata.Group
	if err := json.NewDecoder(resp.Body).Decode(&group); err != nil {
		return nil, err
	}
	return &group, nil
}

func (c *Client) CreateGroup(name string) (*metadata.Group, error) {
	dk, _ := crypto.GenerateEncryptionKey()
	pk := dk.EncapsulationKey().Bytes()
	priv := crypto.MarshalDecapsulationKey(dk)

	lb := crypto.NewLockbox()
	// Encrypt group private key for the creator (owner)
	if err := lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), priv); err != nil {
		return nil, err
	}

	// Encrypt Group Name using Group Key (DEM)
	// Group private key is 64 bytes (mlkem), but DEM needs 32 bytes.
	// We hash the private key to get a 32-byte symmetric key.
	h := sha256.Sum256(priv)
	encName, err := crypto.EncryptDEM(h[:], []byte(name))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt group name: %w", err)
	}

	reqData := map[string]interface{}{
		"name":     name, // Server needs plaintext to compute GroupID = HMAC(Owner:Name)
		"enc_name": encName,
		"enc_key":  pk,
		"lockbox":  lb,
	}

	data, _ := json.Marshal(reqData)
	url := c.metaURL + "/v1/group/"
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create group failed: %d %s", resp.StatusCode, string(b))
	}

	var created metadata.Group
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) AddUserToGroup(groupID, userID string) error {
	group, err := c.GetGroup(groupID)
	if err != nil {
		return err
	}

	// We need the user's public key.
	// We need a GET /v1/user/{id} API.
	user, err := c.GetUser(userID)
	if err != nil {
		return err
	}

	// Decrypt group private key using our identity
	gk, err := c.GetGroupPrivateKey(groupID)
	if err != nil {
		return err
	}
	priv := crypto.MarshalDecapsulationKey(gk)

	// Add new member to lockbox
	userEK, err := crypto.UnmarshalEncapsulationKey(user.EncKey)
	if err != nil {
		return err
	}
	if err := group.Lockbox.AddRecipient(userID, userEK, priv); err != nil {
		return err
	}

	group.Members[userID] = true

	data, _ := json.Marshal(group)
	req, err := http.NewRequest("PUT", c.metaURL+"/v1/group/"+groupID, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err := c.authenticateRequest(req); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update group failed: %d %s", resp.StatusCode, string(b))
	}

	return nil
}

func (c *Client) GetUser(id string) (*metadata.User, error) {
	req, err := http.NewRequest("GET", c.metaURL+"/v1/user/"+id, nil)
	if err != nil {
		return nil, err
	}
	if err := c.authenticateRequest(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user failed: %d", resp.StatusCode)
	}

	var user metadata.User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (c *Client) SetAttr(path string, attr metadata.SetAttrRequest) error {
	inode, key, err := c.ResolvePath(path)
	if err != nil {
		return err
	}
	return c.SetAttrByID(inode, key, attr)
}

func (c *Client) SetAttrByID(inode *metadata.Inode, key []byte, attr metadata.SetAttrRequest) error {
	var err error
	// 1. Handle Cryptographic Access (World & Group)
	if attr.Mode != nil || attr.GroupID != nil {
		oldMode := inode.Mode
		newMode := inode.Mode
		if attr.Mode != nil {
			newMode = *attr.Mode
		}

		oldGroupID := inode.GroupID
		newGroupID := inode.GroupID
		if attr.GroupID != nil {
			newGroupID = *attr.GroupID
		}

		worldReadOld := (oldMode & 0004) != 0
		worldReadNew := (newMode & 0004) != 0

		groupRWOld := (oldMode & 0060) != 0
		groupRWNew := (newMode & 0060) != 0

		groupChanged := oldGroupID != newGroupID

		updated := false
		if worldReadOld != worldReadNew {
			if worldReadNew {
				wpk, err := c.GetWorldPublicKey()
				if err != nil {
					return err
				}
				if err := inode.Lockbox.AddRecipient(metadata.WorldID, wpk, key); err != nil {
					return err
				}
			} else {
				delete(inode.Lockbox, metadata.WorldID)
			}
			updated = true
		}

		if (groupRWOld != groupRWNew || groupChanged) && newGroupID != "" {
			if groupRWNew {
				group, err := c.GetGroup(newGroupID)
				if err == nil {
					gk, _ := crypto.UnmarshalEncapsulationKey(group.EncKey)
					if err := inode.Lockbox.AddRecipient(newGroupID, gk, key); err != nil {
						return err
					}
					updated = true
				}
			} else {
				delete(inode.Lockbox, newGroupID)
				updated = true
			}
		} else if groupRWNew && oldGroupID != "" && groupChanged {
			// Remove old group from lockbox if it was there
			delete(inode.Lockbox, oldGroupID)
			updated = true
		}

		if updated {
			// Update the full Inode to persist Lockbox change
			inode.Mode = newMode
			inode.GroupID = newGroupID
			_, err = c.updateInode(*inode)
			if err != nil {
				return err
			}
		}
	}

	// 2. Push remaining attributes to FSM SetAttr handler
	attr.InodeID = inode.ID
	var data []byte
	data, err = json.Marshal(attr)
	if err != nil {
		return err
	}

	var hReq *http.Request
	hReq, err = http.NewRequest("POST", c.metaURL+"/v1/meta/setattr", bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err = c.authenticateRequest(hReq); err != nil {
		return err
	}
	hReq.Header.Set("Content-Type", "application/json")

	var resp *http.Response
	resp, err = c.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
	}

	return nil
}

func (c *Client) Remove(path string) error {
	inode, _, err := c.ResolvePath(path)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("DELETE", c.metaURL+"/v1/meta/inode/"+inode.ID, nil)
	if err != nil {
		return err
	}
	if err := c.authenticateRequest(req); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
	}
	return nil
}
