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
}

func NewClient(metaAddr, dataAddr string) *Client {
	return &Client{
		metaURL:    metaAddr,
		dataURL:    dataAddr,
		httpClient: &http.Client{},
		keyCache:   make(map[string][]byte),
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

func (c *Client) authenticateRequest(req *http.Request) error {
	if c.signKey == nil || c.serverKey == nil {
		return fmt.Errorf("client keys (sign/server) not configured")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	token := metadata.AuthToken{
		UserID: c.userID,
		Time:   time.Now().Unix(),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
	}

	payload, err := json.Marshal(token)
	if err != nil {
		return err
	}

	sig := c.signKey.Sign(payload)
	signed := metadata.SignedAuthToken{
		Payload:   payload,
		Signature: sig,
	}

	signedBytes, err := json.Marshal(signed)
	if err != nil {
		return err
	}

	// Encrypt (KEM+DEM)
	ss, kemCT := crypto.Encapsulate(c.serverKey)
	demCT, err := crypto.EncryptDEM(ss, signedBytes)
	if err != nil {
		return err
	}

	// Token = KEM + DEM
	fullToken := append(kemCT, demCT...)
	tokenStr := base64.StdEncoding.EncodeToString(fullToken)

	req.Header.Set("Authorization", "Bearer "+tokenStr)
	return nil
}

func (c *Client) allocateNodes() ([]metadata.Node, error) {
	req, err := http.NewRequest("POST", c.metaURL+"/v1/meta/allocate", nil)
	if err != nil {
		return nil, err
	}
	c.authenticateRequest(req)

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
	c.authenticateRequest(req)
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
	c.authenticateRequest(req)
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
	c.authenticateRequest(req)

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
	c.authenticateRequest(req)
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

func (c *Client) writeInodeContent(id string, iType metadata.InodeType, fileKey []byte, data []byte, encryptedName []byte) error {
	lb := crypto.NewLockbox()
	if c.decKey != nil {
		if err := lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), fileKey); err != nil {
			return err
		}
	}

	var inode metadata.Inode
	// Try to get existing inode
	existing, err := c.getInode(id)
	if err == nil {
		inode = *existing
		// We preserve existing ID, Owner, etc.
		// We will replace ChunkManifest and Size.
		inode.Lockbox = lb
		if encryptedName != nil {
			inode.EncryptedName = encryptedName
		}
	} else if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
		// Assume not found, create new
		inode = metadata.Inode{
			ID:            id,
			Type:          iType,
			Size:          uint64(len(data)),
			ChunkManifest: nil,
			Lockbox:       lb,
			EncryptedName: encryptedName,
			OwnerID:       c.userID,
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
	r := bytes.NewReader(data)
	buf := make([]byte, crypto.ChunkSize)

	for {
		n, err := r.Read(buf)
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
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	// Final update using updateInode (uses version check)
	inode.ChunkManifest = chunkEntries
	inode.Size = uint64(len(data))
	_, err = c.updateInode(inode)
	if err == nil {
		c.keyMu.Lock()
		c.keyCache[id] = fileKey
		c.keyMu.Unlock()
	}
	return err
}

// WriteFile writes a file. Returns the FileKey used.
func (c *Client) WriteFile(id string, data []byte) ([]byte, error) {
	c.keyMu.RLock()
	fileKey, ok := c.keyCache[id]
	c.keyMu.RUnlock()

	if !ok {
		if inode, err := c.GetInode(id); err == nil {
			if key, err := c.UnlockInode(inode); err == nil {
				fileKey = key
			}
		}
	}

	if fileKey == nil {
		fileKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
			return nil, err
		}
	}

	if err := c.writeInodeContent(id, metadata.FileType, fileKey, data, nil); err != nil {
		return nil, err
	}
	return fileKey, nil
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
	}, nil
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

		var pt []byte
		if chunkIdx == r.currentChunkIdx && r.currentChunk != nil {
			pt = r.currentChunk
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

func (c *Client) ReadFile(id string, fileKey []byte) ([]byte, error) {
	r, err := c.NewReader(id, fileKey)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
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
	return inode.Lockbox.GetFileKey(c.userID, c.decKey)
}
