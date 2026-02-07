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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type Client struct {
	metaURL    string
	dataURL    string
	httpClient *http.Client
	userID     string
	decKey     *mlkem.DecapsulationKey768
}

func NewClient(metaAddr, dataAddr string) *Client {
	return &Client{
		metaURL:    metaAddr,
		dataURL:    dataAddr,
		httpClient: &http.Client{},
	}
}

func (c *Client) WithIdentity(userID string, key *mlkem.DecapsulationKey768) *Client {
	c2 := *c
	c2.userID = userID
	c2.decKey = key
	return &c2
}

func (c *Client) allocateNodes() ([]metadata.Node, error) {
	resp, err := c.httpClient.Post(c.metaURL+"/v1/meta/allocate", "", nil)
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
	// Not fully implemented until Client Auth is ready.
	return "", fmt.Errorf("not implemented")
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

func (c *Client) createInode(inode metadata.Inode) error {
	data, err := json.Marshal(inode)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.metaURL+"/v1/meta/inode", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create inode failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) getInode(id string) (*metadata.Inode, error) {
	resp, err := c.httpClient.Get(c.metaURL + "/v1/meta/inode/" + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get inode failed: %d", resp.StatusCode)
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
	resp, err := c.httpClient.Post(c.metaURL+"/v1/meta/inodes", "application/json", bytes.NewReader(body))
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
	// For now, we continue to use the old flow without tokens because IssueToken requires Client Auth which is not implemented.
	// I've updated uploadChunk to accept token, passing "" for now.
	
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

			nodes, err := c.allocateNodes()
			if err != nil {
				if c.dataURL != "" {
					nodes = []metadata.Node{{Address: c.dataURL}}
				} else {
					return fmt.Errorf("allocation failed: %v", err)
				}
			}

			if err := c.uploadChunk(cid, ct, nodes, ""); err != nil {
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

	lb := crypto.NewLockbox()
	if c.decKey != nil {
		if err := lb.AddRecipient(c.userID, c.decKey.EncapsulationKey(), fileKey); err != nil {
			return err
		}
	}

	inode := metadata.Inode{
		ID:            id,
		Type:          iType,
		Size:          uint64(len(data)),
		ChunkManifest: chunkEntries,
		Lockbox:       lb,
		EncryptedName: encryptedName,
		OwnerID:       c.userID, // Set Owner!
	}
	return c.createInode(inode)
}

// WriteFile writes a file. Returns the FileKey used.
func (c *Client) WriteFile(id string, data []byte) ([]byte, error) {
	fileKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
		return nil, err
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
}

func (c *Client) NewReader(id string, fileKey []byte) (*FileReader, error) {
	inode, err := c.getInode(id)
	if err != nil {
		return nil, err
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
	}
	
	// Issue Token logic pending Client Auth.
	token := ""

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
			ct, err := r.client.downloadChunk(chunkEntry.ID, r.token)
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