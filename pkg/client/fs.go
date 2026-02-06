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
	"fmt"
	"io/fs"
	"time"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type DistFS struct {
	client *Client
}

func (c *Client) FS() *DistFS {
	return &DistFS{client: c}
}

func (d *DistFS) Open(name string) (fs.File, error) {
	// Try to open reader using client identity
	r, err := d.client.NewReader(name, nil)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	inode := r.Stat()
	if inode.Type == metadata.DirType {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fmt.Errorf("is a directory")}
	}

	return &DistFile{reader: r}, nil
}

type DistFile struct {
	reader *FileReader
}

func (f *DistFile) Stat() (fs.FileInfo, error) {
	return &DistFileInfo{inode: f.reader.Stat()}, nil
}

func (f *DistFile) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *DistFile) Close() error {
	return nil
}

type DistFileInfo struct {
	inode *metadata.Inode
}

func (i *DistFileInfo) Name() string       { return i.inode.ID }
func (i *DistFileInfo) Size() int64        { return int64(i.inode.Size) }
func (i *DistFileInfo) Mode() fs.FileMode  { return fs.FileMode(i.inode.Mode) }
func (i *DistFileInfo) ModTime() time.Time { return time.Now() }
func (i *DistFileInfo) IsDir() bool        { return i.inode.Type == metadata.DirType }
func (i *DistFileInfo) Sys() any           { return i.inode }