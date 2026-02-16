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

package data

import (
	"io"
	"iter"
)

// Store defines the interface for the raw chunk storage layer.
type Store interface {
	// WriteChunk writes the data to the store using the given ID.
	// It must be atomic (all or nothing).
	WriteChunk(id string, data io.Reader) error

	// ReadChunk returns a reader for the chunk data.
	// The caller must close the reader.
	ReadChunk(id string) (io.ReadCloser, error)

	// HasChunk returns true if the chunk exists.
	HasChunk(id string) (bool, error)

	// GetChunkSize returns the size of the chunk in bytes.
	GetChunkSize(id string) (int64, error)

	// DeleteChunk removes the chunk.
	DeleteChunk(id string) error

	// ListChunks returns an iterator for all chunk IDs.
	ListChunks() iter.Seq2[string, error]

	// Stats returns total capacity and used space in bytes.
	Stats() (capacity int64, used int64, err error)
}
