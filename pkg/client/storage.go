// Copyright 2026 TTBT Enterprises LLC
package client

import "errors"

var (
	ErrNotFound = errors.New("storage: key not found")
	ErrClosed   = errors.New("storage: store is closed")
)

// KVStore defines a unified interface for persistent caching across native and WASM platforms.
type KVStore interface {
	// Get retrieves the encrypted value for a given key in a bucket.
	Get(bucket, key string) ([]byte, error)

	// Put stores an encrypted value for a given key in a bucket.
	Put(bucket, key string, value []byte) error

	// Delete removes a key from a bucket.
	Delete(bucket, key string) error

	// Close closes the store.
	Close() error
}
