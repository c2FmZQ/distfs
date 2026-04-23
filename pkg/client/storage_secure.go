// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// SecureKVStore wraps a KVStore and encrypts/decrypts values using AES-256-GCM.
type SecureKVStore struct {
	store KVStore
	block cipher.Block
}

func NewSecureKVStore(store KVStore, key []byte) (*SecureKVStore, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secure storage: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &SecureKVStore{
		store: store,
		block: block,
	}, nil
}

func (s *SecureKVStore) Get(bucket, key string) ([]byte, error) {
	ciphertext, err := s.store.Get(bucket, key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("secure storage: ciphertext too short")
	}

	aesgcm, err := cipher.NewGCM(s.block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:12]
	data, err := aesgcm.Open(nil, nonce, ciphertext[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("secure storage: decryption failed: %w", err)
	}

	return data, nil
}

func (s *SecureKVStore) Put(bucket, key string, value []byte) error {
	aesgcm, err := cipher.NewGCM(s.block)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, value, nil)
	return s.store.Put(bucket, key, ciphertext)
}

func (s *SecureKVStore) Delete(bucket, key string) error {
	return s.store.Delete(bucket, key)
}

func (s *SecureKVStore) Close() error {
	return s.store.Close()
}
