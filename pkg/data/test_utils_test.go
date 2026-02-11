// Copyright 2026 TTBT Enterprises LLC
package data

import (
	"testing"

	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
)

func createTestStorage(t *testing.T, dir string) (*storage.Storage, storage_crypto.MasterKey) {
	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(dir, mk)
	return st, mk
}
