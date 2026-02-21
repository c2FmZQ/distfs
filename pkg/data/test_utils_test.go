// Copyright 2026 TTBT Enterprises LLC
package data

import (
	"testing"

	"encoding/base64"
	"encoding/json"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"time"
)

func createTestStorage(t *testing.T, dir string) (*storage.Storage, storage_crypto.MasterKey) {
	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(dir, mk)
	return st, mk
}

func setupTestAuth(t *testing.T) ([]byte, *crypto.IdentityKey) {
	sk, err := crypto.GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk.Public(), sk
}

func signTestToken(t *testing.T, sk *crypto.IdentityKey, chunks []string, mode string) string {
	capToken := metadata.CapabilityToken{
		Chunks: chunks,
		Mode:   mode,
		Exp:    time.Now().Add(time.Hour).Unix(),
	}
	payload, _ := json.Marshal(capToken)
	sig := sk.Sign(payload)
	signed := metadata.SignedAuthToken{
		Payload:   payload,
		Signature: sig,
	}
	b, _ := json.Marshal(signed)
	return "Bearer " + base64.StdEncoding.EncodeToString(b)
}
