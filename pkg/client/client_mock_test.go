//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type mockRoundTripper struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

func TestClient_MockedErrors(t *testing.T) {
	ctx := context.Background()

	sk, _ := crypto.GenerateIdentityKey()
	dk, _ := crypto.GenerateEncryptionKey()
	c := NewClient("http://mock").withSignKey(sk).withIdentity("u1", dk)

	c.httpCli.Transport = &mockRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewReader([]byte("server error"))),
			}, nil
		},
	}

	_, err := c.applyBatch(ctx, []metadata.LogCommand{{Type: metadata.CmdCreateInode}})
	if err == nil {
		t.Error("Expected error from ApplyBatch")
	}

	nonce := metadata.GenerateNonce()
	inodeID := metadata.GenerateInodeID("u1", nonce)

	_, err = c.getInode(ctx, inodeID)
	if err == nil {
		t.Error("Expected error from getInode")
	}

	_, err = c.updateInode(ctx, inodeID, func(i *metadata.Inode) error { return nil })
	if err == nil {
		t.Error("Expected error from updateInode")
	}
}

func TestClient_MockedRetry(t *testing.T) {
	ctx := context.Background()
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	c := NewClient("http://mock").withServerKey(dk.EncapsulationKey()).withSignKey(sk).withIdentity("u1", dk)

	attempts := 0
	c.httpCli.Transport = &mockRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/v1/auth/challenge" {
				chal := make([]byte, 32)
				sig := sk.Sign(chal)
				res := metadata.AuthChallengeResponse{Challenge: chal, Signature: sig}
				b, _ := json.Marshal(res)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b))}, nil
			}
			if req.URL.Path == "/v1/login" {
				res := metadata.SessionResponse{Token: "fake-token"}
				b, _ := json.Marshal(res)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b))}, nil
			}
			if req.URL.Path == "/v1/meta/key/sign" {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(sk.Public()))}, nil
			}

			attempts++
			if attempts < 3 {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Body:       io.NopCloser(bytes.NewReader([]byte("retry me"))),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte("[]"))),
			}, nil
		},
	}

	_, err := c.allocateNodes(ctx)
	if err != nil {
		t.Errorf("allocateNodes failed after retries: %v", err)
	}
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestClient_MockedConflict(t *testing.T) {
	ctx := context.Background()
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	serverDK, _ := crypto.GenerateEncryptionKey()
	c := NewClient("http://mock").withServerKey(serverDK.EncapsulationKey()).withSignKey(sk).withIdentity("u1", dk).WithAdmin(true).WithRegistry("")

	nonce := metadata.GenerateNonce()
	inodeID := metadata.GenerateInodeID("u1", nonce)

	// Pre-login to avoid login logic in mock
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}
	c.sessionToken = "fake"
	c.sessionKey = sessionKey
	c.sessionExpiry = time.Now().Add(time.Hour)

	attempts := 0
	c.httpCli.Transport = &mockRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.Method == "GET" && strings.Contains(req.URL.Path, "/v1/user/") {
				res := metadata.User{ID: "u1", SignKey: sk.Public()}
				b, _ := json.Marshal(res)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(b)),
				}, nil
			}

			if req.Method == "POST" && req.URL.Path == "/v1/invoke" {
				// Unseal to identify action
				body, _ := io.ReadAll(req.Body)
				var sr metadata.SealedRequest
				if err := json.Unmarshal(body, &sr); err != nil {
					return nil, err
				}

				var payload []byte
				var err error
				if req.Header.Get("Session-Token") != "" {
					_, payload, _, err = crypto.OpenRequestSymmetric(sessionKey, sk.Public(), sr.Sealed)
				} else {
					_, payload, _, _, err = crypto.OpenRequest(serverDK, sk.Public(), sr.Sealed)
				}
				if err != nil {
					return nil, err
				}
				var env metadata.SealedEnvelope
				if err := json.Unmarshal(payload, &env); err != nil {
					return nil, err
				}

				if env.Action == metadata.ActionGetUser {
					res := metadata.User{ID: "u1", SignKey: sk.Public()}
					b, _ := json.Marshal(res)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(b)),
					}, nil
				}

				if env.Action == metadata.ActionGetInode {
					// Create a valid inode with ClientBlob and Lockbox
					fileKey := make([]byte, 32)
					inode := metadata.Inode{
						ID:      inodeID,
						Nonce:   nonce,
						Version: 1,
						Type:    metadata.FileType,
						OwnerID: "u1",
						Lockbox: make(crypto.Lockbox),
					}
					inode.Lockbox.AddRecipient("u1", dk.EncapsulationKey(), fileKey, 0)

					blob := metadata.InodeClientBlob{
						MTime: time.Now().UnixNano(),
					}
					plainBlob, _ := json.Marshal(blob)
					encBlob, _ := crypto.EncryptDEM(fileKey, plainBlob)
					inode.ClientBlob = encBlob

					// Also set transient fields for ManifestHash calculation during signing
					inode.SetSignerID("u1")
					inode.SignInodeForTest("u1", sk)

					b, _ := json.Marshal(inode)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(b)),
					}, nil
				}

				if env.Action == metadata.ActionBatch {
					if attempts < 2 {
						attempts++
						return &http.Response{
							StatusCode: http.StatusConflict,
							Body:       io.NopCloser(bytes.NewReader([]byte(`{"code":"DISTFS_VERSION_CONFLICT"}`))),
						}, nil
					}

					// Return a successful batch response after 2 attempts
					attempts++
					// For tests, use the SAME inodeID but incremented version
					u1ID := "u1"
					updatedInode := metadata.Inode{ID: inodeID, Nonce: nonce, Version: 2, Type: metadata.FileType, OwnerID: u1ID}
					updatedInode.SignInodeForTest("u1", sk)
					ib, _ := json.Marshal(updatedInode)
					batchRes := []json.RawMessage{ib}
					bb, _ := json.Marshal(batchRes)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(bb)),
					}, nil
				}
			}

			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewReader([]byte("not found"))),
			}, nil
		},
	}

	_, err := c.updateInode(ctx, inodeID, func(i *metadata.Inode) error {
		return nil
	})
	if err != nil {
		t.Errorf("updateInode should have succeeded after retries, got: %v", err)
	}
	if attempts < 2 {
		t.Errorf("Expected multiple attempts, got %d", attempts)
	}
}

func TestClient_MockedUnsealError(t *testing.T) {
	ctx := context.Background()
	dk, _ := crypto.GenerateEncryptionKey()
	sk, _ := crypto.GenerateIdentityKey()
	c := NewClient("http://mock").withServerKey(dk.EncapsulationKey()).withSignKey(sk).withIdentity("u1", dk)

	c.httpCli.Transport = &mockRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"X-DistFS-Sealed": []string{"true"}},
				Body:       io.NopCloser(bytes.NewReader([]byte("not-json"))),
			}, nil
		},
	}

	_, err := c.allocateNodes(ctx)
	if err == nil {
		t.Error("Expected unseal error")
	}
}
