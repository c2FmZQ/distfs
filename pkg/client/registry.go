// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"encoding/binary"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

// DirectoryEntry represents a signed identity attestation in the DistFS registry.
type DirectoryEntry struct {
	Username   string `json:"username"`
	FullName   string `json:"full_name"`
	UserID     string `json:"uid"`
	EncKey     []byte `json:"ek"` // ML-KEM Public Key
	SignKey    []byte `json:"sk"` // ML-DSA Public Key
	HomeDir    string `json:"home_dir,omitempty"`
	VerifierID string `json:"verifier_id"`
	Timestamp  int64  `json:"ts"`
	Signature  []byte `json:"sig"` // Signature by Verifier over all other fields
}

// Hash returns a deterministic cryptographic commitment of the directory entry.
func (e *DirectoryEntry) Hash() []byte {
	h := crypto.NewHash()
	h.Write([]byte(e.Username))
	h.Write([]byte("|"))
	h.Write([]byte(e.FullName))
	h.Write([]byte("|"))
	h.Write([]byte(e.UserID))
	h.Write([]byte("|"))
	h.Write(e.EncKey)
	h.Write([]byte("|"))
	h.Write(e.SignKey)
	h.Write([]byte("|"))
	h.Write([]byte(e.HomeDir))
	h.Write([]byte("|"))
	h.Write([]byte(e.VerifierID))
	h.Write([]byte("|"))
	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, uint64(e.Timestamp))
	h.Write(v)
	return h.Sum(nil)
}

func (e *DirectoryEntry) VerifySignature(verifierPubKey []byte) bool {
	if len(e.Signature) == 0 {
		return false
	}
	return crypto.VerifySignature(verifierPubKey, e.Hash(), e.Signature)
}

// GroupDirectoryEntry represents a signed group identity record in /registry.
type GroupDirectoryEntry struct {
	GroupName   string `json:"group_name"`
	GroupID     string `json:"group_id"`
	OwnerID     string `json:"owner_id"`
	EncKey      []byte `json:"ek"` // ML-KEM Public Key
	SignKey     []byte `json:"sk"` // ML-DSA Public Key
	VerifierID  string `json:"verifier_id"`
	Attestation []byte `json:"attestation"` // Signed by VerifierID
}

// Hash calculates a cryptographic hash of the entry for signing.
func (e *GroupDirectoryEntry) Hash() []byte {
	h := crypto.NewHash()
	h.Write([]byte("DistFS-GroupEntry-v1|"))
	h.Write([]byte("name:" + e.GroupName + "|"))
	h.Write([]byte("id:" + e.GroupID + "|"))
	h.Write([]byte("owner:" + e.OwnerID + "|"))
	h.Write([]byte("ek:"))
	h.Write(e.EncKey)
	h.Write([]byte("|"))
	h.Write([]byte("sk:"))
	h.Write(e.SignKey)
	h.Write([]byte("|"))
	h.Write([]byte("verifier:" + e.VerifierID + "|"))
	return h.Sum(nil)
}

// VerifyAttestation confirms the entry's integrity using the verifier's public key.
func (e *GroupDirectoryEntry) VerifyAttestation(verifierPubKey []byte) bool {
	if len(e.Attestation) == 0 {
		return false
	}
	return crypto.VerifySignature(verifierPubKey, e.Hash(), e.Attestation)
}
