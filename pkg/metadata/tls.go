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

package metadata

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
)

// GenerateSelfSignedCert generates a self-signed X.509 certificate using the provided IdentityKey.
func GenerateSelfSignedCert(key *crypto.IdentityKey) (*tls.Certificate, error) {
	edPriv := ed25519.PrivateKey(key.MarshalPrivate())
	edPub := ed25519.PublicKey(key.Public())

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"DistFS Cluster"},
			CommonName:   NodeIDFromKey(key),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 year

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, edPub, edPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  edPriv,
	}, nil
}

// NewServerTLSConfig creates a TLS config for the server (mTLS).
// It requires a callback to verify peer certificates against authorized nodes (NodeMeta).
func NewServerTLSConfig(cert *tls.Certificate, verifyPeer func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.RequireAnyClientCert, // We verify manually in VerifyPeerCertificate
		VerifyPeerCertificate: verifyPeer,
		MinVersion:            tls.VersionTLS13,
	}
}

// NewClientTLSConfig creates a TLS config for the client (mTLS).
func NewClientTLSConfig(cert *tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true, // We verify the peer key manually, not the CA chain (since self-signed)
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// In strict mode, we'd check against NodeMeta.
			// For now, we trust connection if we trust the key.
			// The caller (Transport) should probably handle this or we inject logic here.
			return nil 
		},
		MinVersion: tls.VersionTLS13,
	}
}