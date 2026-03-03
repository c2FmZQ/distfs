// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestTLS_Configs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := &NodeKey{Pub: pub, Signer: priv}
	cert, err := GenerateSelfSignedCert(key)
	if err != nil {
		t.Fatal(err)
	}

	// Server Config
	sConfig := NewServerTLSConfig(cert, func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return nil
	})
	if sConfig.ClientAuth != tls.RequireAnyClientCert {
		t.Error("Wrong client auth mode")
	}
	if len(sConfig.Certificates) != 1 {
		t.Error("Missing cert")
	}

	// Client Config
	cConfig := NewClientTLSConfig(cert, nil)
	if cConfig.InsecureSkipVerify {
		t.Error("Client config should not skip verify by default")
	}

	cConfig2 := NewClientTLSConfig(cert, func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return nil
	})
	if !cConfig2.InsecureSkipVerify {
		t.Error("Client config should skip verify when custom verifier is provided")
	}
}
