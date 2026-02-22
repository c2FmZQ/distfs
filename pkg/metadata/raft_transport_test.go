// Copyright 2026 TTBT Enterprises LLC
package metadata

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestTLSStreamLayer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := &NodeKey{Pub: pub, Priv: priv}
	cert, _ := GenerateSelfSignedCert(key)
	tlsConfig := NewServerTLSConfig(cert, func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return nil
	})

	sl, err := NewTLSStreamLayer("127.0.0.1:0", nil, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()

	addr := sl.Addr().String()

	// Dial in background
	errCh := make(chan error, 1)
	go func() {
		conn, err := sl.Dial(raft.ServerAddress(addr), 1*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
		errCh <- nil
	}()

	// Accept
	conn, err := sl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	conn.Read(buf)
	if string(buf) != "hello" {
		t.Errorf("Unexpected message: %s", buf)
	}
	conn.Close()

	if err := <-errCh; err != nil {
		t.Errorf("Dial failed: %v", err)
	}
}
