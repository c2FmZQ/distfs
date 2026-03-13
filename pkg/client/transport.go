//go:build !wasm

package client

import (
	"net/http"
	"strings"

	"github.com/c2FmZQ/ech"
)

func getDefaultTransport(serverAddr string) http.RoundTripper {
	if strings.HasPrefix(serverAddr, "http://") {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.ForceAttemptHTTP2 = true
		t.MaxIdleConns = 100
		t.MaxIdleConnsPerHost = 100
		return t
	}
	echTransport := ech.NewTransport()
	echTransport.HTTPTransport.MaxIdleConns = 100
	echTransport.HTTPTransport.MaxIdleConnsPerHost = 100
	return echTransport
}

func applyDisableDoH(transport http.RoundTripper, disable bool) http.RoundTripper {
	if t, ok := transport.(*ech.Transport); ok {
		t2 := *t
		if disable {
			t2.Resolver = ech.InsecureGoResolver()
		} else {
			t2.Resolver = ech.DefaultResolver
		}
		return &t2
	}
	return transport
}
