//go:build wasm

package client

import (
	"net/http"
)

func getDefaultTransport(serverAddr string) http.RoundTripper {
	return http.DefaultTransport
}

func applyDisableDoH(transport http.RoundTripper, disable bool) http.RoundTripper {
	// DoH and ECH are handled natively by the browser in WASM/Fetch
	return transport
}

func applyAllowInsecure(transport http.RoundTripper, allow bool) http.RoundTripper {
	// TLS verification is handled natively by the browser in WASM/Fetch
	return transport
}
