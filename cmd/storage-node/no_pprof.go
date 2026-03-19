//go:build !pprof

package main

import (
	"net/http"
)

func registerDebugHandlers(mux *http.ServeMux) {
	// No-op when pprof tag is not present
}
