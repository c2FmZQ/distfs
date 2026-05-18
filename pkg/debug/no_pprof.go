//go:build !pprof

// Copyright 2026 TTBT Enterprises LLC
package debug

import "net/http"

// RegisterHandlers is a no-op when pprof is not enabled.
func RegisterHandlers(mux *http.ServeMux) {}

// StartServer is a no-op when pprof is not enabled.
func StartServer(port int) {}
