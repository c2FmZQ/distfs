//go:build pprof

// Copyright 2026 TTBT Enterprises LLC
package debug

import (
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
)

// RegisterHandlers registers pprof handlers to the provided mux.
func RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// StartServer starts a standalone pprof server on the specified port.
func StartServer(port int) {
	go func() {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		log.Printf("Starting pprof server on %s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("pprof server error: %v", err)
		}
	}()
}
