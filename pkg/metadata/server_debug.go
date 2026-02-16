//go:build debug

package metadata

import (
	"log"
	"net/http"
	"os"
	"time"
)

func (s *Server) handleDebugRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/api/debug/suicide" && r.Method == http.MethodPost {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return true
		}
		s.handleSuicide(w, r)
		return true
	}

	if r.URL.Path == "/api/debug/scrub" && r.Method == http.MethodPost {
		if !s.checkRaftSecret(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return true
		}
		s.ForceReplicationScan()
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

func (s *Server) handleSuicide(w http.ResponseWriter, r *http.Request) {
	log.Printf("CRITICAL: Suicide requested via debug API")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Goodbye cruel world\n"))
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(1)
	}()
}
