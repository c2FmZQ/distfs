//go:build !wasm && !debug

package metadata

import (
	"net/http"
)

func (s *Server) handleDebugRoutes(w http.ResponseWriter, r *http.Request) bool {
	return false
}
