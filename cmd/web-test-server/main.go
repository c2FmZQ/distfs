package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
)

// A custom file system handler that intercepts requests and correctly
// serves Javascript files, ensuring the correct Content-Type is set.
type wasmFileSystem struct {
	fs http.FileSystem
}

func (wfs wasmFileSystem) Open(name string) (http.File, error) {
	return wfs.fs.Open(name)
}

func main() {
	addr := flag.String("addr", ":8091", "HTTP network address")
	dir := flag.String("dir", "web", "Directory to serve")
	flag.Parse()

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("Invalid directory: %v", err)
	}

	fs := http.FileServer(wasmFileSystem{http.Dir(absDir)})

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set headers for WASM and Service Worker to function correctly
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		if filepath.Ext(r.URL.Path) == ".wasm" {
			w.Header().Set("Content-Type", "application/wasm")
		}
		fs.ServeHTTP(w, r)
	}))

	log.Printf("Starting web test server on %s, serving %s", *addr, absDir)
	err = http.ListenAndServe(*addr, mux)
	if err != nil {
		log.Fatal(err)
	}
}
