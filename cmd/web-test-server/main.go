package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
)

func main() {
	addr := flag.String("addr", ":8091", "HTTP network address")
	dir := flag.String("dir", "web", "Directory to serve")
	flag.Parse()

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("Invalid directory: %v", err)
	}

	fs := http.FileServer(http.Dir(absDir))

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set WASM content type if needed
		if filepath.Ext(r.URL.Path) == ".wasm" {
			w.Header().Set("Content-Type", "application/wasm")
		}
		fs.ServeHTTP(w, r)
	}))

	log.Printf("Starting web server on %s, serving %s", *addr, absDir)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
