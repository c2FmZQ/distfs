package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "web-test-server",
		Usage: "Static web server for DistFS testing",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "addr", Value: ":8091", Usage: "HTTP network address"},
			&cli.StringFlag{Name: "dir", Value: "web", Usage: "Directory to serve"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			addr := cmd.String("addr")
			dir := cmd.String("dir")

			absDir, err := filepath.Abs(dir)
			if err != nil {
				return fmt.Errorf("invalid directory: %w", err)
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

			log.Printf("Starting web server on %s, serving %s", addr, absDir)
			return http.ListenAndServe(addr, mux)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
