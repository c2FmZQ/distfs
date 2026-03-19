//go:build pprof

package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func startPprofServer() {
	go func() {
		log.Println("Starting pprof server on :6060")
		if err := http.ListenAndServe("0.0.0.0:6060", nil); err != nil {
			log.Printf("pprof server error: %v", err)
		}
	}()
}
