// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestClient_ReadDataFiles_Consistency(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()

	// 1. Prepare two files that must be read consistently
	type Config struct {
		Version int    `json:"version"`
		Secret  string `json:"secret"`
	}

	path1 := "/config.json"
	path2 := "/secret.json"

	cfg1 := Config{Version: 1, Secret: "secret-1"}
	sec1 := Config{Version: 1, Secret: "key-1"}

	if err := c.SaveDataFiles(ctx, []string{path1, path2}, []any{cfg1, sec1}); err != nil {
		t.Fatalf("Initial save failed: %v", err)
	}

	// 2. Start a goroutine that rapidly updates both files atomically
	// Use a DIFFERENT client instance to ensure lease conflicts
	cWriter := createExtraClient(t, ts, metaNode, c)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		version := 2
		for {
			select {
			case <-stop:
				return
			default:
				cfg := Config{Version: version, Secret: fmt.Sprintf("secret-%d", version)}
				sec := Config{Version: version, Secret: fmt.Sprintf("key-%d", version)}
				if err := cWriter.SaveDataFiles(ctx, []string{path1, path2}, []any{cfg, sec}); err != nil {
					// Conflicts are expected, SaveDataFiles should handle retries but if it fails we just continue
				}
				version++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// 3. Perform many atomic reads and verify consistency
	for i := 0; i < 10; i++ {
		var rCfg, rSec Config
		if err := c.ReadDataFiles(ctx, []string{path1, path2}, []any{&rCfg, &rSec}); err != nil {
			t.Errorf("ReadDataFiles failed at iteration %d: %v", i, err)
			continue
		}

		if rCfg.Version != rSec.Version {
			t.Errorf("Inconsistency detected at iteration %d: Config Version %d != Secret Version %d", i, rCfg.Version, rSec.Version)
		}
	}

	close(stop)
	wg.Wait()
}
