// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/metadata"
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

func TestClient_ReadDataFiles_BlocksExclusive(t *testing.T) {
	c, metaNode, metaServer, ts := SetupTestClient(t)
	defer metaNode.Shutdown()
	defer metaServer.Shutdown()
	defer ts.Close()

	ctx := context.Background()

	path := "/locked.json"
	c.SaveDataFile(ctx, path, map[string]string{"data": "initial"})

	// 1. Acquire a shared lease manually to simulate a long ReadDataFiles phase
	nonce := "test-nonce"
	err := c.AcquireLeases(ctx, []string{path}, 5*time.Second, nil, metadata.LeaseShared, nonce)
	if err != nil {
		t.Fatalf("AcquireLeases failed: %v", err)
	}

	// 2. Try to SaveDataFile using a DIFFERENT client instance (same user, different session)
	c2 := createExtraClient(t, ts, metaNode, c)
	saveDone := make(chan error, 1)
	go func() {
		saveDone <- c2.SaveDataFile(ctx, path, map[string]string{"data": "updated"})
	}()

	// 3. Verify it's blocked
	select {
	case err := <-saveDone:
		t.Fatalf("SaveDataFile should have been blocked by Shared lease, but returned err=%v", err)
	case <-time.After(500 * time.Millisecond):
		// Good, it's blocked
	}

	// 4. Release the shared lease
	c.ReleaseLeases(ctx, []string{path}, nonce)

	// 5. Verify SaveDataFile completes
	select {
	case err := <-saveDone:
		if err != nil {
			t.Errorf("SaveDataFile failed after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("SaveDataFile timed out after lease release")
	}
}
