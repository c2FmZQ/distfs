//go:build !wasm

package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
)

func TestClient_Stress_Reproducer(t *testing.T) {
	// 1. Setup Client
	adminC, node, _, ts, adminID, adminSK := setupTestClient(t)
	ctx := context.Background()

	// 2. Provision stress-user
	c, _, _ := provisionUser(t, ts, node, adminC, adminID, adminSK, "stress-user")

	// Create user directory with correct ownership
	if err := adminC.MkdirExtended(ctx, "/users/stress-user", 0700, MkdirOptions{
		OwnerID: "stress-user",
	}); err != nil {
		t.Fatalf("Admin MkdirExtended failed: %v", err)
	}

	// 3. Run Concurrent Workers
	const numWorkers = 10
	var wg sync.WaitGroup
	errs := make(chan error, numWorkers)

	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			path := fmt.Sprintf("/users/stress-user/file-%d", id)
			data := []byte(fmt.Sprintf("worker-%d data", id))

			// UPLOAD
			err := c.withConflictRetry(ctx, func() error {
				w, err := c.OpenBlobWrite(ctx, path)
				if err != nil {
					return err
				}
				if _, err := w.Write(data); err != nil {
					if fw, ok := w.(*FileWriter); ok {
						fw.Abort()
					}
					return err
				}
				return w.Close()
			})
			if err != nil {
				errs <- fmt.Errorf("worker %d upload failed: %v", id, err)
				return
			}

			// DOWNLOAD
			r, err := c.OpenBlobRead(ctx, path)
			if err != nil {
				errs <- fmt.Errorf("worker %d download failed: %v", id, err)
				return
			}
			got, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				errs <- fmt.Errorf("worker %d read failed: %v", id, err)
				return
			}

			if !bytes.Equal(got, data) {
				errs <- fmt.Errorf("worker %d integrity check failed: expected %q, got %q", id, string(data), string(got))
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
