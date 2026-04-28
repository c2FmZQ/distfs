// Copyright 2026 The DistFS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metadata

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestAIMDLimiter(t *testing.T) {
	limiter := NewConcurrencyLimiter(1, 10, 50*time.Millisecond)

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delay := r.URL.Query().Get("delay")
		if delay != "" {
			d, _ := time.ParseDuration(delay)
			time.Sleep(d)
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Initial limit is 10. Send 11 concurrent requests.
	done := make(chan int, 11)
	for i := 0; i < 11; i++ {
		go func(id int) {
			req := httptest.NewRequest("GET", "/?delay=100ms", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			done <- rr.Code
		}(i)
	}

	tooMany := 0
	ok := 0
	for i := 0; i < 11; i++ {
		code := <-done
		if code == http.StatusTooManyRequests {
			tooMany++
		} else if code == http.StatusOK {
			ok++
		}
	}

	if ok > 10 {
		t.Errorf("expected at most 10 OK requests, got %d", ok)
	}
	if tooMany == 0 {
		t.Errorf("expected at least one 429 response")
	}

	// 2. Simulate latency spike to trigger multiplicative decrease
	// Record enough latencies to trigger adjustment
	for i := 0; i < 20; i++ {
		limiter.recordLatency(100 * time.Millisecond)
	}
	// Force adjustment by moving time forward or waiting
	atomic.StoreInt64(&limiter.lastAdjustedNanos, time.Now().Add(-2*time.Second).UnixNano())
	limiter.recordLatency(100 * time.Millisecond)

	newLimit := atomic.LoadInt32(&limiter.currentLimit)
	if newLimit >= 10 {
		t.Errorf("expected limit to decrease, got %d", newLimit)
	}
}

func TestMaxDirectoryChildren(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "fsm-test-*")
	defer os.RemoveAll(tmpDir)

	fsm, _ := NewMetadataFSM("n1", tmpDir+"/db", []byte("secret"))
	defer fsm.Close()

	userID := "owner"
	sk, _ := crypto.GenerateIdentityKey()

	// Register user
	fsm.db.Update(func(tx *bolt.Tx) error {
		user := User{ID: userID, SignKey: sk.Public()}
		data, _ := json.Marshal(user)
		return fsm.Put(tx, []byte("users"), []byte(userID), data)
	})

	// 1. Create a directory with MaxDirectoryChildren entries.
	dirID := "00000000000000000000000000000001"
	children := make(map[string]ChildEntry)
	for i := 0; i < MaxDirectoryChildren; i++ {
		name := fmt.Sprintf("file-%d", i)
		children[name] = ChildEntry{ID: fmt.Sprintf("%032x", i+100)}
	}

	dir := Inode{
		ID:       dirID,
		Type:     DirType,
		Children: children,
		NLink:    1,
		IsRoot:   true,
		OwnerID:  userID,
		Version:  1,
	}
	dir.SignInodeForTest(userID, sk)

	fsm.db.Update(func(tx *bolt.Tx) error {
		data, _ := json.Marshal(dir)
		return fsm.Put(tx, []byte("inodes"), []byte(dirID), data)
	})

	// 2. Attempt to add one more child via executeUpdateInode
	dir.Children["one-too-many"] = ChildEntry{ID: "0000000000000000000000000000ffff"}
	dir.Version = 2
	dir.SignInodeForTest(userID, sk)
	data, _ := json.Marshal(dir)

	fsm.db.Update(func(tx *bolt.Tx) error {
		res := fsm.executeUpdateInode(tx, data, userID, "sess1", nil)
		if err, ok := res.(error); ok && err != nil {
			if !errors.Is(err, ErrStructuralInconsistency) {
				t.Errorf("expected ErrStructuralInconsistency, got %v", err)
			}
		} else {
			t.Errorf("expected update to fail due to MaxDirectoryChildren limit")
		}
		return nil
	})
}

func TestPendingBytesReservation(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "fsm-test-*")
	defer os.RemoveAll(tmpDir)

	fsm, _ := NewMetadataFSM("n1", tmpDir+"/db", []byte("secret"))
	defer fsm.Close()

	// 1. Create User with 10MB quota
	user := &User{
		ID:    "u1",
		Quota: UserQuota{MaxBytes: 10 * 1024 * 1024},
	}
	fsm.db.Update(func(tx *bolt.Tx) error {
		data, _ := json.Marshal(user)
		return fsm.Put(tx, []byte("users"), []byte("u1"), data)
	})

	// 2. Reserve 6MB
	req := QuotaReservationRequest{UserID: "u1", Bytes: 6 * 1024 * 1024}
	data, _ := json.Marshal(req)
	fsm.db.Update(func(tx *bolt.Tx) error {
		res := fsm.executeReservePendingBytes(tx, data)
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("reserve failed: %v", err)
		}
		return nil
	})

	// 3. Verify PendingBytes
	fsm.db.View(func(tx *bolt.Tx) error {
		plain, _ := fsm.Get(tx, []byte("users"), []byte("u1"))
		var u User
		json.Unmarshal(plain, &u)
		if u.Usage.PendingBytes != 6*1024*1024 {
			t.Errorf("expected 6MB pending, got %d", u.Usage.PendingBytes)
		}
		return nil
	})

	// 4. Try to reserve another 6MB -> should fail
	fsm.db.Update(func(tx *bolt.Tx) error {
		res := fsm.executeReservePendingBytes(tx, data)
		if err, ok := res.(error); ok && err != nil {
			if !errors.Is(err, ErrQuotaExceeded) {
				t.Errorf("expected ErrQuotaExceeded, got %v", err)
			}
		} else {
			t.Error("expected reservation to fail")
		}
		return nil
	})

	// 5. Commit 2MB of data
	fsm.db.Update(func(tx *bolt.Tx) error {
		fsm.updateUsage(tx, "u1", "", 0, 2*1024*1024)
		return nil
	})

	// 6. Verify PendingBytes decreased
	fsm.db.View(func(tx *bolt.Tx) error {
		plain, _ := fsm.Get(tx, []byte("users"), []byte("u1"))
		var u User
		json.Unmarshal(plain, &u)
		if u.Usage.TotalBytes != 2*1024*1024 {
			t.Errorf("expected 2MB total, got %d", u.Usage.TotalBytes)
		}
		if u.Usage.PendingBytes != 4*1024*1024 {
			t.Errorf("expected 4MB pending, got %d", u.Usage.PendingBytes)
		}
		return nil
	})

	// 7. Expire reservations
	fsm.db.Update(func(tx *bolt.Tx) error {
		// Manually expire reservations by tweaking their keys in the bucket
		b := tx.Bucket([]byte("pending_reservations"))
		c := b.Cursor()
		k, v := c.First()
		if k != nil {
			// Decrypt first
			plain, _ := fsm.DecryptValue([]byte("pending_reservations"), v)
			var res PendingReservation
			json.Unmarshal(plain, &res)

			// Key is "expiry:id"
			// Create a key in the past
			pastExpiry := time.Now().Add(-1 * time.Hour).UnixNano()
			newKey := fmt.Sprintf("%016x:expired", pastExpiry)
			res.ID = newKey
			res.Expiry = pastExpiry
			newData, _ := json.Marshal(res)
			b.Delete(k)
			// Use fsm.Put to ensure encryption
			fsm.Put(tx, []byte("pending_reservations"), []byte(newKey), newData)
		}
		return nil
	})

	fsm.db.Update(func(tx *bolt.Tx) error {
		fsm.executeReconcilePending(tx)
		return nil
	})

	// 8. Verify PendingBytes is now 0 (expired)
	fsm.db.View(func(tx *bolt.Tx) error {
		plain, _ := fsm.Get(tx, []byte("users"), []byte("u1"))
		var u User
		json.Unmarshal(plain, &u)
		if u.Usage.PendingBytes != 0 {
			t.Errorf("expected 0MB pending after expiry, got %d", u.Usage.PendingBytes)
		}
		return nil
	})
}

func TestLeaseLimits(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "fsm-test-*")
	defer os.RemoveAll(tmpDir)

	fsm, _ := NewMetadataFSM("n1", tmpDir+"/db", []byte("secret"))
	defer fsm.Close()

	userID := "u1"
	// Register User
	fsm.db.Update(func(tx *bolt.Tx) error {
		user := User{ID: userID}
		data, _ := json.Marshal(user)
		return fsm.Put(tx, []byte("users"), []byte(userID), data)
	})

	// 1. Pre-create 110 inodes
	fsm.db.Update(func(tx *bolt.Tx) error {
		for i := 0; i < 110; i++ {
			id := fmt.Sprintf("%032x", i)
			inode := Inode{
				ID:      id,
				OwnerID: userID,
				Mode:    0644,
				Type:    FileType,
			}
			data, _ := json.Marshal(inode)
			fsm.Put(tx, []byte("inodes"), []byte(id), data)
		}
		return nil
	})

	// 2. Acquire 100 leases
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("%032x", i)
		req := LeaseRequest{
			InodeIDs:  []string{id},
			SessionID: "sess1",
			Duration:  int64(1 * time.Minute),
			UserID:    userID,
		}
		data, _ := json.Marshal(req)
		fsm.db.Update(func(tx *bolt.Tx) error {
			res := fsm.executeAcquireLeases(tx, data, "sess1")
			if err, ok := res.(error); ok && err != nil {
				t.Fatalf("failed to acquire lease %d: %v", i, err)
			}
			return nil
		})
	}

	// 3. Try to acquire 101st lease -> should fail
	id101 := fmt.Sprintf("%032x", 101)
	req := LeaseRequest{
		InodeIDs:  []string{id101},
		SessionID: "sess1",
		Duration:  int64(1 * time.Minute),
		UserID:    userID,
	}
	data, _ := json.Marshal(req)
	fsm.db.Update(func(tx *bolt.Tx) error {
		res := fsm.executeAcquireLeases(tx, data, "sess1")
		if err, ok := res.(error); ok && err != nil {
			if !errors.Is(err, ErrQuotaExceeded) {
				t.Errorf("expected ErrQuotaExceeded, got %v", err)
			}
		} else {
			t.Error("expected 101st lease to fail")
		}
		return nil
	})

	// 4. Verify duration hardcap
	idLong := fmt.Sprintf("%032x", 102)
	reqLong := LeaseRequest{
		InodeIDs:  []string{idLong},
		SessionID: "sess2",
		Duration:  int64(10 * time.Minute), // Over 5 min limit
		UserID:    userID,
	}
	dataLong, _ := json.Marshal(reqLong)
	fsm.db.Update(func(tx *bolt.Tx) error {
		fsm.executeAcquireLeases(tx, dataLong, "sess2")
		return nil
	})

	fsm.db.View(func(tx *bolt.Tx) error {
		plain, _ := fsm.Get(tx, []byte("inodes"), []byte(idLong))
		var inode Inode
		json.Unmarshal(plain, &inode)
		for _, l := range inode.Leases {
			duration := l.Expiry - time.Now().UnixNano()
			if duration > int64(6*time.Minute) { // Allow some slack, but definitely not 10 min
				t.Errorf("expected lease duration capped, got %v", time.Duration(duration))
			}
		}
		return nil
	})
}
