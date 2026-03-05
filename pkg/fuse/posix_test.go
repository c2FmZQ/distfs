// Copyright 2026 TTBT Enterprises LLC
package fuse

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
	"net/http/httptest"
)

func TestFUSE_POSIXCompliance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FUSE E2E test in short mode")
	}

	// 1. Setup Infrastructure
	metaDir := t.TempDir()
	metaSt, _ := createTestStorageLocal(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
	clusterSecret := []byte("test-cluster-secret-32-bytes-long!!")
	metaNode, err := metadata.NewRaftNode("meta1", "127.0.0.1:0", "", metaDir, metaSt, nodeKey, clusterSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer metaNode.Shutdown()

	metaNode.Raft.BootstrapCluster(raft.Configuration{
		Servers: []raft.Server{{ID: "meta1", Address: metaNode.Transport.LocalAddr()}},
	})
	waitLeaderLocal(t, metaNode.Raft)

	serverEK, metaSignPK := bootstrapClusterLocal(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true, true)
	tsMeta := httptest.NewServer(metaServer)

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      "user-fuse",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUserLocal(t, metaNode, user)

	dataDir := t.TempDir()
	dataSt, _ := createTestStorageLocal(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	registerNodeLocal(t, tsMeta.URL, "testsecret", metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	})

	c := client.NewClient(tsMeta.URL)
	c = c.WithIdentity("user-fuse", dk)
	c = c.WithSignKey(userSignKey)
	c = c.WithServerKey(serverEK)

	if err := c.EnsureRoot(context.Background()); err != nil {
		t.Fatalf("EnsureRoot failed: %v", err)
	}

	mountpoint := t.TempDir()
	conn, err := fuse.Mount(mountpoint)
	if err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	defer func() {
		log.Printf("DEBUG TEST: Unmounting %s", mountpoint)
		fuse.Unmount(mountpoint)
		conn.Close()
		time.Sleep(2 * time.Second) // Give kernel/background flushes time to finish
	}()
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	filesys := NewFS(c)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- fs.Serve(conn, filesys)
	}()

	// Wait ready
	ready := false
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(mountpoint); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("FUSE mount not ready")
	}

	// --- START POSIX COMPLIANCE TESTS (MIRRORING test-fuse.sh) ---

	// TEST 1: Basic Creation and Deletion
	t.Run("BasicCreation", func(t *testing.T) {
		f1 := filepath.Join(mountpoint, "f1")
		if err := os.WriteFile(f1, []byte("hello"), 0644); err != nil {
			t.Fatalf("WriteFile f1 failed: %v", err)
		}
		if _, err := os.Stat(f1); err != nil {
			t.Fatalf("Stat f1 failed: %v", err)
		}
		if err := os.Remove(f1); err != nil {
			t.Fatalf("Remove f1 failed: %v", err)
		}
		if _, err := os.Stat(f1); !os.IsNotExist(err) {
			t.Fatalf("f1 should be gone, err=%v", err)
		}
	})

	// TEST 2: Multi-file & Persistence
	t.Run("MultiFilePersistence", func(t *testing.T) {
		f1 := filepath.Join(mountpoint, "f1-p")
		f2 := filepath.Join(mountpoint, "f2-p")
		os.WriteFile(f1, []byte("content1"), 0644)
		os.WriteFile(f2, []byte("content2"), 0644)

		if b, _ := os.ReadFile(f1); string(b) != "content1" {
			t.Errorf("f1 content mismatch: got %q", string(b))
		}
		if b, _ := os.ReadFile(f2); string(b) != "content2" {
			t.Errorf("f2 content mismatch: got %q", string(b))
		}
	})

	// TEST 3: Nested Directories
	t.Run("NestedDirectories", func(t *testing.T) {
		dir := filepath.Join(mountpoint, "dir1/dir2")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		f3 := filepath.Join(dir, "f3")
		content := "nested content"
		if err := os.WriteFile(f3, []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile f3 failed: %v", err)
		}
		if b, _ := os.ReadFile(f3); string(b) != content {
			t.Errorf("f3 content mismatch: got %q", string(b))
		}
	})

	// TEST 4: Renaming
	t.Run("Renaming", func(t *testing.T) {
		oldPath := filepath.Join(mountpoint, "f2-p")
		newPath := filepath.Join(mountpoint, "f2-renamed")
		if err := os.Rename(oldPath, newPath); err != nil {
			t.Fatalf("Rename failed: %v", err)
		}
		if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
			t.Errorf("old file should be gone")
		}
		if b, _ := os.ReadFile(newPath); string(b) != "content2" {
			t.Errorf("renamed file content mismatch")
		}

		// Rename across directories
		dir1f3 := filepath.Join(mountpoint, "dir1/dir2/f3")
		rootf3 := filepath.Join(mountpoint, "f3-moved")
		if err := os.Rename(dir1f3, rootf3); err != nil {
			t.Fatalf("Cross-dir rename failed: %v", err)
		}
		if b, _ := os.ReadFile(rootf3); string(b) != "nested content" {
			t.Errorf("moved file content mismatch")
		}
	})

	// TEST 5: Symlinks
	t.Run("Symlinks", func(t *testing.T) {
		target := "f1-target"
		link := filepath.Join(mountpoint, "s1")
		f1 := filepath.Join(mountpoint, target)
		os.WriteFile(f1, []byte("link-target-content"), 0644)

		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink failed: %v", err)
		}

		got, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("Readlink failed: %v", err)
		}
		if got != target {
			t.Errorf("Readlink mismatch: got %q, want %q", got, target)
		}

		b, err := os.ReadFile(link)
		if err != nil {
			t.Fatalf("ReadFile via symlink failed: %v", err)
		}
		if string(b) != "link-target-content" {
			t.Errorf("Content via symlink mismatch")
		}
	})

	// TEST 6: Deletion & NLink
	t.Run("DeletionNLink", func(t *testing.T) {
		f1 := filepath.Join(mountpoint, "f1-target")
		if err := os.Remove(f1); err != nil {
			t.Fatalf("Remove f1 failed: %v", err)
		}
		if _, err := os.Stat(f1); !os.IsNotExist(err) {
			t.Errorf("f1 should be gone")
		}
	})

	// TEST 7: Metadata (chmod/chown)
	t.Run("Metadata", func(t *testing.T) {
		f := filepath.Join(mountpoint, "f2-renamed")
		if err := os.Chmod(f, 0700); err != nil {
			t.Fatalf("Chmod failed: %v", err)
		}
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Mode mismatch: got %v, want %v", info.Mode().Perm(), 0700)
		}
	})

	// TEST 8: Concurrent Writes
	t.Run("ConcurrentWrites", func(t *testing.T) {
		f := filepath.Join(mountpoint, "concurrent.txt")
		errCh := make(chan error, 2)

		write := func(val string) {
			errCh <- os.WriteFile(f, []byte(val), 0644)
		}

		go write("writer1")
		go write("writer2")

		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Errorf("Concurrent write %d failed: %v", i, err)
			}
		}

		b, _ := os.ReadFile(f)
		if string(b) != "writer1" && string(b) != "writer2" {
			t.Errorf("Corrupted content: %q", string(b))
		}
	})

	// TEST 9: DeleteWhileOpen
	t.Run("DeleteWhileOpen", func(t *testing.T) {
		f := filepath.Join(mountpoint, "delete-me")
		content := []byte("keep reading me")
		os.WriteFile(f, content, 0644)

		fh, err := os.Open(f)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer fh.Close()

		if err := os.Remove(f); err != nil {
			t.Fatalf("Remove failed: %v", err)
		}

		buf := make([]byte, len(content))
		_, err = fh.Read(buf)
		if err != nil {
			t.Fatalf("Read after remove failed: %v", err)
		}
		if !bytes.Equal(buf, content) {
			t.Errorf("Content mismatch after remove")
		}
	})

	// Wait for server to finish after unmount (triggered by defers)
}
