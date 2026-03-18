//go:build !wasm

package client

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestClient_CopyRecursive(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	// 1. Setup source structure
	// /src/
	//   f1.txt (content: "file1")
	//   subdir/
	//     f2.txt (content: "file2")
	c.Mkdir(ctx, "/src", 0755)
	c.CreateFile(ctx, "/src/f1.txt", bytes.NewReader([]byte("file1")), 5)
	c.Mkdir(ctx, "/src/subdir", 0755)
	c.CreateFile(ctx, "/src/subdir/f2.txt", bytes.NewReader([]byte("file2")), 5)

	// 2. Perform recursive copy
	err := c.Copy(ctx, "/src", "/dst")
	if err != nil {
		t.Fatalf("Recursive copy failed: %v", err)
	}

	// 3. Verify destination structure
	inodeF1, _, err := c.ResolvePath(ctx, "/dst/f1.txt")
	if err != nil {
		t.Fatalf("Resolve /dst/f1.txt failed: %v", err)
	}
	if inodeF1.Size != 5 {
		t.Errorf("Expected size 5, got %d", inodeF1.Size)
	}

	rc, err := c.OpenBlobRead(ctx, "/dst/f1.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "file1" {
		t.Errorf("Content mismatch: expected 'file1', got '%s'", string(data))
	}

	inodeF2, _, err := c.ResolvePath(ctx, "/dst/subdir/f2.txt")
	if err != nil {
		t.Fatalf("Resolve /dst/subdir/f2.txt failed: %v", err)
	}
	if inodeF2.Size != 5 {
		t.Errorf("Expected size 5, got %d", inodeF2.Size)
	}
}

func TestClient_Quota(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	quota, usage, err := c.GetQuota(ctx)
	if err != nil {
		t.Fatalf("GetQuota failed: %v", err)
	}

	// Default quota for new user in test environment is usually 0 (unlimited) or some fixed value
	// Just verify we got something
	t.Logf("Quota: %+v, Usage: %+v", quota, usage)
}

func TestFileReader_Seek(t *testing.T) {
	ctx := context.Background()
	c, _, _, ts := SetupTestClient(t)
	defer ts.Close()

	content := []byte("0123456789")
	c.CreateFile(ctx, "/seekable", bytes.NewReader(content), 10)

	inode, key, err := c.ResolvePath(ctx, "/seekable")
	if err != nil {
		t.Fatal(err)
	}

	r, err := c.NewReader(ctx, inode.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// 1. Seek from start
	pos, err := r.Seek(2, io.SeekStart)
	if err != nil || pos != 2 {
		t.Fatalf("SeekStart failed: pos=%d, err=%v", pos, err)
	}
	buf := make([]byte, 2)
	n, _ := r.Read(buf)
	if n != 2 || string(buf) != "23" {
		t.Errorf("Read after SeekStart mismatch: %s", buf)
	}

	// 2. Seek from current
	pos, err = r.Seek(2, io.SeekCurrent) // now at 6
	if err != nil || pos != 6 {
		t.Fatalf("SeekCurrent failed: pos=%d, err=%v", pos, err)
	}
	n, _ = r.Read(buf)
	if n != 2 || string(buf) != "67" {
		t.Errorf("Read after SeekCurrent mismatch: %s", buf)
	}

	// 3. Seek from end
	pos, err = r.Seek(-2, io.SeekEnd) // at 8
	if err != nil || pos != 8 {
		t.Fatalf("SeekEnd failed: pos=%d, err=%v", pos, err)
	}
	n, _ = r.Read(buf)
	if n != 2 || string(buf) != "89" {
		t.Errorf("Read after SeekEnd mismatch: %s", buf)
	}
}
