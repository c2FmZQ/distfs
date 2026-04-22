//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC

package client

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

func setupFUSETestEnv(t *testing.T) (*Client, string, func()) {
	c, _, _, _, _, _ := setupTestClient(t)

	mountpoint := t.TempDir()
	conn, err := fuse.Mount(mountpoint)
	if err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	filesys := NewFS(c)
	go func() {
		_ = fs.Serve(conn, filesys)
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
		filesys.Close()
		fuse.Unmount(mountpoint)
		conn.Close()
		t.Fatal("FUSE mount not ready")
	}

	cleanup := func() {
		fuse.Unmount(mountpoint)
		filesys.Close()
		conn.Close()
		time.Sleep(200 * time.Millisecond) // Give kernel time to clean up
	}
	return c, mountpoint, cleanup
}

// assertErrno is a helper to verify that a given error matches the expected syscall.Errno.
func assertErrno(t *testing.T, err error, expected syscall.Errno) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %v, got nil", expected)
	}

	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		if sysErr != expected {
			t.Errorf("expected syscall.Errno %v (%v), got %v (%v) from error: %v", expected, expected.Error(), sysErr, sysErr.Error(), err)
		}
		return
	}

	// Sometimes errors are wrapped in os.PathError or os.LinkError
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.As(pathErr.Err, &sysErr) {
			if sysErr != expected {
				t.Errorf("expected syscall.Errno %v, got %v from PathError: %v", expected, sysErr, pathErr)
			}
			return
		}
		t.Errorf("expected syscall.Errno %v, got PathError without Errno: %v", expected, pathErr)
		return
	}

	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		if errors.As(linkErr.Err, &sysErr) {
			if sysErr != expected {
				t.Errorf("expected syscall.Errno %v, got %v from LinkError: %v", expected, sysErr, linkErr)
			}
			return
		}
		t.Errorf("expected syscall.Errno %v, got LinkError without Errno: %v", expected, linkErr)
		return
	}

	t.Errorf("expected syscall.Errno %v, got unknown error type: %T (%v)", expected, err, err)
}

// assertErrnoOr is a helper to verify that an error matches one of the expected syscall.Errno values.
func assertErrnoOr(t *testing.T, err error, expected ...syscall.Errno) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected one of %v, got nil", expected)
	}

	var sysErr syscall.Errno
	matched := false
	if errors.As(err, &sysErr) {
		for _, e := range expected {
			if sysErr == e {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("expected one of %v, got %v (%v) from error: %v", expected, sysErr, sysErr.Error(), err)
		}
		return
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.As(pathErr.Err, &sysErr) {
			for _, e := range expected {
				if sysErr == e {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("expected one of %v, got %v from PathError: %v", expected, sysErr, pathErr)
			}
			return
		}
	}

	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		if errors.As(linkErr.Err, &sysErr) {
			for _, e := range expected {
				if sysErr == e {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("expected one of %v, got %v from LinkError: %v", expected, sysErr, linkErr)
			}
			return
		}
	}

	t.Errorf("expected one of %v, got unknown error type: %T (%v)", expected, err, err)
}

func TestFUSEErrors_Mkdir(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	// 1. EEXIST: Target directory already exists
	target := filepath.Join(mnt, "existing_dir")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	err := os.Mkdir(target, 0755)
	assertErrno(t, err, syscall.EEXIST)

	// 2. ENOENT: Parent directory does not exist
	targetENOENT := filepath.Join(mnt, "non_existent_parent", "new_dir")
	err = os.Mkdir(targetENOENT, 0755)
	assertErrno(t, err, syscall.ENOENT)

	// 3. ENOTDIR: Parent is a file
	targetFile := filepath.Join(mnt, "existing_file")
	if err := os.WriteFile(targetFile, []byte("test"), 0644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	targetENOTDIR := filepath.Join(targetFile, "new_dir")
	err = os.Mkdir(targetENOTDIR, 0755)
	assertErrno(t, err, syscall.ENOTDIR)
}

func TestFUSEErrors_Rmdir(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	// 1. ENOENT: Target does not exist
	targetENOENT := filepath.Join(mnt, "non_existent_dir")
	err := os.Remove(targetENOENT)
	assertErrno(t, err, syscall.ENOENT)

	// 2. ENOTEMPTY: Directory is not empty
	targetENOTEMPTY := filepath.Join(mnt, "not_empty_dir")
	if err := os.Mkdir(targetENOTEMPTY, 0755); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetENOTEMPTY, "file.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	err = os.Remove(targetENOTEMPTY)
	assertErrno(t, err, syscall.ENOTEMPTY)

	// 3. ENOTDIR: Target is a file
	targetENOTDIR := filepath.Join(mnt, "file_to_rmdir")
	if err := os.WriteFile(targetENOTDIR, []byte("test"), 0644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	// Note: os.Remove handles both files and dirs. To test rmdir specifically on a file, we could use syscall.Rmdir
	err = syscall.Rmdir(targetENOTDIR)
	assertErrno(t, err, syscall.ENOTDIR)
}

func TestFUSEErrors_Unlink(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	// 1. ENOENT: Target does not exist
	targetENOENT := filepath.Join(mnt, "non_existent_file")
	err := syscall.Unlink(targetENOENT)
	assertErrno(t, err, syscall.ENOENT)

	// 2. EISDIR: Target is a directory
	targetEISDIR := filepath.Join(mnt, "dir_to_unlink")
	if err := os.Mkdir(targetEISDIR, 0755); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	err = syscall.Unlink(targetEISDIR)
	assertErrno(t, err, syscall.EISDIR)
}

func TestFUSEErrors_Rename(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	// Setup directories and files
	dir1 := filepath.Join(mnt, "dir1")
	dir2 := filepath.Join(mnt, "dir2")
	file1 := filepath.Join(mnt, "file1")
	file2 := filepath.Join(mnt, "file2")

	os.Mkdir(dir1, 0755)
	os.Mkdir(dir2, 0755)
	os.WriteFile(file1, []byte("test"), 0644)
	os.WriteFile(file2, []byte("test"), 0644)

	// 1. ENOENT: Source does not exist
	err := os.Rename(filepath.Join(mnt, "non_existent"), filepath.Join(mnt, "new_name"))
	assertErrno(t, err, syscall.ENOENT)

	// 2. ENOTEMPTY or EEXIST: Destination is a non-empty directory
	os.WriteFile(filepath.Join(dir2, "child"), []byte("test"), 0644)
	err = os.Rename(dir1, dir2)
	assertErrnoOr(t, err, syscall.ENOTEMPTY, syscall.EEXIST)

	// 3. EISDIR or EEXIST: Destination is a directory, but source is a file
	err = os.Rename(file1, dir1)
	assertErrnoOr(t, err, syscall.EISDIR, syscall.EEXIST)

	// 4. ENOTDIR: Destination is a file, but source is a directory
	// Clear dir1 first to ensure we don't get ENOTEMPTY
	os.RemoveAll(dir1)
	os.Mkdir(dir1, 0755)
	err = os.Rename(dir1, file2)
	assertErrno(t, err, syscall.ENOTDIR)

	// 5. EINVAL: Source is a prefix of Destination (e.g., rename `a` to `a/b`)
	err = os.Rename(dir1, filepath.Join(dir1, "subdir"))
	assertErrno(t, err, syscall.EINVAL)
}

func TestFUSEErrors_Open(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	// 1. ENOENT: File does not exist (without O_CREAT)
	_, err := os.Open(filepath.Join(mnt, "non_existent"))
	assertErrno(t, err, syscall.ENOENT)

	// 2. EEXIST: O_CREAT | O_EXCL specified and file exists
	existingFile := filepath.Join(mnt, "existing_file")
	os.WriteFile(existingFile, []byte("test"), 0644)
	_, err = os.OpenFile(existingFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	assertErrno(t, err, syscall.EEXIST)

	// 3. EISDIR: Path is a directory and opened for writing
	existingDir := filepath.Join(mnt, "existing_dir")
	os.Mkdir(existingDir, 0755)
	_, err = os.OpenFile(existingDir, os.O_WRONLY, 0644)
	assertErrno(t, err, syscall.EISDIR)
}

func TestFUSEErrors_Xattr(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	targetFile := filepath.Join(mnt, "xattr_file")
	os.WriteFile(targetFile, []byte("test"), 0644)

	// ENODATA: Requested attribute does not exist
	// In Go, syscall.Getxattr is used for extended attributes.
	var buf [1024]byte
	_, err := syscall.Getxattr(targetFile, "user.non_existent", buf[:])
	assertErrnoOr(t, err, syscall.ENODATA)

	// ERANGE: Provided buffer is too small
	// We first need to set an attribute to get it.
	err = syscall.Setxattr(targetFile, "user.test", []byte("long_value"), 0)
	if err == nil {
		var smallBuf [2]byte
		_, err = syscall.Getxattr(targetFile, "user.test", smallBuf[:])
		assertErrnoOr(t, err, syscall.ERANGE)
	}
}

func TestFUSEErrors_ChmodChown(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	// 1. ENOENT: Path does not exist
	err := os.Chmod(filepath.Join(mnt, "non_existent"), 0644)
	assertErrnoOr(t, err, syscall.ENOENT)

	err = os.Chown(filepath.Join(mnt, "non_existent"), 1000, 1000)
	assertErrnoOr(t, err, syscall.ENOENT)
}

func TestFUSEErrors_LinkAndSymlink(t *testing.T) {
	_, mnt, cleanup := setupFUSETestEnv(t)
	defer cleanup()

	targetFile := filepath.Join(mnt, "target_file")
	targetDir := filepath.Join(mnt, "target_dir")
	existingLink := filepath.Join(mnt, "existing_link")

	os.WriteFile(targetFile, []byte("test"), 0644)
	os.Mkdir(targetDir, 0755)
	os.Symlink(targetFile, existingLink)

	// Link Tests
	// 1. ENOENT: Target file does not exist
	err := os.Link(filepath.Join(mnt, "non_existent"), filepath.Join(mnt, "new_link"))
	assertErrno(t, err, syscall.ENOENT)

	// 2. EPERM: Target is a directory
	err = os.Link(targetDir, filepath.Join(mnt, "new_link_dir"))
	assertErrno(t, err, syscall.EPERM)

	// 3. EEXIST: Link path already exists
	err = os.Link(targetFile, existingLink)
	assertErrno(t, err, syscall.EEXIST)

	// Symlink Tests
	// 4. EEXIST: Link path already exists
	err = os.Symlink(targetFile, existingLink)
	assertErrno(t, err, syscall.EEXIST)

	// Readlink Tests
	// 5. ENOENT: Path does not exist
	_, err = os.Readlink(filepath.Join(mnt, "non_existent"))
	assertErrno(t, err, syscall.ENOENT)

	// 6. EINVAL: Path is not a symbolic link
	_, err = os.Readlink(targetFile)
	assertErrno(t, err, syscall.EINVAL)
}
