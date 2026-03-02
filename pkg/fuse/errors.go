// Copyright 2026 TTBT Enterprises LLC
package fuse

import (
	"context"
	"errors"

	"github.com/c2FmZQ/distfs/pkg/client"

	"github.com/c2FmZQ/distfs/pkg/metadata"
	"strings"
	"syscall"
)

// mapError translates internal errors to POSIX syscall errors for FUSE.
func mapError(err error) error {
	if err == nil {
		return nil
	}

	// 1. Check for specific APIError mapping
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ToPOSIX()
	}
	// 2. Handle specific Sentinel errors
	if errors.Is(err, metadata.ErrNotFound) {
		return syscall.ENOENT
	}
	if errors.Is(err, metadata.ErrExists) {
		return syscall.EEXIST
	}
	if errors.Is(err, metadata.ErrConflict) {
		return syscall.EAGAIN
	}
	if errors.Is(err, metadata.ErrLeaseRequired) {
		return syscall.EACCES
	}
	if errors.Is(err, metadata.ErrStructuralInconsistency) {
		return syscall.EIO
	}
	if errors.Is(err, metadata.ErrAtomicRollback) {
		return syscall.EAGAIN
	}

	// 3. Handle Context errors
	if errors.Is(err, context.Canceled) {
		return syscall.EINTR
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return syscall.ETIMEDOUT
	}

	// 4. Handle string-based matching for specific conditions

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "directory not empty") {
		return syscall.ENOTEMPTY
	}
	if strings.Contains(msg, "not a directory") {
		return syscall.ENOTDIR
	}
	if strings.Contains(msg, "is a directory") {
		return syscall.EISDIR
	}
	if strings.Contains(msg, "access denied") || strings.Contains(msg, "forbidden") {
		return syscall.EACCES
	}
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "retry") || strings.Contains(msg, "busy") {
		return syscall.EAGAIN
	}
	if strings.Contains(msg, "text file busy") {
		return syscall.ETXTBSY
	}

	// 3. Fallback to general I/O error
	return syscall.EIO
}
