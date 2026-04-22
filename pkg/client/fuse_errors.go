//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"errors"
	"net/http"

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
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case metadata.ErrCodeNotDirectory:
			return syscall.ENOTDIR
		case metadata.ErrCodeIsDirectory:
			return syscall.EISDIR
		case metadata.ErrCodeNotEmpty:
			return syscall.ENOTEMPTY
		case metadata.ErrCodeNameTooLong:
			return syscall.ENAMETOOLONG
		case metadata.ErrCodeInvalid:
			return syscall.EINVAL
		case metadata.ErrCodePerm:
			return syscall.EPERM
		case metadata.ErrCodeNoData:
			return syscall.ENODATA
		case metadata.ErrCodeNotSupp:
			return syscall.ENOTSUP
		case metadata.ErrCodeTooBig:
			return syscall.E2BIG
		case metadata.ErrCodeRange:
			return syscall.ERANGE
		case metadata.ErrCodeQuotaExceeded:
			return syscall.EDQUOT
		case metadata.ErrCodeForbidden:
			return syscall.EACCES
		case metadata.ErrCodeNotFound:
			return syscall.ENOENT
		case metadata.ErrCodeExists:
			return syscall.EEXIST
		case metadata.ErrCodeVersionConflict:
			return syscall.EAGAIN
		case metadata.ErrCodeLeaseRequired:
			return syscall.EACCES
		case metadata.ErrCodeAtomicRollback:
			return syscall.EAGAIN
		}

		// Fallback to StatusCode if Code doesn't match
		switch apiErr.StatusCode {
		case http.StatusNotFound:
			return syscall.ENOENT
		case http.StatusUnauthorized, http.StatusForbidden:
			return syscall.EACCES
		case http.StatusServiceUnavailable, http.StatusTooManyRequests:
			return syscall.EAGAIN
		case http.StatusConflict:
			return syscall.EEXIST
		default:
			return syscall.EIO
		}
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
	if errors.Is(err, metadata.ErrNotDirectory) {
		return syscall.ENOTDIR
	}
	if errors.Is(err, metadata.ErrIsDirectory) {
		return syscall.EISDIR
	}
	if errors.Is(err, metadata.ErrNotEmpty) {
		return syscall.ENOTEMPTY
	}
	if errors.Is(err, metadata.ErrNameTooLong) {
		return syscall.ENAMETOOLONG
	}
	if errors.Is(err, metadata.ErrInvalid) {
		return syscall.EINVAL
	}
	if errors.Is(err, metadata.ErrPerm) {
		return syscall.EPERM
	}
	if errors.Is(err, metadata.ErrNoData) {
		return syscall.ENODATA
	}
	if errors.Is(err, metadata.ErrNotSupp) {
		return syscall.ENOTSUP
	}
	if errors.Is(err, metadata.ErrTooBig) {
		return syscall.E2BIG
	}
	if errors.Is(err, metadata.ErrRange) {
		return syscall.ERANGE
	}
	if errors.Is(err, metadata.ErrForbidden) {
		return syscall.EACCES
	}
	if errors.Is(err, metadata.ErrQuotaExceeded) {
		return syscall.EDQUOT
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
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "retry") ||
		strings.Contains(msg, "busy") || strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection aborted") {
		return syscall.EAGAIN
	}
	if strings.Contains(msg, "text file busy") {
		return syscall.ETXTBSY
	}

	// 3. Fallback to general I/O error
	return syscall.EIO
}
