// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/c2FmZQ/distfs/pkg/metadata"
)

// FormatBytes scales bytes to a human-readable string.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// IsNotFound returns true if the error indicates a 404 Not Found response from the server
// or is wrapping a metadata.ErrNotFound sentinel. This should be used for logic that
// needs to handle missing resources gracefully (e.g. cache invalidation on delete).
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, metadata.ErrNotFound) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// IsConflict returns true if the error indicates a 409 Conflict response (e.g. version mismatch),
// metadata.ErrConflict, or metadata.ErrExists. This is commonly used to trigger retries
// in optimistic concurrency control loops.
func IsConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, metadata.ErrConflict) || errors.Is(err, metadata.ErrExists) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusConflict ||
			apiErr.Code == metadata.ErrCodeVersionConflict ||
			apiErr.Code == metadata.ErrCodeExists ||
			apiErr.Code == metadata.ErrCodeLeaseRequired
	}
	return false
}

// Ptr returns a pointer to the provided value. It is a convenience helper for
// initializing fields in structs that require pointers to primitive types or constants.
func Ptr[T any](v T) *T {
	return &v
}
