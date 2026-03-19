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

func isNotFound(err error) bool {
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

func isConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, metadata.ErrConflict) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusConflict ||
			apiErr.Code == metadata.ErrCodeVersionConflict
	}
	return false
}

func ptr[T any](v T) *T {
	return &v
}
