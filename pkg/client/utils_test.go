//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{1024 * 1024 * 1024 * 1024, "1.0 TB"},
	}

	for _, tt := range tests {
		if got := FormatBytes(tt.bytes); got != tt.want {
			t.Errorf("FormatBytes(%d) = %v, want %v", tt.bytes, got, tt.want)
		}
	}
}
