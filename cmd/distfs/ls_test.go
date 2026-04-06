package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

func TestLS_ProcessAndPrint(t *testing.T) {
	now := time.Now()
	// MTime is in nanoseconds in Inode
	i1 := &metadata.Inode{ID: "1", Size: 100}
	i1.SetMTime(now.UnixNano())
	i2 := &metadata.Inode{ID: "2", Size: 200}
	i2.SetMTime(now.Add(time.Hour).UnixNano())
	i3 := &metadata.Inode{ID: "3", Size: 50}
	i3.SetMTime(now.Add(-time.Hour).UnixNano())

	entries := []*client.DistDirEntry{
		client.NewDirEntryForTest(i1, "b.txt", nil),
		client.NewDirEntryForTest(i2, "a.txt", nil),
		client.NewDirEntryForTest(i3, ".hidden", nil),
	}

	tests := []struct {
		name    string
		all     bool
		sortByT bool
		sortByS bool
		reverse bool
		want    []string
		notWant []string
	}{
		{
			name: "Default (Alphabetical, no hidden)",
			all:  false, want: []string{"a.txt", "b.txt"}, notWant: []string{".hidden"},
		},
		{
			name: "All files",
			all:  true, want: []string{".hidden", "a.txt", "b.txt"},
		},
		{
			name: "Sort by Size",
			all:  true, sortByS: true, want: []string{"a.txt", "b.txt", ".hidden"},
		},
		{
			name: "Sort by Time",
			all:  true, sortByT: true, want: []string{"a.txt", "b.txt", ".hidden"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			processAndPrintEntries(&buf, entries, false, tt.all, false, false, false, false, tt.sortByT, tt.sortByS, tt.reverse)
			output := buf.String()
			for _, w := range tt.want {
				if !strings.Contains(output, w) {
					t.Errorf("missing %s", w)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(output, nw) {
					t.Errorf("unexpected %s", nw)
				}
			}
		})
	}
}

func TestLS_LongFormat(t *testing.T) {
	now := time.Now()
	i1 := &metadata.Inode{
		ID:   "inode-1234567890",
		Size: 1024,
		Mode: 0644,
	}
	i1.SetMTime(now.UnixNano())
	entries := []*client.DistDirEntry{
		client.NewDirEntryForTest(i1, "file.txt", nil),
	}

	var buf bytes.Buffer
	// w, entries, long, all, human, inode, classify, oneCol, sortByTime, sortBySize, reverse
	processAndPrintEntries(&buf, entries, true, false, true, true, true, false, false, false, false)
	output := buf.String()

	if !strings.Contains(output, "1.0 KB") {
		t.Errorf("missing human size")
	}
	if !strings.Contains(output, "inode-1234567890") {
		t.Errorf("missing inode ID")
	}
	if !strings.Contains(output, "-rw-r--r--") {
		t.Errorf("missing mode string, got %s", output)
	}
}
