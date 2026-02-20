package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/metadata"
)

type mockLSClient struct {
	entries   []*client.DistDirEntry
	recursive map[string][]*client.DistDirEntry
	inode     *metadata.Inode
	err       error
}

func (m *mockLSClient) ResolvePath(path string) (*metadata.Inode, []byte, error) {
	return m.inode, []byte("key"), m.err
}

func (m *mockLSClient) ReadDirExtended(ctx context.Context, path string) ([]*client.DistDirEntry, error) {
	return m.entries, m.err
}

func (m *mockLSClient) ReadDirRecursive(ctx context.Context, path string) (map[string][]*client.DistDirEntry, error) {
	return m.recursive, m.err
}

func (m *mockLSClient) NewDirEntry(inode *metadata.Inode, name string) *client.DistDirEntry {
	return client.NewDirEntryForTest(inode, name)
}

func (m *mockLSClient) DecryptName(inode *metadata.Inode) (string, error) {
	return "decrypted", m.err
}

func (m *mockLSClient) UserID() string {
	return "user-123"
}

func TestLS_ProcessAndPrint(t *testing.T) {
	now := time.Now()
	entries := []*client.DistDirEntry{
		client.NewDirEntryForTest(&metadata.Inode{ID: "1", Size: 100, MTime: now.UnixNano()}, "b.txt"),
		client.NewDirEntryForTest(&metadata.Inode{ID: "2", Size: 200, MTime: now.Add(time.Hour).UnixNano()}, "a.txt"),
		client.NewDirEntryForTest(&metadata.Inode{ID: "3", Size: 50, MTime: now.Add(-time.Hour).UnixNano()}, ".hidden"),
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
	entries := []*client.DistDirEntry{
		client.NewDirEntryForTest(&metadata.Inode{
			ID:    "inode-1234567890",
			Size:  1024,
			Mode:  0644,
			MTime: now.UnixNano(),
		}, "file.txt"),
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
