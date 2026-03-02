// Copyright 2026 TTBT Enterprises LLC
package fuse

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"io"
	iofs "io/fs"
	"net/http"
	"net/http/httptest"
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
	"github.com/c2FmZQ/storage"
	storage_crypto "github.com/c2FmZQ/storage/crypto"
	"github.com/hashicorp/raft"
)

func createTestStorageLocal(t *testing.T, dir string) (*storage.Storage, storage_crypto.MasterKey) {
	mk, err := storage_crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	st := storage.New(dir, mk)
	return st, mk
}

var nextTestUID uint32 = 1000

func createUserLocal(t *testing.T, raftNode *metadata.RaftNode, user metadata.User) {
	metadata.CreateUser(t, raftNode, user)
}

func waitLeaderLocal(t *testing.T, r *raft.Raft) {
	leader := false
	for i := 0; i < 50; i++ {
		if r.State() == raft.Leader {
			leader = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !leader {
		t.Fatal("Node did not become leader")
	}
}

func bootstrapClusterLocal(t *testing.T, raftNode *metadata.RaftNode) (*mlkem.EncapsulationKey768, []byte) {
	waitLeaderLocal(t, raftNode.Raft)
	dk, _ := crypto.GenerateEncryptionKey()
	ek := dk.EncapsulationKey()
	key := metadata.ClusterKey{
		ID:        "key-1",
		EncKey:    ek.Bytes(),
		DecKey:    dk.Bytes(),
		CreatedAt: time.Now().Unix(),
	}
	keyBytes, _ := json.Marshal(key)
	cmd := metadata.LogCommand{Type: metadata.CmdRotateKey, Data: keyBytes}
	cmdBytes, _ := json.Marshal(cmd)
	future := raftNode.Raft.Apply(cmdBytes, 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap cluster key apply failed: %v", err)
	}

	// Bootstrap cluster sign key
	csk, _ := crypto.GenerateIdentityKey()
	cskData := metadata.ClusterSignKey{
		Public:           csk.Public(),
		EncryptedPrivate: csk.MarshalPrivate(),
	}
	cskBytes, _ := json.Marshal(cskData)
	future = raftNode.Raft.Apply(metadata.LogCommand{Type: metadata.CmdSetClusterSignKey, Data: cskBytes}.Marshal(), 5*time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Bootstrap sign key apply failed: %v", err)
	}

	return dk.EncapsulationKey(), csk.Public()
}

func registerNodeLocal(t *testing.T, serverURL, secret string, node metadata.Node) {
	body, _ := json.Marshal(node)
	req, _ := http.NewRequest("POST", serverURL+"/v1/node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Raft-Secret", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Register node failed: %d", resp.StatusCode)
	}
}

func TestFUSE_ReadWriteSeek(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FUSE E2E test in short mode")
	}

	// 1. Setup Metadata Node
	metaDir := t.TempDir()
	metaSt, _ := createTestStorageLocal(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key")
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
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      "user-fuse",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUserLocal(t, metaNode, user)

	// 2. Setup Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorageLocal(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{})
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	node := metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNodeLocal(t, tsMeta.URL, "testsecret", node)

	newClient := func() *client.Client {
		c := client.NewClient(tsMeta.URL)
		c = c.WithIdentity("user-fuse", dk)
		c = c.WithSignKey(userSignKey)
		c = c.WithServerKey(serverEK)
		return c
	}

	// 3. Initialize Root once
	if err := newClient().EnsureRoot(t.Context()); err != nil {
		t.Fatalf("Initial EnsureRoot failed: %v", err)
	}

	// 4. Setup Client and Mount Point
	mount := func(mountpoint string) (func(), *client.Client) {
		c := newClient()

		//conn, err := fuse.Mount(mountpoint, fuse.AsyncRead())
		conn, err := fuse.Mount(mountpoint)
		if err != nil {
			t.Fatalf("Mount failed: %v", err)
		}

		filesys := NewFS(c)
		serverDone := make(chan error, 1)

		go func() {
			serverDone <- fs.Serve(conn, filesys)
		}()

		// Wait for mount to be ready
		t.Logf("Waiting for FUSE mount at %s...", mountpoint)
		mounted := false

		for i := 0; i < 100; i++ {
			if _, err := os.Stat(filepath.Join(mountpoint, ".")); err == nil {
				mounted = true
				break
			}
			select {
			case err := <-serverDone:
				t.Fatalf("FUSE server at %s exited early: %v", mountpoint, err)
			case <-time.After(100 * time.Millisecond):
			}
		}

		if !mounted {
			t.Fatalf("Timeout waiting for FUSE ready at %s", mountpoint)
		}

		return func() {
			t.Logf("Unmounting %s...", mountpoint)
			if err := fuse.Unmount(mountpoint); err != nil {
				t.Logf("Unmount warning: %v", err)
			}
			t.Logf("Closing connection for %s...", mountpoint)
			conn.Close()

			// Wait for server to exit
			t.Logf("Waiting for FUSE server at %s to exit...", mountpoint)

			select {
			case err := <-serverDone:
				if err != nil {
					t.Logf("FUSE server at %s exited with: %v", mountpoint, err)
				} else {
					t.Logf("FUSE server at %s exited cleanly", mountpoint)
				}
			case <-time.After(5 * time.Second):
				t.Logf("FUSE server at %s failed to exit after unmount", mountpoint)
			}
		}, c
	}

	// 4. Initial Mount and File Creation
	mountpoint1 := t.TempDir()
	unmount1, _ := mount(mountpoint1)
	filePath := filepath.Join(mountpoint1, "testfile.bin")
	fileSize := 7500000 // 7.5 MB
	originalData := make([]byte, fileSize)

	if _, err := io.ReadFull(rand.Reader, originalData); err != nil {
		t.Fatal(err)
	}

	t.Log("Creating 7.5MB file...")
	if err := os.WriteFile(filePath, originalData, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 5. Complex Seek and Write Operations
	t.Log("Opening file RW for complex seeks...")
	f, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}

	// Operation 1: Overwrite 100 KB at 3.25 MB offset
	off1 := int64(3.25 * 1024 * 1024)
	data1 := make([]byte, 100*1024)
	rand.Read(data1)
	t.Logf("Writing 100KB at %d", off1)
	if _, err := f.Seek(off1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data1); err != nil {
		t.Fatal(err)
	}

	// Operation 2: Overwrite 5 bytes at 6 MB offset (chunk boundary)
	off2 := int64(6 * 1024 * 1024)
	data2 := []byte("BOUND")
	t.Logf("Writing 5 bytes at %d (chunk boundary)", off2)
	if _, err := f.Seek(off2, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	if _, err := f.Write(data2); err != nil {
		t.Fatal(err)
	}

	// Operation 3: Overwrite 2 bytes at (3 MB - 1 B) offset (across chunk boundary)
	off3 := int64(3*1024*1024 - 1)
	data3 := []byte("XY")

	t.Logf("Writing 2 bytes at %d (across chunk boundary)", off3)
	if _, err := f.Seek(off3, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	if _, err := f.Write(data3); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	expectedData := make([]byte, fileSize)
	copy(expectedData, originalData)
	copy(expectedData[off1:], data1)
	copy(expectedData[off2:], data2)
	copy(expectedData[off3:], data3)

	compare := func(desc string, data []byte) {
		t.Helper()
		if len(data) != fileSize {
			t.Fatalf("[%s] Size mismatch: got %d, want %d", desc, len(data), fileSize)
		}

		if !bytes.Equal(data, expectedData) {
			t.Errorf("[%s] Content mismatch after complex overwrites", desc)
			// Find first mismatch for debugging
			for i := 0; i < len(data); i++ {
				if data[i] != expectedData[i] {
					t.Errorf("[%s] First mismatch at offset %d: got %02x, want %02x", desc, i, data[i], expectedData[i])
					break
				}
			}
		} else {
			t.Logf("[%s] PASS: Content verified after complex seeking and remount.", desc)
		}
	}

	t.Log("Reading back and verifying...")
	rb1, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	compare("fuse", rb1)

	t.Log("Unmounting...")
	unmount1()

	fsClient := newClient()
	rb2, err := iofs.ReadFile(fsClient.FS(t.Context()), "testfile.bin")
	if err != nil {
		t.Fatalf("fs.ReadFile: %v", err)
	}
	compare("fs.FS", rb2)

	t.Log("Remounting with fresh client...")
	mountpoint2 := t.TempDir()
	unmount2, _ := mount(mountpoint2)
	defer unmount2()

	filePath2 := filepath.Join(mountpoint2, "testfile.bin")
	t.Log("Reading back and verifying...")
	rb3, err := os.ReadFile(filePath2)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	compare("fuse2", rb3)
}
