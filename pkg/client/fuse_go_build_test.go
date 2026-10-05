//go:build !wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/data"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/hashicorp/raft"
)

func TestFUSE_GoBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FUSE E2E test in short mode")
	}

	// 1. Setup Metadata Node
	metaDir := t.TempDir()
	metaSt, _ := createTestStorageLocal(t, metaDir)
	nodeKey, _ := metadata.LoadOrGenerateNodeKey(metaSt, "node.key", nil)
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

	serverEK, serverDK, metaSignPK := bootstrapClusterLocal(t, metaNode)
	signKey, _ := crypto.GenerateIdentityKey()
	nodeDecKey, _ := crypto.GenerateEncryptionKey()
	metaServer := metadata.NewServer("meta1", metaNode.Raft, metaNode.FSM, "", signKey, "testsecret", nil, 0, metadata.NewNodeVault(metaSt), nodeDecKey, true)
	metaServer.RegisterEpochKey("key-1", serverDK)
	tsMeta := httptest.NewServer(metaServer)
	defer tsMeta.Close()
	defer metaServer.Shutdown()

	dk, _ := crypto.GenerateEncryptionKey()
	userSignKey, _ := crypto.GenerateIdentityKey()
	adminSK, _ := crypto.GenerateIdentityKey()
	user := metadata.User{
		ID:      "user-fuse-go",
		SignKey: userSignKey.Public(),
		EncKey:  dk.EncapsulationKey().Bytes(),
	}
	createUserLocal(t, metaNode, user, userSignKey, "admin", adminSK)

	// 2. Setup Data Node
	dataDir := t.TempDir()
	dataSt, _ := createTestStorageLocal(t, dataDir)
	dataStore, _ := data.NewDiskStore(dataSt)
	dataServer := data.NewServer(dataStore, metaSignPK, metaNode.FSM, data.NoopValidator{}, true, true)
	tsData := httptest.NewServer(dataServer)
	defer tsData.Close()

	node := metadata.Node{
		ID:      "data1",
		Address: tsData.URL,
		Status:  metadata.NodeStatusActive,
	}
	registerNodeLocal(t, tsMeta.URL, "testsecret", node)

	newClient := func() *Client {
		c := NewClient(tsMeta.URL)
		c = c.withIdentity("user-fuse-go", dk)
		c = c.withSignKey(userSignKey)
		c = c.withServerKey(serverEK)
		c = c.WithAdmin(true)
		return c
	}

	// 3. Initialize Backbone once
	adminClient := newClient()
	if err := adminClient.BootstrapFileSystem(t.Context()); err != nil {
		t.Fatalf("Initial BootstrapFileSystem failed: %v", err)
	}

	// Create user home directory
	if err := adminClient.MkdirExtended(t.Context(), "/users/user-fuse-go", 0755, MkdirOptions{OwnerID: "user-fuse-go"}); err != nil {
		t.Fatalf("Mkdir /users/user-fuse-go failed: %v", err)
	}

	// 4. Setup Client and Mount Point
	mountpoint := t.TempDir()
	c := newClient()

	oldDebug := fuse.Debug
	defer func() { fuse.Debug = oldDebug }()
	fuse.Debug = func(msg interface{}) {
		// Log FUSE debug messages (uncomment for verbose logs)
		// t.Logf("FUSE: %v", msg)
	}
	conn, err := fuse.Mount(mountpoint)
	if err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	filesys := NewFS(c)
	serverDone := make(chan error, 1)

	go func() {
		err := fs.Serve(conn, filesys)
		if err != nil {
			fmt.Printf("FUSE Serve exited with error: %v\n", err)
		} else {
			fmt.Printf("FUSE Serve exited cleanly\n")
		}
		serverDone <- err
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

	// Monitor FUSE server in background
	go func() {
		err := <-serverDone
		if err != nil {
			fmt.Printf("FUSE server exited unexpectedly during test: %v\n", err)
		}
	}()

	defer func() {
		t.Logf("Unmounting %s...", mountpoint)
		filesys.Close()
		if err := fuse.Unmount(mountpoint); err != nil {
			t.Logf("Unmount warning: %v", err)
		}
		conn.Close()
	}()

	// 5. Create project structure in distfs
	// We use /users/user-fuse-go as the base directory as distfs-fuse maps root to /
	// but the user's home is usually /users/user-fuse-go
	userBase := filepath.Join(mountpoint, "users", "user-fuse-go")
	// Ensure user directory exists (BootstrapFileSystem should have created it)
	if _, err := os.Stat(userBase); err != nil {
		t.Fatalf("User base directory %s does not exist: %v", userBase, err)
	}

	projectDir := filepath.Join(userBase, "hello")
	if err := os.Mkdir(projectDir, 0755); err != nil {
		t.Fatalf("Mkdir projectDir failed: %v", err)
	}

	mainGo := `package main
import "fmt"
func main() {
	fmt.Println("hello world from distfs")
}
`
	if err := os.WriteFile(filepath.Join(projectDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatalf("WriteFile main.go failed: %v", err)
	}

	// 6. Set GOPATH and GOCACHE outside distfs to speed up the test
	localTempDir := t.TempDir()
	goPath := filepath.Join(localTempDir, "gopath")
	if err := os.Mkdir(goPath, 0755); err != nil {
		t.Fatalf("Mkdir goPath failed: %v", err)
	}

	// Put GOCACHE in a local temp dir to avoid extreme slowness
	goCache := filepath.Join(localTempDir, "gocache")
	if err := os.Mkdir(goCache, 0755); err != nil {
		t.Fatalf("Mkdir goCache failed: %v", err)
	}
	// 7. Run go build
	t.Log("Running go build inside distfs...")
	buildCtx, buildCancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer buildCancel()
	cmd := exec.CommandContext(buildCtx, "go", "build", "-o", "hello-bin", "main.go")
	cmd.Dir = projectDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOPATH=%s", goPath),
		fmt.Sprintf("GOCACHE=%s", goCache),
		"GO111MODULE=off",
		"GOTOOLCHAIN=local",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOTELEMETRY=off",
		"GOPRIVATE=*",
	)

	start := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)
	t.Logf("go build took %v", duration)

	if err != nil {
		if buildCtx.Err() == context.DeadlineExceeded {
			t.Fatalf("go build timed out after 2 minutes")
		}
		if strings.Contains(err.Error(), "transport endpoint is not connected") {
			t.Fatalf("FUSE mount lost during build (transport endpoint not connected): %v\nOutput: %s", err, string(output))
		}
		t.Fatalf("go build failed: %v\nOutput: %s", err, string(output))
	}

	// 8. Verify the binary exists and is executable
	binPath := filepath.Join(projectDir, "hello-bin")
	fi, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("Stat hello-bin failed: %v", err)
	}
	t.Logf("Binary size: %d, mode: %v", fi.Size(), fi.Mode())

	// 9. Copy the binary out of FUSE
	localBinPath := filepath.Join(localTempDir, "hello-bin")
	binData, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("ReadFile hello-bin failed: %v", err)
	}
	if err := os.WriteFile(localBinPath, binData, 0755); err != nil {
		t.Fatalf("WriteFile local-bin failed: %v", err)
	}

	// 10. Run the binary locally
	t.Log("Running the built binary locally...")
	runCtx, runCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer runCancel()
	runCmd := exec.CommandContext(runCtx, localBinPath)
	runOutput, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running binary failed: %v\nOutput: %s", err, string(runOutput))
	}
	t.Logf("output: %q", runOutput)

	expected := "hello world from distfs\n"
	if string(runOutput) != expected {
		t.Fatalf("unexpected output: got %q, want %q", string(runOutput), expected)
	}

	t.Log("SUCCESS: go build and execution completed on distfs via FUSE")
}
