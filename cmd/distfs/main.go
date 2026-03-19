// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/tpm"
	"golang.org/x/term"
)

var (
	configPath    = flag.String("config", config.DefaultPath(), "Path to config file")
	usePinentry   = flag.Bool("use-pinentry", true, "Use pinentry for passphrase input")
	useTPM        = flag.Bool("use-tpm", false, "Use TPM to securely bind the master passphrase to this hardware")
	adminFlag     = flag.Bool("admin", false, "Enable admin bypass mode")
	disableDoH    = flag.Bool("disable-doh", false, "Disable DNS-over-HTTPS and use system resolver")
	allowInsecure = flag.Bool("allow-insecure", false, "Allow insecure TLS connections (skip verification)")
	rootID        = flag.String("root", "", "Specify target root directory ID")
	registryDir   = flag.String("registry", "/registry", "Directory to use for identity verification")
)

func setupTPMHasher() {
	config.TPMHasher = func(password []byte) ([]byte, error) {
		tpmDev, err := tpm.New()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TPM: %w", err)
		}
		defer tpmDev.Close()

		baseDir := filepath.Dir(*configPath)
		hmacKeyPath := filepath.Join(baseDir, "tpm_hmac.key")
		var hmacKey *tpm.Key

		if b, err := os.ReadFile(hmacKeyPath); err == nil {
			hmacKey, err = tpmDev.UnmarshalKey(b)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal TPM HMAC key: %w", err)
			}
		} else {
			hmacKey, err = tpmDev.CreateKey(tpm.WithHMAC(256))
			if err != nil {
				return nil, fmt.Errorf("failed to create TPM HMAC key: %w", err)
			}
			marshaled, err := hmacKey.Marshal()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal TPM HMAC key: %w", err)
			}
			if err := os.WriteFile(hmacKeyPath, marshaled, 0600); err != nil {
				return nil, fmt.Errorf("failed to save TPM HMAC key: %w", err)
			}
		}

		boundHash, err := hmacKey.HMAC(password)
		if err != nil {
			return nil, fmt.Errorf("failed to compute TPM HMAC: %w", err)
		}
		return []byte(hex.EncodeToString(boundHash)), nil
	}
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if os.Getenv("DISTFS_ALLOW_INSECURE") == "true" {
		*allowInsecure = true
	}

	if *useTPM {
		setupTPMHasher()
	}

	if flag.NArg() == 0 {
		usage()
	}

	config.UsePinentry = *usePinentry

	ctx := context.Background()
	command := flag.Arg(0)
	args := flag.Args()[1:]

	switch command {
	case "init":
		cmdInit(ctx, args)
	case "ls":
		cmdLs(ctx, args)
	case "mkdir":
		cmdMkdir(ctx, args)
	case "put":
		cmdPut(ctx, args)
	case "get":
		cmdGet(ctx, args)
	case "cp":
		cmdCp(ctx, args)
	case "mv":
		cmdMv(ctx, args)
	case "ln":
		cmdLn(ctx, args)
	case "rm":
		cmdRm(ctx, args)
	case "cat":
		cmdCat(ctx, args)
	case "head":
		cmdHead(ctx, args)
	case "tail":
		cmdTail(ctx, args)
	case "stat":
		cmdStat(ctx, args)
	case "du":
		cmdDu(ctx, args)
	case "df":
		cmdDf(ctx, args)
	case "touch":
		cmdTouch(ctx, args)
	case "getfacl":
		cmdGetFacl(ctx, args)
	case "setfacl":
		cmdSetFacl(ctx, args)
	case "chmod":
		cmdChmod(ctx, args)
	case "chgrp":
		cmdChgrp(ctx, args)
	case "group-create":
		cmdGroupCreate(ctx, args)
	case "group-list":
		cmdGroupList(ctx, args)
	case "group-add":
		cmdGroupAdd(ctx, args)
	case "group-remove":
		cmdGroupRemove(ctx, args)
	case "group-chown":
		cmdGroupChown(ctx, args)
	case "group-members":
		cmdGroupMembers(ctx, args)
	case "contact-info":
		cmdContactInfo(ctx, args)
	case "admin":
		cmdAdmin(ctx, args)
	case "admin-join":
		cmdAdminJoin(ctx, args)
	case "admin-remove":
		cmdAdminRemove(ctx, args)
	case "registry-add":
		cmdRegistryAdd(ctx, args)
	case "admin-lock-user":
		cmdAdminLockUser(ctx, args, true)
	case "admin-unlock-user":
		cmdAdminLockUser(ctx, args, false)
	case "admin-user-quota":
		cmdAdminUserQuota(ctx, args)
	case "admin-group-quota":
		cmdAdminGroupQuota(ctx, args)
	case "admin-promote":
		cmdAdminPromote(ctx, args)
	case "admin-audit":
		cmdAdminAudit(ctx, args)
	case "admin-create-root":
		cmdAdminCreateRoot(ctx, args)
	case "whoami":
		cmdWhoami(ctx, args)
	case "quota":
		cmdQuota(ctx, args)
	case "dump-inodes":
		cmdDumpInodes(ctx, args)
	default:
		usage()
	}
}

func cmdWhoami(ctx context.Context, args []string) {
	c := loadClient()
	fmt.Println(c.UserID())
}

func isHexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func usage() {
	fmt.Println("Usage: distfs [-config <path>] [-use-pinentry] [-admin] <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  init [--new] -server <url>      Initialize client config (pulls existing keys by default)")
	fmt.Println("  ls <path>                       List directory")
	fmt.Println("  mkdir [--owner=id] <path>       Create directory (Admin can specify owner)")
	fmt.Println("  put <local> <remote>            Upload a file")
	fmt.Println("  get <remote> <local>            Download a file")
	fmt.Println("  cp <src> <dst>                  Copy a file or directory")
	fmt.Println("  mv <src> <dst>                  Move or rename a file or directory")
	fmt.Println("  rm <path>                       Delete file or directory")
	fmt.Println("  ln [-s] <target> <link>         Create a hard or symbolic link")
	fmt.Println("  cat <path>                      Display file content")
	fmt.Println("  head [-n N] <path>              Display first lines of a file")
	fmt.Println("  tail [-n N] <path>              Display last lines of a file")
	fmt.Println("  stat <path>                     Display file status")
	fmt.Println("  du [-h] <path>                  Display disk usage")
	fmt.Println("  df [-h]                         Display filesystem usage")
	fmt.Println("  touch <path>                    Create empty file or update timestamp")
	fmt.Println("  getfacl <path>                  Get file access control lists")
	fmt.Println("  setfacl [-m spec] [-x spec] <p> Modify file access control lists")
	fmt.Println("  chmod <mode> <path>             Change permissions")
	fmt.Println("  chgrp <group_id> <path>         Change group")
	fmt.Println("  group-create <name>             Create a new group")
	fmt.Println("  group-list                      List groups you are member or manager of")
	fmt.Println("  group-add [-f] <group_id> <user_id|contact_string> [info] Add user to group")
	fmt.Println("  group-remove <group_id> <user_id> Remove user from group")
	fmt.Println("  group-chown <group_id> <owner>  Change group owner")
	fmt.Println("  group-members <group_id>        List group members (info shown if owner)")
	fmt.Println("  contact-info                    Display your signed contact string for sharing")
	fmt.Println("  quota                           Display your resource usage and limits")
	fmt.Println("  put <local> <remote>            Upload file")
	fmt.Println("  get <remote> <local>            Download file")
	fmt.Println("  admin                           Open interactive cluster management console")
	fmt.Println("  admin-join <addr>               Add a node to the cluster (discovered via address)")
	fmt.Println("  admin-remove <id>               Remove a node from the cluster (by node ID)")
	fmt.Println("  admin-user-quota <userID> <max_bytes> <max_inodes> Set user quota (Admin only)")
	fmt.Println("  admin-group-quota <group_id> <max_bytes> <max_inodes> Set group quota (Admin only)")
	fmt.Println("  admin-lock-user <userID>        Lock a user account")
	fmt.Println("  admin-unlock-user <userID>      Unlock a user account")
	fmt.Println("  registry-add [--unlock] [--quota <limit>] [--home] <username> <userID> Verify and add a user to the registry")
	fmt.Println("  admin-audit                     Run a comprehensive system integrity and structural audit")
	fmt.Println("  admin-create-root [-secondary]  Initialize a new root inode (Admin only, defaults to standard root)")
	fmt.Println("  whoami                          Display your user ID")
	fmt.Println("  dump-inodes [path|id]           Recursively dump inode metadata for debugging")
	os.Exit(1)
}

func cmdInit(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	serverURL := fs.String("server", "http://localhost:8080", "Metadata Server URL")
	isNew := fs.Bool("new", false, "Initialize a new account")

	// Auth flags
	jwt := fs.String("jwt", "", "OIDC JWT for authentication")
	clientID := fs.String("client-id", "distfs", "The client ID")
	scopes := fs.String("scopes", "openid", "The scopes to request (comma separated)")
	authEndpoint := fs.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint := fs.String("token-endpoint", "", "The token endpoint")
	qrCode := fs.Bool("qr", false, "Show a QR code of the verification URL")
	browser := fs.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")

	fs.Parse(args)

	opts := client.OnboardingOptions{
		ConfigPath:    *configPath,
		ServerURL:     *serverURL,
		IsNew:         *isNew,
		JWT:           *jwt,
		ClientID:      *clientID,
		Scopes:        strings.Split(*scopes, ","),
		AuthEndpoint:  *authEndpoint,
		TokenEndpoint: *tokenEndpoint,
		ShowQR:        *qrCode,
		Browser:       *browser,
		DisableDoH:    *disableDoH,
		AllowInsecure: *allowInsecure,
	}

	if err := client.PerformUnifiedOnboarding(ctx, opts); err != nil {
		log.Fatal(err)
	}
}

func loadClient() *client.Client {
	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	c := client.NewClient(conf.ServerURL).
		WithAllowInsecure(*allowInsecure).
		WithDisableDoH(*disableDoH)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	dk, _ := crypto.UnmarshalDecapsulationKey(dkBytes)

	skBytes, _ := hex.DecodeString(conf.SignKey)
	sk := crypto.UnmarshalIdentityKey(skBytes)

	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)
	svKey, err := crypto.UnmarshalEncapsulationKey(svKeyBytes)
	if err != nil {
		log.Fatalf("failed to unmarshal server key: %v", err)
	}

	c = c.WithIdentity(conf.UserID, dk).
		WithSignKey(sk).
		WithServerKey(svKey).
		WithRootAnchor(conf.RootID, conf.RootOwner, conf.RootVersion).
		WithAdmin(*adminFlag).
		WithDisableDoH(*disableDoH).
		WithAllowInsecure(*allowInsecure).
		WithRegistry(*registryDir)

	if *rootID != "" {
		c = c.WithRootID(*rootID)
	}
	return c
}

func saveClient(c *client.Client) {
	conf, err := config.Load(*configPath)
	if err != nil {
		// If we can't load it, we can't save it (need the password for encryption)
		return
	}

	rid, rowner, rver := c.GetRootAnchor()
	if rid == conf.RootID && rowner == conf.RootOwner && rver == conf.RootVersion {
		return // No change
	}

	conf.RootID = rid
	conf.RootOwner = rowner
	conf.RootVersion = rver

	// We need the password. config.Save will prompt for it.
	// This might be annoying for every 'ls' if the version changes often.
	// For now, let's only save if explicitly requested or on 'init'.
	// Actually, let's just NOT save automatically in the CLI for now to avoid UX friction.
	// In distfs-fuse it makes more sense.
}

type LSClient interface {
	ResolvePath(ctx context.Context, path string) (*metadata.Inode, []byte, error)
	ReadDirExtended(ctx context.Context, path string, fetchMetadata bool) ([]*client.DistDirEntry, error)
	ReadDirRecursive(ctx context.Context, path string) (map[string][]*client.DistDirEntry, error)
	NewDirEntry(inode *metadata.Inode, name string, key []byte) *client.DistDirEntry
	UserID() string
}

func cmdLs(ctx context.Context, args []string) {
	c := loadClient()
	runLs(ctx, c, args)
}

func runLs(ctx context.Context, c LSClient, args []string) {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	long := fs.Bool("l", false, "Long format")
	all := fs.Bool("a", false, "Show hidden files")
	human := fs.Bool("h", false, "Human readable sizes")
	inode := fs.Bool("i", false, "Print inode ID")
	recursive := fs.Bool("R", false, "Recursive")
	directory := fs.Bool("d", false, "List directory itself")
	sortByTime := fs.Bool("t", false, "Sort by time")
	sortBySize := fs.Bool("S", false, "Sort by size")
	reverse := fs.Bool("r", false, "Reverse sort order")
	oneCol := fs.Bool("1", false, "One per line")
	classify := fs.Bool("F", false, "Classify entries")

	fs.Parse(args)
	path := "/"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if *directory {
		// Resolve path to get its inode
		inodeInfo, key, err := c.ResolvePath(ctx, path)
		if err != nil {
			log.Fatal(err)
		}

		name := path
		if path == "/" {
			name = "/"
		} else {
			name = filepath.Base(path)
		}

		entry := c.NewDirEntry(inodeInfo, name, key)
		processAndPrintEntries(os.Stdout, []*client.DistDirEntry{entry}, *long, *all, *human, *inode, *classify, *oneCol, *sortByTime, *sortBySize, *reverse)
		return
	}

	if *recursive {
		results, err := c.ReadDirRecursive(ctx, path)
		if err != nil {
			log.Fatal(err)
		}
		// Sort paths for consistent output
		var paths []string
		for p := range results {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		for i, p := range paths {
			if len(paths) > 1 {
				fmt.Printf("%s:\n", p)
			}
			entries := results[p]
			processAndPrintEntries(os.Stdout, entries, *long, *all, *human, *inode, *classify, *oneCol, *sortByTime, *sortBySize, *reverse)
			if i < len(paths)-1 {
				fmt.Println()
			}
		}
	} else {
		entries, err := c.ReadDirExtended(ctx, path, *long || *classify || *sortByTime || *sortBySize)
		if err != nil {
			log.Fatal(err)
		}
		processAndPrintEntries(os.Stdout, entries, *long, *all, *human, *inode, *classify, *oneCol, *sortByTime, *sortBySize, *reverse)
	}
}

func processAndPrintEntries(w io.Writer, entries []*client.DistDirEntry, long, all, human, inode, classify, oneCol, sortByTime, sortBySize, reverse bool) {
	var filtered []*client.DistDirEntry
	for _, e := range entries {
		if !all && strings.HasPrefix(e.Name(), ".") {
			continue
		}
		filtered = append(filtered, e)
	}

	sort.Slice(filtered, func(i, j int) bool {
		var res bool
		if sortByTime {
			if !filtered[i].ModTime().Equal(filtered[j].ModTime()) {
				res = filtered[i].ModTime().After(filtered[j].ModTime())
			} else {
				res = filtered[i].Name() < filtered[j].Name()
			}
		} else if sortBySize {
			if filtered[i].Size() != filtered[j].Size() {
				res = filtered[i].Size() > filtered[j].Size()
			} else {
				res = filtered[i].Name() < filtered[j].Name()
			}
		} else {
			res = filtered[i].Name() < filtered[j].Name()
		}
		if reverse {
			return !res
		}
		return res
	})

	if long {
		// Calculate max widths for alignment
		maxSize := 0
		for _, e := range filtered {
			s := len(strconv.FormatInt(e.Size(), 10))
			if human {
				s = len(client.FormatBytes(e.Size()))
			}
			if s > maxSize {
				maxSize = s
			}
		}

		for _, e := range filtered {
			if inode {
				fmt.Fprintf(w, "%s ", e.InodeID())
			}
			mode := e.Mode().String()
			sizeStr := strconv.FormatInt(e.Size(), 10)
			if human {
				sizeStr = client.FormatBytes(e.Size())
			}
			mtime := e.ModTime().Format("Jan _2 15:04")
			name := e.Name()
			if classify {
				if e.IsDir() {
					name += "/"
				}
			}
			// Format: mode  size  mtime  name
			fmt.Fprintf(w, "%s %*s %s %s\n", mode, maxSize, sizeStr, mtime, name)
		}
	} else {
		if oneCol {
			for _, e := range filtered {
				name := e.Name()
				if inode {
					name = e.InodeID()[:8] + " " + name
				}
				if classify && e.IsDir() {
					name += "/"
				}
				fmt.Fprintln(w, name)
			}
			return
		}

		// Multi-column output
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil || width <= 0 {
			width = 80 // Fallback
		}

		maxNameWidth := 0
		names := make([]string, len(filtered))
		for i, e := range filtered {
			name := e.Name()
			if inode {
				name = e.InodeID()[:8] + " " + name
			}
			if classify && e.IsDir() {
				name += "/"
			}
			names[i] = name
			if len(name) > maxNameWidth {
				maxNameWidth = len(name)
			}
		}

		colWidth := maxNameWidth + 2
		cols := width / colWidth
		if cols <= 0 {
			cols = 1
		}

		for i, name := range names {
			fmt.Fprintf(w, "%-*s", colWidth, name)
			if (i+1)%cols == 0 {
				fmt.Fprintln(w)
			}
		}
		if len(names)%cols != 0 {
			fmt.Fprintln(w)
		}
	}
}

func cmdMkdir(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("mkdir", flag.ExitOnError)
	ownerID := fs.String("owner", "", "Specify owner ID (Admin only)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatal("path required")
	}
	path := fs.Arg(0)
	c := loadClient()

	opts := client.MkdirOptions{}
	if *ownerID != "" {
		resolvedOwner, _, err := c.ResolveUsername(ctx, *ownerID)
		if err != nil {
			log.Fatalf("failed to resolve owner %s: %v", *ownerID, err)
		}
		opts.OwnerID = resolvedOwner
	}

	if err := c.MkdirExtended(ctx, path, 0700, opts); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Directory %s created.\n", path)
}

func cmdRm(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("path required")
	}
	path := args[0]
	c := loadClient()
	if err := c.Remove(ctx, path); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Removed %s\n", path)
}

func cmdMv(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("source and destination paths required")
	}
	src, dst := args[0], args[1]
	c := loadClient()
	if err := c.Rename(ctx, src, dst); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Moved %s to %s\n", src, dst)
}

func cmdCp(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("source and destination paths required")
	}
	src, dst := args[0], args[1]
	c := loadClient()
	if err := c.Copy(ctx, src, dst); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Copied %s to %s\n", src, dst)
}

func cmdLn(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("ln", flag.ExitOnError)
	symbolic := fs.Bool("s", false, "Create a symbolic link")
	fs.Parse(args)

	if fs.NArg() < 2 {
		log.Fatal("target and link_path required")
	}
	target, linkPath := fs.Arg(0), fs.Arg(1)
	c := loadClient()

	var err error
	if *symbolic {
		err = c.Symlink(ctx, target, linkPath)
	} else {
		err = c.Link(ctx, target, linkPath)
	}

	if err != nil {
		log.Fatal(err)
	}
	if *symbolic {
		fmt.Printf("Created symbolic link %s -> %s\n", linkPath, target)
	} else {
		fmt.Printf("Created hard link %s -> %s\n", linkPath, target)
	}
}

func cmdCat(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("path required")
	}
	path := args[0]
	c := loadClient()
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		log.Fatal(err)
	}

	rc, err := c.ReadFile(ctx, inode.ID, key)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()

	io.Copy(os.Stdout, rc)
}

func cmdHead(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("head", flag.ExitOnError)
	lines := fs.Int("n", 10, "Number of lines to show")
	fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatal("path required")
	}
	path := fs.Arg(0)
	c := loadClient()
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		log.Fatal(err)
	}

	rc, err := c.ReadFile(ctx, inode.ID, key)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()

	// Simple line-based head
	scanner := bufio.NewScanner(rc)
	for i := 0; i < *lines && scanner.Scan(); i++ {
		fmt.Println(scanner.Text())
	}
}

func cmdTail(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	lines := fs.Int("n", 10, "Number of lines to show")
	fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatal("path required")
	}
	path := fs.Arg(0)
	c := loadClient()
	inode, key, err := c.ResolvePath(ctx, path)
	if err != nil {
		log.Fatal(err)
	}

	r, err := c.NewReader(ctx, inode.ID, key)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	// For tail, we can't easily seek lines from the end without reading backwards.
	// But we can seek to a reasonable estimate or just read the whole file if it's small.
	// For now, let's read the whole file and keep last N lines.
	var lastLines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lastLines = append(lastLines, scanner.Text())
		if len(lastLines) > *lines {
			lastLines = lastLines[1:]
		}
	}

	for _, line := range lastLines {
		fmt.Println(line)
	}
}

func cmdStat(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("path required")
	}
	path := args[0]
	c := loadClient()
	info, err := c.Lstat(ctx, path)
	if err != nil {
		log.Fatal(err)
	}

	inode := info.Sys().(*metadata.Inode)
	fmt.Printf("  File: %s\n", info.Name())
	fmt.Printf("  Size: %-15d Blocks: %-10d IO Block: %-10d ", info.Size(), (info.Size()+511)/512, 4096)
	switch inode.Type {
	case metadata.DirType:
		fmt.Println("directory")
	case metadata.FileType:
		fmt.Println("regular file")
	case metadata.SymlinkType:
		fmt.Printf("symbolic link -> %s\n", inode.GetSymlinkTarget())
	}
	fmt.Printf("Device: %-15s Inode: %-15s Links: %-10d\n", "distfs", inode.ID[:16], inode.NLink)
	fmt.Printf("Access: (%04o/%s)  Uid: (%-8s)   Gid: (%-8s)\n", info.Mode().Perm(), info.Mode().String(), inode.OwnerID[:8], inode.GroupID)
	fmt.Printf("Modify: %s\n", info.ModTime().Format(time.RFC3339))
}

func cmdDu(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("du", flag.ExitOnError)
	human := fs.Bool("h", false, "Human readable sizes")
	fs.Parse(args)

	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	c := loadClient()
	var totalSize int64

	var walk func(string) error
	walk = func(p string) error {
		info, err := c.Stat(ctx, p)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
			return nil
		}
		entries, err := c.ReadDirExtended(ctx, p, true)
		if err != nil {
			return err
		}
		for _, e := range entries {
			childPath := filepath.Join(p, e.Name())
			if err := walk(childPath); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(path); err != nil {
		log.Fatal(err)
	}

	if *human {
		fmt.Printf("%s\t%s\n", client.FormatBytes(totalSize), path)
	} else {
		fmt.Printf("%d\t%s\n", totalSize, path)
	}
}

func cmdDf(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("df", flag.ExitOnError)
	human := fs.Bool("h", false, "Human readable sizes")
	fs.Parse(args)

	c := loadClient()
	quota, usage, err := c.GetQuota(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%-20s %-10s %-10s %-10s %-10s\n", "Filesystem", "Size", "Used", "Avail", "Use%")

	sizeStr := strconv.FormatInt(quota.MaxBytes, 10)
	usedStr := strconv.FormatInt(usage.TotalBytes, 10)
	availStr := strconv.FormatInt(quota.MaxBytes-usage.TotalBytes, 10)
	if quota.MaxBytes == 0 {
		sizeStr = "Inf"
		availStr = "Inf"
	}

	if *human {
		sizeStr = client.FormatBytes(quota.MaxBytes)
		if quota.MaxBytes == 0 {
			sizeStr = "Inf"
		}
		usedStr = client.FormatBytes(usage.TotalBytes)
		availStr = client.FormatBytes(quota.MaxBytes - usage.TotalBytes)
		if quota.MaxBytes == 0 {
			availStr = "Inf"
		}
	}

	percent := "0%"
	if quota.MaxBytes > 0 {
		percent = fmt.Sprintf("%d%%", (usage.TotalBytes*100)/quota.MaxBytes)
	}

	fmt.Printf("%-20s %-10s %-10s %-10s %-10s\n", "distfs", sizeStr, usedStr, availStr, percent)
}

func cmdTouch(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("path required")
	}
	path := args[0]
	c := loadClient()

	// Try to resolve path
	_, err := c.Stat(ctx, path)
	if err == nil {
		// File exists, update MTime
		now := time.Now().UnixNano()
		err = c.SetAttr(ctx, path, metadata.SetAttrRequest{MTime: &now})
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	// File doesn't exist, create it
	err = c.CreateFile(ctx, path, bytes.NewReader(nil), 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created empty file %s\n", path)
}

func cmdGetFacl(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("path required")
	}
	path := args[0]
	c := loadClient()
	info, err := c.Stat(ctx, path)
	if err != nil {
		log.Fatal(err)
	}

	inode := info.Sys().(*metadata.Inode)
	fmt.Printf("# file: %s\n", info.Name())
	fmt.Printf("# owner: %s\n", inode.OwnerID[:8])
	fmt.Printf("# group: %s\n", inode.GroupID)

	// Base permissions
	fmt.Printf("user::%s\n", formatPerms((inode.Mode>>6)&7))

	if inode.AccessACL != nil {
		for uid, bits := range inode.AccessACL.Users {
			fmt.Printf("user:%s:%s\n", uid[:8], formatPerms(bits))
		}
	}

	fmt.Printf("group::%s\n", formatPerms((inode.Mode>>3)&7))

	if inode.AccessACL != nil {
		for gid, bits := range inode.AccessACL.Groups {
			fmt.Printf("group:%s:%s\n", gid, formatPerms(bits))
		}
		if inode.AccessACL.Mask != nil {
			fmt.Printf("mask::%s\n", formatPerms(*inode.AccessACL.Mask))
		}
	}

	fmt.Printf("other::%s\n", formatPerms(inode.Mode&7))
}

func formatPerms(bits uint32) string {
	res := ""
	if bits&4 != 0 {
		res += "r"
	} else {
		res += "-"
	}
	if bits&2 != 0 {
		res += "w"
	} else {
		res += "-"
	}
	if bits&1 != 0 {
		res += "x"
	} else {
		res += "-"
	}
	return res
}

func parsePerms(s string) (uint32, error) {
	if len(s) == 3 {
		var res uint32
		if s[0] == 'r' {
			res |= 4
		}
		if s[1] == 'w' {
			res |= 2
		}
		if s[2] == 'x' {
			res |= 1
		}
		return res, nil
	}
	p, err := strconv.ParseUint(s, 8, 32)
	return uint32(p), err
}

func cmdSetFacl(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("setfacl", flag.ExitOnError)
	modify := fs.String("m", "", "Modify ACL entries (e.g. u:user:rw-)")
	remove := fs.String("x", "", "Remove ACL entries (e.g. u:user)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatal("path required")
	}
	path := fs.Arg(0)
	c := loadClient()
	info, err := c.Stat(ctx, path)
	if err != nil {
		log.Fatal(err)
	}
	inode := info.Sys().(*metadata.Inode)

	acl := inode.AccessACL
	if acl == nil {
		acl = &metadata.POSIXAccess{
			Users:  make(map[string]uint32),
			Groups: make(map[string]uint32),
		}
	}

	if *modify != "" {
		parts := strings.Split(*modify, ":")
		if len(parts) < 3 {
			log.Fatal("invalid modify spec, expected type:id:perms")
		}
		t, id, permsStr := parts[0], parts[1], parts[2]
		bits, err := parsePerms(permsStr)
		if err != nil {
			log.Fatalf("invalid permissions: %v", err)
		}

		switch t {
		case "u", "user":
			resolvedID, _, err := c.ResolveUsername(ctx, id)
			if err != nil {
				log.Fatalf("failed to resolve user %s: %v", id, err)
			}
			acl.Users[resolvedID] = bits
		case "g", "group":
			acl.Groups[id] = bits
		case "m", "mask":
			acl.Mask = &bits
		default:
			log.Fatalf("unsupported ACL type: %s", t)
		}
	}

	if *remove != "" {
		parts := strings.Split(*remove, ":")
		if len(parts) < 2 {
			log.Fatal("invalid remove spec, expected type:id")
		}
		t, id := parts[0], parts[1]
		switch t {
		case "u", "user":
			resolvedID, _, err := c.ResolveUsername(ctx, id)
			if err == nil {
				delete(acl.Users, resolvedID)
			}
		case "g", "group":
			delete(acl.Groups, id)
		}
	}

	if err := c.SetAttr(ctx, path, metadata.SetAttrRequest{AccessACL: acl}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ACL of %s updated.\n", path)
}

func cmdChmod(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("mode and path required")
	}
	modeStr, path := args[0], args[1]
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		log.Fatalf("invalid mode: %v", err)
	}

	c := loadClient()
	m32 := uint32(mode)
	if err := c.SetAttr(ctx, path, metadata.SetAttrRequest{Mode: &m32}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Mode of %s changed to %s\n", path, modeStr)
}

func cmdChgrp(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("group_id and path required")
	}
	groupID, path := args[0], args[1]

	c := loadClient()
	if err := c.SetAttr(ctx, path, metadata.SetAttrRequest{GroupID: &groupID}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Group of %s changed to %s\n", path, groupID)
}

func cmdGroupCreate(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("group-create", flag.ExitOnError)
	quota := fs.Bool("quota", false, "Enable independent group quota (charged to group, not owner)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatal("group name required")
	}
	name := fs.Arg(0)
	c := loadClient()
	group, err := c.CreateGroup(ctx, name, *quota)
	if err != nil {
		if errors.Is(err, metadata.ErrExists) {
			// Find existing group ID for automated tools
			if g, _, rerr := c.ResolvePath(ctx, "/.groups/"+name); rerr == nil {
				log.Printf("Group %s already exists (%s)", name, g.ID)
				return
			}
		}
		log.Fatal(err)
	}
	fmt.Printf("Group %s created.\n", name)
	fmt.Printf("ID: %s\n", group.ID)
	fmt.Printf("QuotaEnabled: %v\n", group.QuotaEnabled)
}

func cmdGroupAdd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("group-add", flag.ExitOnError)
	force := fs.Bool("f", false, "Force add without confirmation")
	fs.Parse(args)

	if fs.NArg() < 2 {
		log.Fatal("group_id and user_id/contact_string required")
	}
	groupID, userArg := fs.Arg(0), fs.Arg(1)
	info := ""
	if fs.NArg() > 2 {
		info = fs.Arg(2)
	}
	c := loadClient()

	userID := userArg
	var ci *client.ContactInfo
	if strings.HasPrefix(userArg, "distfs-contact:v1:") {
		var err error
		ci, err = c.ParseContactString(userArg)
		if err != nil {
			log.Fatalf("Invalid contact string: %v", err)
		}
		userID = ci.UserID
		fmt.Printf("Parsed contact string:\n")
		fmt.Printf("  User ID:    %s\n", ci.UserID)
		fmt.Printf("  Created At: %s\n", time.Unix(ci.Timestamp, 0).Format(time.RFC3339))

		if !*force {
			fmt.Printf("Add this user to group %s? [y/N]: ", groupID)
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" {
				fmt.Println("Aborted.")
				return
			}
		}
	} else {
		var err error
		var entry *client.DirectoryEntry
		userID, entry, err = c.ResolveUsername(ctx, userArg)
		if err != nil {
			log.Fatalf("Failed to resolve user %s: %v", userArg, err)
		}
		if entry != nil && entry.EncKey != nil {
			// Phase 49: Convert Registry Entry to ContactInfo for OOB pinning
			ci = &client.ContactInfo{
				UserID:    entry.UserID,
				EncKey:    entry.EncKey,
				SignKey:   entry.SignKey,
				Timestamp: entry.Timestamp,
				Signature: entry.Signature,
			}
		}
	}

	if err := c.AddUserToGroup(ctx, groupID, userID, info, ci); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User %s added to group %s\n", userID, groupID)
}

func cmdContactInfo(ctx context.Context, args []string) {
	c := loadClient()
	s, err := c.GenerateContactString()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Your DistFS Contact String:")
	fmt.Println(s)
}

func cmdGroupMembers(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("group_id required")
	}
	groupID := args[0]
	c := loadClient()

	fmt.Printf("Members of group %s:\n", groupID)
	fmt.Printf("%-64s %s\n", "User ID", "User Info")
	fmt.Println(strings.Repeat("-", 80))
	for m, err := range c.GetGroupMembers(ctx, groupID) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%-64s %s\n", m.UserID, m.Info)
	}
}

func cmdGroupRemove(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("group_id and user_id required")
	}
	groupID, userID := args[0], args[1]
	c := loadClient()
	if err := c.RemoveUserFromGroup(ctx, groupID, userID); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User %s removed from group %s\n", userID, groupID)
}

func cmdGroupList(ctx context.Context, args []string) {
	c := loadClient()

	fmt.Printf("%-32s %-20s %s\n", "Group ID", "Name", "Role")
	fmt.Println(strings.Repeat("-", 80))
	for e, err := range c.ListGroups(ctx) {
		if err != nil {
			log.Fatal(err)
		}
		name := "[HIDDEN]"
		if decrypted, err := c.DecryptGroupName(ctx, e); err == nil {
			name = decrypted
		}
		if e.IsSystem {
			name = "[SYSTEM] " + name
		}
		fmt.Printf("%-32s %-20s %s\n", e.ID, name, e.Role)
	}
}

func cmdPut(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("local and remote paths required")
	}
	local, remote := args[0], args[1]
	f, err := os.Open(local)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}

	c := loadClient()
	if err := c.CreateFile(ctx, remote, f, info.Size()); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("File %s uploaded to %s.\n", local, remote)
}

func cmdGet(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("remote and local paths required")
	}
	remote, local := args[0], args[1]
	c := loadClient()
	inode, key, err := c.ResolvePath(ctx, remote)
	if err != nil {
		log.Fatal(err)
	}

	rc, err := c.ReadFile(ctx, inode.ID, key)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()

	f, err := os.Create(local)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err := io.Copy(f, rc); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("File %s downloaded to %s.\n", remote, local)
}

func cmdGroupChown(ctx context.Context, args []string) {
	if len(args) < 2 {
		log.Fatal("group_id and owner required")
	}
	groupID, ownerID := args[0], args[1]
	c := loadClient()
	if err := c.GroupChown(ctx, groupID, ownerID); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Owner of group %s changed to %s\n", groupID, ownerID)
}

func cmdQuota(ctx context.Context, args []string) {
	c := loadClient()
	user, err := c.GetUser(ctx, c.UserID())
	if err != nil {
		log.Fatalf("Failed to fetch user info: %v", err)
	}

	fmt.Printf("Personal Usage for %s:\n", c.UserID())
	displayUsage(user.Usage, user.Quota)

	managedGroups := 0
	for g, err := range c.ListGroups(ctx) {
		if err != nil {
			fmt.Printf("\nFailed to fetch group info: %v\n", err)
			return
		}
		if g.Role == metadata.RoleOwner || g.Role == metadata.RoleManager {
			if managedGroups == 0 {
				fmt.Println("Managed Group Quotas:")
			}
			managedGroups++
			fmt.Println()
			name := "[HIDDEN]"
			if decrypted, err := c.DecryptGroupName(ctx, g); err == nil {
				name = decrypted
			}
			fmt.Printf("Group: %s (%s)\n", name, g.ID)
			displayUsage(g.Usage, g.Quota)
		}
	}
}

func displayUsage(usage metadata.UserUsage, quota metadata.UserQuota) {
	fmt.Printf("  Inodes: %d / ", usage.InodeCount)
	if quota.MaxInodes > 0 {
		fmt.Printf("%d\n", quota.MaxInodes)
	} else {
		fmt.Println("Unlimited")
	}

	fmt.Printf("  Storage: %s / ", client.FormatBytes(usage.TotalBytes))
	if quota.MaxBytes > 0 {
		fmt.Printf("%s\n", client.FormatBytes(quota.MaxBytes))
	} else {
		fmt.Println("Unlimited")
	}
}
