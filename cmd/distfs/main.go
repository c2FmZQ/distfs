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
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/c2FmZQ/tpm"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

var (
	appConfigPath    string
	appUsePinentry   bool
	appUseTPM        bool
	appAdminFlag     bool
	appDisableDoH    bool
	appAllowInsecure bool
	appRootID        string
	appRegistryDir   string
)

func setupTPMHasher() {
	config.TPMHasher = func(password []byte) ([]byte, error) {
		tpmDev, err := tpm.New()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TPM: %w", err)
		}
		defer tpmDev.Close()

		baseDir := filepath.Dir(appConfigPath)
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
	app := &cli.Command{
		Name:  "distfs",
		Usage: "Secure Distributed File System CLI",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Value:       config.DefaultPath(),
				Usage:       "Path to config file",
				Destination: &appConfigPath,
			},
			&cli.BoolFlag{
				Name:        "use-pinentry",
				Value:       true,
				Usage:       "Use pinentry for passphrase input",
				Destination: &appUsePinentry,
			},
			&cli.BoolFlag{
				Name:        "use-tpm",
				Value:       false,
				Usage:       "Use TPM to securely bind the master passphrase to this hardware",
				Destination: &appUseTPM,
			},
			&cli.BoolFlag{
				Name:        "admin",
				Value:       false,
				Usage:       "Enable admin bypass mode",
				Destination: &appAdminFlag,
			},
			&cli.BoolFlag{
				Name:        "disable-doh",
				Value:       false,
				Usage:       "Disable DNS-over-HTTPS and use system resolver",
				Destination: &appDisableDoH,
			},
			&cli.BoolFlag{
				Name:        "allow-insecure",
				Value:       false,
				Usage:       "Allow insecure TLS connections (skip verification)",
				Destination: &appAllowInsecure,
			},
			&cli.StringFlag{
				Name:        "root",
				Value:       "",
				Usage:       "Specify target root directory ID",
				Destination: &appRootID,
			},
			&cli.StringFlag{
				Name:        "registry",
				Value:       "/registry",
				Usage:       "Directory to use for identity verification",
				Destination: &appRegistryDir,
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if os.Getenv("DISTFS_ALLOW_INSECURE") == "true" {
				appAllowInsecure = true
			}
			if appUseTPM {
				setupTPMHasher()
			}
			config.UsePinentry = appUsePinentry
			return ctx, nil
		},
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initialize client config (pulls existing keys by default)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "server", Value: "http://localhost:8080", Usage: "Metadata Server URL"},
					&cli.BoolFlag{Name: "new", Value: false, Usage: "Initialize a new account"},
					&cli.StringFlag{Name: "jwt", Value: "", Usage: "OIDC JWT for authentication"},
					&cli.StringFlag{Name: "client-id", Value: "distfs", Usage: "The client ID"},
					&cli.StringFlag{Name: "scopes", Value: "openid", Usage: "The scopes to request (comma separated)"},
					&cli.StringFlag{Name: "auth-endpoint", Value: "", Usage: "The authorization endpoint"},
					&cli.StringFlag{Name: "token-endpoint", Value: "", Usage: "The token endpoint"},
					&cli.BoolFlag{Name: "qr", Value: false, Usage: "Show a QR code of the verification URL"},
					&cli.StringFlag{Name: "browser", Value: os.Getenv("BROWSER"), Usage: "The command to use to open the verification URL"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					opts := client.OnboardingOptions{
						ConfigPath:    appConfigPath,
						ServerURL:     cmd.String("server"),
						IsNew:         cmd.Bool("new"),
						JWT:           cmd.String("jwt"),
						ClientID:      cmd.String("client-id"),
						Scopes:        strings.Split(cmd.String("scopes"), ","),
						AuthEndpoint:  cmd.String("auth-endpoint"),
						TokenEndpoint: cmd.String("token-endpoint"),
						ShowQR:        cmd.Bool("qr"),
						Browser:       cmd.String("browser"),
						DisableDoH:    appDisableDoH,
						AllowInsecure: appAllowInsecure,
					}
					return client.PerformUnifiedOnboarding(ctx, opts)
				},
			},
			{
				Name:  "ls",
				Usage: "List directory",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "l", Aliases: []string{"long"}, Usage: "Long format"},
					&cli.BoolFlag{Name: "a", Aliases: []string{"all"}, Usage: "Show hidden files"},
					&cli.BoolFlag{Name: "h", Aliases: []string{"human"}, Usage: "Human readable sizes"},
					&cli.BoolFlag{Name: "i", Aliases: []string{"inode"}, Usage: "Print inode ID"},
					&cli.BoolFlag{Name: "R", Aliases: []string{"recursive"}, Usage: "Recursive"},
					&cli.BoolFlag{Name: "d", Aliases: []string{"directory"}, Usage: "List directory itself"},
					&cli.BoolFlag{Name: "t", Usage: "Sort by time"},
					&cli.BoolFlag{Name: "S", Usage: "Sort by size"},
					&cli.BoolFlag{Name: "r", Aliases: []string{"reverse"}, Usage: "Reverse sort order"},
					&cli.BoolFlag{Name: "1", Usage: "One per line"},
					&cli.BoolFlag{Name: "F", Aliases: []string{"classify"}, Usage: "Classify entries"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c := loadClient()
					return runLs(ctx, c, cmd)
				},
			},
			{
				Name:  "mkdir",
				Usage: "Create directory",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "owner", Usage: "Specify owner ID (Admin only)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					c := loadClient()
					opts := client.MkdirOptions{}
					if owner := cmd.String("owner"); owner != "" {
						resolvedOwner, _, err := c.ResolveUsername(ctx, owner)
						if err != nil {
							return fmt.Errorf("failed to resolve owner %s: %w", owner, err)
						}
						opts.OwnerID = resolvedOwner
					}
					if err := c.MkdirExtended(ctx, path, 0700, opts); err != nil {
						return err
					}
					fmt.Printf("Directory %s created.\n", path)
					return nil
				},
			},
			{
				Name:  "put",
				Usage: "Upload a file",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "Force overwrite existing file"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("local and remote paths required")
					}
					local, remote := cmd.Args().Get(0), cmd.Args().Get(1)
					return cmdPut(ctx, local, remote, cmd.Bool("f"))
				},
			},
			{
				Name:  "get",
				Usage: "Download a file",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("remote and local paths required")
					}
					return cmdGet(ctx, cmd.Args().Get(0), cmd.Args().Get(1))
				},
			},
			{
				Name:  "cp",
				Usage: "Copy a file or directory",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("source and destination paths required")
					}
					c := loadClient()
					if err := c.Copy(ctx, cmd.Args().Get(0), cmd.Args().Get(1)); err != nil {
						return err
					}
					fmt.Printf("Copied %s to %s\n", cmd.Args().Get(0), cmd.Args().Get(1))
					return nil
				},
			},
			{
				Name:  "mv",
				Usage: "Move or rename a file or directory",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("source and destination paths required")
					}
					c := loadClient()
					if err := c.Rename(ctx, cmd.Args().Get(0), cmd.Args().Get(1)); err != nil {
						return err
					}
					fmt.Printf("Moved %s to %s\n", cmd.Args().Get(0), cmd.Args().Get(1))
					return nil
				},
			},
			{
				Name:  "rm",
				Usage: "Delete file or directory",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					c := loadClient()
					if err := c.Remove(ctx, path); err != nil {
						return err
					}
					fmt.Printf("Removed %s\n", path)
					return nil
				},
			},
			{
				Name:  "ln",
				Usage: "Create a hard or symbolic link",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "s", Usage: "Create a symbolic link"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("target and link_path required")
					}
					target, linkPath := cmd.Args().Get(0), cmd.Args().Get(1)
					c := loadClient()
					var err error
					if cmd.Bool("s") {
						err = c.Symlink(ctx, target, linkPath)
					} else {
						err = c.Link(ctx, target, linkPath)
					}
					if err != nil {
						return err
					}
					if cmd.Bool("s") {
						fmt.Printf("Created symbolic link %s -> %s\n", linkPath, target)
					} else {
						fmt.Printf("Created hard link %s -> %s\n", linkPath, target)
					}
					return nil
				},
			},
			{
				Name:  "cat",
				Usage: "Display file content",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					c := loadClient()
					rc, err := c.OpenBlobRead(ctx, path)
					if err != nil {
						return err
					}
					defer rc.Close()
					_, err = io.Copy(os.Stdout, rc)
					return err
				},
			},
			{
				Name:  "head",
				Usage: "Display first lines of a file",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "n", Value: 10, Usage: "Number of lines to show"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					c := loadClient()
					rc, err := c.OpenBlobRead(ctx, path)
					if err != nil {
						return err
					}
					defer rc.Close()
					scanner := bufio.NewScanner(rc)
					for i := 0; i < int(cmd.Int("n")) && scanner.Scan(); i++ {
						fmt.Println(scanner.Text())
					}
					return nil
				},
			},
			{
				Name:  "tail",
				Usage: "Display last lines of a file",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "n", Value: 10, Usage: "Number of lines to show"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					c := loadClient()
					rc, err := c.OpenBlobRead(ctx, path)
					if err != nil {
						return err
					}
					defer rc.Close()
					var lastLines []string
					scanner := bufio.NewScanner(rc)
					for scanner.Scan() {
						lastLines = append(lastLines, scanner.Text())
						if len(lastLines) > int(cmd.Int("n")) {
							lastLines = lastLines[1:]
						}
					}
					for _, line := range lastLines {
						fmt.Println(line)
					}
					return nil
				},
			},
			{
				Name:  "stat",
				Usage: "Display file status",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					c := loadClient()
					info, err := c.Lstat(ctx, path)
					if err != nil {
						return err
					}
					inode := info.Sys().(*client.InodeInfo)
					fmt.Printf("  File: %s\n", info.Name())
					fmt.Printf("  Size: %-15d Blocks: %-10d IO Block: %-10d ", info.Size(), (info.Size()+511)/512, 4096)
					switch inode.Type {
					case metadata.DirType:
						fmt.Println("directory")
					case metadata.FileType:
						fmt.Println("regular file")
					case metadata.SymlinkType:
						fmt.Printf("symbolic link -> %s\n", inode.SymlinkTarget)
					}
					fmt.Printf("Device: %-15s Inode: %-15s Links: %-10d\n", "distfs", inode.ID[:16], inode.NLink)
					fmt.Printf("Access: (%04o/%s)  Uid: (%-8s)   Gid: (%-8s)\n", info.Mode().Perm(), info.Mode().String(), inode.OwnerID[:8], inode.GroupID)
					fmt.Printf("Modify: %s\n", info.ModTime().Format(time.RFC3339))
					return nil
				},
			},
			{
				Name:  "du",
				Usage: "Display disk usage",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "human", Aliases: []string{"H"}, Usage: "Human readable sizes"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						path = "."
					}
					return cmdDu(ctx, path, cmd.Bool("human"))
				},
			},
			{
				Name:  "df",
				Usage: "Display filesystem usage",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "human", Aliases: []string{"H"}, Usage: "Human readable sizes"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return cmdDf(ctx, cmd.Bool("human"))
				},
			},
			{
				Name:  "touch",
				Usage: "Create empty file or update timestamp",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					c := loadClient()
					_, err := c.Stat(ctx, path)
					if err == nil {
						return c.SetMTime(ctx, path, time.Now().UnixNano())
					}
					return c.CreateFile(ctx, path, bytes.NewReader(nil), 0)
				},
			},
			{
				Name:  "getfacl",
				Usage: "Get file access control lists",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					return cmdGetFacl(ctx, path)
				},
			},
			{
				Name:  "setfacl",
				Usage: "Modify file access control lists",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "m", Usage: "Modify ACL entries (e.g. u:user:rw-)"},
					&cli.StringFlag{Name: "x", Usage: "Remove ACL entries (e.g. u:user)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					path := cmd.Args().First()
					if path == "" {
						return errors.New("path required")
					}
					return cmdSetFacl(ctx, path, cmd.String("m"), cmd.String("x"))
				},
			},
			{
				Name:  "chmod",
				Usage: "Change permissions",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("mode and path required")
					}
					modeStr, path := cmd.Args().Get(0), cmd.Args().Get(1)
					mode, err := strconv.ParseUint(modeStr, 8, 32)
					if err != nil {
						return fmt.Errorf("invalid mode: %w", err)
					}
					c := loadClient()
					return c.Chmod(ctx, path, fs.FileMode(mode))
				},
			},
			{
				Name:  "chgrp",
				Usage: "Change group",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("group_id and path required")
					}
					c := loadClient()
					return c.Chgrp(ctx, cmd.Args().Get(1), cmd.Args().Get(0))
				},
			},
			{
				Name:  "group-create",
				Usage: "Create a new group",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "quota", Usage: "Enable independent group quota"},
					&cli.StringFlag{Name: "owner", Usage: "Initial group owner"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					name := cmd.Args().First()
					if name == "" {
						return errors.New("group name required")
					}
					return cmdGroupCreate(ctx, name, cmd.Bool("quota"), cmd.String("owner"))
				},
			},
			{
				Name:  "group-list",
				Usage: "List groups you are member or manager of",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return cmdGroupList(ctx)
				},
			},
			{
				Name:  "group-add",
				Usage: "Add user to group",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "Force add without confirmation"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("group_id and user_id required")
					}
					return cmdGroupAdd(ctx, cmd.Args().Get(0), cmd.Args().Get(1), cmd.Args().Get(2), cmd.Bool("f"))
				},
			},
			{
				Name:  "group-remove",
				Usage: "Remove user from group",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("group_id and user_id required")
					}
					return cmdGroupRemove(ctx, cmd.Args().Get(0), cmd.Args().Get(1))
				},
			},
			{
				Name:  "group-chown",
				Usage: "Change group owner",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("group_id and owner required")
					}
					c := loadClient()
					return c.GroupChown(ctx, cmd.Args().Get(0), cmd.Args().Get(1))
				},
			},
			{
				Name:  "group-members",
				Usage: "List group members",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return errors.New("group_id required")
					}
					return cmdGroupMembers(ctx, cmd.Args().First())
				},
			},
			{
				Name:  "contact-info",
				Usage: "Display your signed contact string for sharing",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c := loadClient()
					s, err := c.GenerateContactString()
					if err != nil {
						return err
					}
					fmt.Println(s)
					return nil
				},
			},
			{
				Name:  "whoami",
				Usage: "Display your user ID",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c := loadClient()
					fmt.Println(c.UserID())
					return nil
				},
			},
			{
				Name:  "quota",
				Usage: "Display your resource usage and limits",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return cmdQuota(ctx)
				},
			},
			{
				Name:  "admin",
				Usage: "Open interactive cluster management console",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					cmdAdmin(ctx, cmd.Args().Slice())
					return nil
				},
			},
			{
				Name:  "admin-join",
				Usage: "Add a node to the cluster",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return errors.New("node address required")
					}
					return cmdAdminJoin(ctx, cmd.Args().First())
				},
			},
			{
				Name:  "admin-remove",
				Usage: "Remove a node from the cluster",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return errors.New("node ID required")
					}
					return cmdAdminRemove(ctx, cmd.Args().First())
				},
			},
			{
				Name:  "admin-lock-user",
				Usage: "Lock a user account",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return errors.New("userID required")
					}
					return cmdAdminLockUser(ctx, cmd.Args().First(), true)
				},
			},
			{
				Name:  "admin-unlock-user",
				Usage: "Unlock a user account",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return errors.New("userID required")
					}
					return cmdAdminLockUser(ctx, cmd.Args().First(), false)
				},
			},
			{
				Name:  "admin-user-quota",
				Usage: "Set user quota",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 3 {
						return errors.New("userID, max_bytes, max_inodes required")
					}
					return cmdAdminUserQuota(ctx, cmd.Args().Get(0), cmd.Args().Get(1), cmd.Args().Get(2))
				},
			},
			{
				Name:  "admin-group-quota",
				Usage: "Set group quota",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 3 {
						return errors.New("groupID, max_bytes, max_inodes required")
					}
					return cmdAdminGroupQuota(ctx, cmd.Args().Get(0), cmd.Args().Get(1), cmd.Args().Get(2))
				},
			},
			{
				Name:  "admin-promote",
				Usage: "Promote user to admin",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return errors.New("userID required")
					}
					return cmdAdminPromote(ctx, cmd.Args().First())
				},
			},
			{
				Name:  "admin-audit",
				Usage: "Run a comprehensive system integrity audit",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return cmdAdminAudit(ctx, cmd.Args().Slice())
				},
			},
			{
				Name:  "admin-create-root",
				Usage: "Initialize a new root inode",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "secondary", Usage: "Create secondary root"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return cmdAdminCreateRoot(ctx, cmd.Bool("secondary"))
				},
			},
			{
				Name:  "registry-add",
				Usage: "Verify and add a user to the registry",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "unlock", Usage: "Unlock the user record"},
					&cli.StringFlag{Name: "quota", Usage: "Initial quota limit (format: bytes,inodes)"},
					&cli.BoolFlag{Name: "home", Usage: "Create home directory"},
					&cli.BoolFlag{Name: "yes", Usage: "Assume yes for prompts"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("username and userID required")
					}
					return cmdRegistryAdd(ctx, cmd.Args().Get(0), cmd.Args().Get(1), cmd.Bool("unlock"), cmd.String("quota"), cmd.Bool("home"), cmd.Bool("yes"))
				},
			},
			{
				Name:  "registry-add-group",
				Usage: "Anchor a group in the registry",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return errors.New("name and groupID required")
					}
					return cmdRegistryAddGroup(ctx, cmd.Args().Get(0), cmd.Args().Get(1))
				},
			},
			{
				Name:  "registry-update-cluster",
				Usage: "Update the anchored cluster topology in the registry",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c := loadClient()
					if err := c.AnchorClusterInRegistry(ctx); err != nil {
						return err
					}
					fmt.Println("Cluster topology successfully anchored in /registry/cluster.json")
					return nil
				},
			},
			{
				Name:  "verify-timeline",
				Usage: "Verify the cluster timeline consistency across nodes",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					c := loadClient()
					if err := c.VerifyTimeline(ctx); err != nil {
						return err
					}
					fmt.Println("Timeline verified successfully. Quorum consistency confirmed.")
					return nil
				},
			},
			{
				Name:  "dump-inodes",
				Usage: "Recursively dump inode metadata for debugging",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return cmdDump(ctx, cmd.Args().Slice())
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func loadClient() *client.Client {
	conf, err := config.Load(appConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	c := client.NewClient(conf.ServerURL).
		WithAllowInsecure(appAllowInsecure).
		WithDisableDoH(appDisableDoH)

	dkBytes, _ := hex.DecodeString(conf.EncKey)
	skBytes, _ := hex.DecodeString(conf.SignKey)
	svKeyBytes, _ := hex.DecodeString(conf.ServerKey)

	rid := conf.DefaultRootID
	if rid == "" {
		rid = metadata.RootID
	}
	if appRootID != "" {
		rid = appRootID
	}

	var rowner string
	var rpk, rek []byte
	var rver uint64

	if anchor, ok := conf.Roots[rid]; ok {
		rowner = anchor.RootOwner
		rpk = anchor.RootOwnerPublicKey
		rek = anchor.RootOwnerEncryptionKey
		rver = anchor.RootVersion
	}

	c, err = c.WithIdentityBytes(conf.UserID, dkBytes)
	if err != nil {
		log.Fatalf("failed to load identity: %v", err)
	}
	c, err = c.WithSignKeyBytes(skBytes)
	if err != nil {
		log.Fatalf("failed to load signing key: %v", err)
	}
	c, err = c.WithServerKeyBytes(svKeyBytes)
	if err != nil {
		log.Fatalf("failed to load server key: %v", err)
	}

	c = c.WithRootAnchorBytes(rid, rowner, rpk, rek, rver).
		WithAdmin(appAdminFlag).
		WithDisableDoH(appDisableDoH).
		WithAllowInsecure(appAllowInsecure).
		WithRegistry(appRegistryDir)

	return c
}

func saveClient(c *client.Client) {
	conf, err := config.Load(appConfigPath)
	if err != nil {
		// If we can't load it, we can't save it (need the password for encryption)
		return
	}

	rid, rowner, rpk, rek, rver := c.GetRootAnchor()
	if rid == "" {
		return
	}

	if conf.Roots == nil {
		conf.Roots = make(map[string]config.RootAnchor)
	}

	anchor := config.RootAnchor{
		RootOwner:              rowner,
		RootOwnerPublicKey:     rpk,
		RootOwnerEncryptionKey: rek,
		RootVersion:            rver,
	}

	existing, exists := conf.Roots[rid]
	changed := !exists || existing.RootOwner != rowner || existing.RootVersion != rver || !bytes.Equal(existing.RootOwnerPublicKey, rpk) || !bytes.Equal(existing.RootOwnerEncryptionKey, rek)

	isDefault := conf.DefaultRootID == "" || conf.DefaultRootID == rid || rid == metadata.RootID

	if !changed && !isDefault {
		return // No change
	}

	conf.Roots[rid] = anchor

	if isDefault {
		conf.DefaultRootID = rid
	}

	// Save the updated configuration
	if err := config.Save(*conf, appConfigPath); err != nil {
		log.Printf("Warning: failed to save config: %v", err)
	} else {
		fmt.Println("Local configuration updated with root anchor.")
	}
}

type LSClient interface {
	Stat(ctx context.Context, path string) (*client.DistFileInfo, error)
	Lstat(ctx context.Context, path string) (*client.DistFileInfo, error)
	LstatDirEntry(ctx context.Context, path string) (*client.DistDirEntry, error)
	ReadDirExtended(ctx context.Context, path string, fetchMetadata bool) ([]*client.DistDirEntry, error)
	ReadDirRecursive(ctx context.Context, path string) (map[string][]*client.DistDirEntry, error)
	UserID() string
}

func runLs(ctx context.Context, c LSClient, cmd *cli.Command) error {
	long := cmd.Bool("l")
	all := cmd.Bool("a")
	human := cmd.Bool("h")
	inode := cmd.Bool("i")
	recursive := cmd.Bool("R")
	directory := cmd.Bool("d")
	sortByTime := cmd.Bool("t")
	sortBySize := cmd.Bool("S")
	reverse := cmd.Bool("r")
	oneCol := cmd.Bool("1")
	classify := cmd.Bool("F")

	path := cmd.Args().First()
	if path == "" {
		path = "/"
	}

	if directory {
		entry, err := c.LstatDirEntry(ctx, path)
		if err != nil {
			return err
		}

		processAndPrintEntries(os.Stdout, []*client.DistDirEntry{entry}, long, all, human, inode, classify, oneCol, sortByTime, sortBySize, reverse)
		return nil
	}

	if recursive {
		results, err := c.ReadDirRecursive(ctx, path)
		if err != nil {
			return err
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
			processAndPrintEntries(os.Stdout, entries, long, all, human, inode, classify, oneCol, sortByTime, sortBySize, reverse)
			if i < len(paths)-1 {
				fmt.Println()
			}
		}
	} else {
		entries, err := c.ReadDirExtended(ctx, path, long || classify || sortByTime || sortBySize)
		if err != nil {
			return err
		}
		processAndPrintEntries(os.Stdout, entries, long, all, human, inode, classify, oneCol, sortByTime, sortBySize, reverse)
	}
	return nil
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

func cmdPut(ctx context.Context, local, remote string, force bool) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	c := loadClient()

	var opts client.MkdirOptions
	if force {
		if fi, err := c.Lstat(ctx, remote); err == nil {
			inode := fi.Sys().(*client.InodeInfo)
			if err := c.EnsureFileKey(ctx, remote); err != nil {
				log.Printf("cmdPut: EnsureFileKey warning: %v", err)
			}

			m := uint32(fi.Mode()) & 0777
			opts.Mode = &m
			opts.GroupID = inode.GroupID
			opts.AccessACL = inode.AccessACL
			opts.DefaultACL = inode.DefaultACL

			if err := c.RemoveEntry(ctx, remote); err != nil {
				return fmt.Errorf("failed to remove existing file for overwrite: %w", err)
			}
		} else if !errors.Is(err, metadata.ErrNotFound) {
			return fmt.Errorf("failed to check existing file: %w", err)
		}
	}

	if err := c.CreateFileExtended(ctx, remote, f, info.Size(), opts); err != nil {
		return err
	}
	fmt.Printf("File %s uploaded to %s.\n", local, remote)
	return nil
}

func cmdGet(ctx context.Context, remote, local string) error {
	c := loadClient()
	rc, err := c.OpenBlobRead(ctx, remote)
	if err != nil {
		return err
	}
	defer rc.Close()

	f, err := os.Create(local)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, rc); err != nil {
		return err
	}
	fmt.Printf("File %s downloaded to %s.\n", remote, local)
	return nil
}

func cmdDu(ctx context.Context, path string, human bool) error {
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
		return err
	}

	if human {
		fmt.Printf("%s\t%s\n", client.FormatBytes(totalSize), path)
	} else {
		fmt.Printf("%d\t%s\n", totalSize, path)
	}
	return nil
}

func cmdDf(ctx context.Context, human bool) error {
	c := loadClient()
	quota, usage, err := c.GetQuota(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("%-20s %-10s %-10s %-10s %-10s\n", "Filesystem", "Size", "Used", "Avail", "Use%")

	sizeStr := strconv.FormatInt(quota.MaxBytes, 10)
	usedStr := strconv.FormatInt(usage.TotalBytes, 10)
	availStr := strconv.FormatInt(quota.MaxBytes-usage.TotalBytes, 10)
	if quota.MaxBytes == 0 {
		sizeStr = "Inf"
		availStr = "Inf"
	}

	if human {
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
	return nil
}

func cmdGetFacl(ctx context.Context, path string) error {
	c := loadClient()
	info, err := c.Stat(ctx, path)
	if err != nil {
		return err
	}

	inode := info.Sys().(*client.InodeInfo)
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
	return nil
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

func cmdSetFacl(ctx context.Context, path, modify, remove string) error {
	c := loadClient()
	info, err := c.Stat(ctx, path)
	if err != nil {
		return err
	}
	inode := info.Sys().(*client.InodeInfo)

	acl := inode.AccessACL
	if acl == nil {
		acl = &client.ACL{
			Users:  make(map[string]uint32),
			Groups: make(map[string]uint32),
		}
	}

	if modify != "" {
		parts := strings.Split(modify, ":")
		if len(parts) < 3 {
			return errors.New("invalid modify spec, expected type:id:perms")
		}
		t, id, permsStr := parts[0], parts[1], parts[2]
		bits, err := parsePerms(permsStr)
		if err != nil {
			return fmt.Errorf("invalid permissions: %w", err)
		}

		switch t {
		case "u", "user":
			resolvedID, _, err := c.ResolveUsername(ctx, id)
			if err != nil {
				return fmt.Errorf("failed to resolve user %s: %w", id, err)
			}
			acl.Users[resolvedID] = bits
		case "g", "group":
			acl.Groups[id] = bits
		case "m", "mask":
			acl.Mask = &bits
		default:
			return fmt.Errorf("unsupported ACL type: %s", t)
		}
	}

	if remove != "" {
		parts := strings.Split(remove, ":")
		if len(parts) < 2 {
			return errors.New("invalid remove spec, expected type:id")
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

	if err := c.Setfacl(ctx, path, *acl); err != nil {
		return err
	}
	fmt.Printf("ACL of %s updated.\n", path)
	return nil
}

func cmdGroupCreate(ctx context.Context, name string, quota bool, owner string) error {
	c := loadClient()

	if !appAdminFlag {
		return errors.New("group-create now requires --admin privileges to anchor in /registry")
	}

	ownerID := ""
	if owner != "" {
		var err error
		ownerID, _, err = c.ResolveUsername(ctx, owner)
		if err != nil {
			return fmt.Errorf("failed to resolve owner %s: %w", owner, err)
		}
	}

	group, err := c.CreateGroupWithOptions(ctx, name, quota, ownerID)
	if err != nil {
		return err
	}
	if err := c.AnchorGroupInRegistry(ctx, name, group.ID); err != nil {
		return fmt.Errorf("failed to anchor group in registry: %w", err)
	}
	fmt.Printf("Group %s created and anchored in /registry.\n", name)
	fmt.Printf("ID: %s\n", group.ID)
	fmt.Printf("Owner: %s\n", group.OwnerID)
	fmt.Printf("QuotaEnabled: %v\n", group.QuotaEnabled)
	return nil
}

func cmdGroupAdd(ctx context.Context, groupArg, userArg, info string, force bool) error {
	c := loadClient()

	// Resolve Group
	groupID := groupArg
	if !metadata.IsInodeID(groupArg) {
		id, _, err := c.ResolveGroupName(ctx, groupArg)
		if err != nil {
			return fmt.Errorf("failed to resolve group %s: %w", groupArg, err)
		}
		groupID = id
	}

	userID := userArg
	var ci *client.ContactInfo
	if strings.HasPrefix(userArg, "distfs-contact:v1:") {
		var err error
		ci, err = c.ParseContactString(userArg)
		if err != nil {
			return fmt.Errorf("invalid contact string: %w", err)
		}
		userID = ci.UserID
		fmt.Printf("Parsed contact string:\n")
		fmt.Printf("  User ID:    %s\n", ci.UserID)
		fmt.Printf("  Created At: %s\n", time.Unix(ci.Timestamp, 0).Format(time.RFC3339))

		if !force {
			fmt.Printf("Add this user to group %s? [y/N]: ", groupID)
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(strings.TrimSpace(response)) != "y" {
				fmt.Println("Aborted.")
				return nil
			}
		}
	} else {
		var err error
		var entry *client.DirectoryEntry
		userID, entry, err = c.ResolveUsername(ctx, userArg)
		if err != nil {
			return fmt.Errorf("failed to resolve user %s: %w", userArg, err)
		}
		if entry != nil && entry.EncKey != nil {
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
		return err
	}
	fmt.Printf("User %s added to group %s\n", userID, groupID)
	return nil
}

func cmdGroupMembers(ctx context.Context, groupArg string) error {
	c := loadClient()

	// Resolve Group
	groupID := groupArg
	if !metadata.IsInodeID(groupArg) {
		id, _, err := c.ResolveGroupName(ctx, groupArg)
		if err != nil {
			return fmt.Errorf("failed to resolve group %s: %w", groupArg, err)
		}
		groupID = id
	}

	fmt.Printf("Members of group %s (%s):\n", groupArg, groupID)
	fmt.Printf("%-64s %s\n", "User ID", "User Info")
	fmt.Println(strings.Repeat("-", 80))
	members, err := c.AdminGetGroupMembers(ctx, groupID)
	if err != nil {
		return err
	}
	for userID, info := range members {
		fmt.Printf("%-64s %s\n", userID, info)
	}
	return nil
}

func cmdGroupRemove(ctx context.Context, groupArg, userArg string) error {
	c := loadClient()

	// Resolve Group
	groupID := groupArg
	if !metadata.IsInodeID(groupArg) {
		id, _, err := c.ResolveGroupName(ctx, groupArg)
		if err != nil {
			return fmt.Errorf("failed to resolve group %s: %w", groupArg, err)
		}
		groupID = id
	}

	// Resolve User
	userID := userArg
	if !metadata.IsInodeID(userArg) && len(userArg) != 64 {
		id, _, err := c.ResolveUsername(ctx, userArg)
		if err != nil {
			return fmt.Errorf("failed to resolve user %s: %w", userArg, err)
		}
		userID = id
	}

	if err := c.RemoveUserFromGroup(ctx, groupID, userID); err != nil {
		return err
	}
	fmt.Printf("User %s removed from group %s\n", userArg, groupArg)
	return nil
}

func cmdGroupList(ctx context.Context) error {
	c := loadClient()

	fmt.Printf("%-32s %-20s %s\n", "Group ID", "Name", "Role")
	fmt.Println(strings.Repeat("-", 80))
	for e, err := range c.ListGroups(ctx) {
		if err != nil {
			return err
		}
		name := "[HIDDEN]"
		if decrypted, err := c.AdminDecryptGroupName(ctx, e); err == nil {
			name = decrypted
		}
		fmt.Printf("%-32s %-20s %s\n", e.ID, name, e.Role)
	}
	return nil
}

func cmdQuota(ctx context.Context) error {
	c := loadClient()
	quota, usage, err := c.GetQuota(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch user info: %w", err)
	}

	fmt.Printf("Personal Usage for %s:\n", c.UserID())
	displayUsage(usage, quota)

	managedGroups := 0
	for g, err := range c.ListGroups(ctx) {
		if err != nil {
			fmt.Printf("\nFailed to fetch group info: %v\n", err)
			return nil
		}
		if g.Role == metadata.RoleOwner || g.Role == metadata.RoleManager {
			if managedGroups == 0 {
				fmt.Println("Managed Group Quotas:")
			}
			managedGroups++
			fmt.Println()
			name := "[HIDDEN]"
			if decrypted, err := c.AdminDecryptGroupName(ctx, g); err == nil {
				name = decrypted
			}
			fmt.Printf("Group: %s (%s)\n", name, g.ID)
			displayUsage(g.Usage, g.Quota)
		}
	}
	return nil
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
