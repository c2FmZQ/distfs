//go:build !wasm

package client

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/c2FmZQ/distfs/pkg/metadata"
	"go.etcd.io/bbolt"
)

// DumpFSMState dumps the inodes and groups buckets to stdout for debugging test failures.
func DumpFSMState(t *testing.T, fsm *metadata.MetadataFSM) {
	fmt.Println("================================================================")
	fmt.Println("====================== FSM STATE DUMP ==========================")
	fmt.Println("================================================================")

	err := fsm.DB().View(func(tx *bbolt.Tx) error {
		fmt.Println("--- INODES ---")
		ibName := []byte("inodes")
		b := tx.Bucket(ibName)
		if b != nil {
			b.ForEach(func(k, v []byte) error {
				plain, err := fsm.DecryptValue(ibName, v)
				if err != nil {
					return nil
				}
				var inode metadata.Inode
				if err := json.Unmarshal(plain, &inode); err == nil {
					j, _ := json.MarshalIndent(inode, "", "  ")
					fmt.Printf("Inode %s:\n%s\n", k, string(j))
				}
				return nil
			})
		}

		fmt.Println("\n--- GROUPS ---")
		gbName := []byte("groups")
		gb := tx.Bucket(gbName)
		if gb != nil {
			gb.ForEach(func(k, v []byte) error {
				plain, err := fsm.DecryptValue(gbName, v)
				if err != nil {
					return nil
				}
				var group metadata.Group
				if err := json.Unmarshal(plain, &group); err == nil {
					j, _ := json.MarshalIndent(group, "", "  ")
					fmt.Printf("Group %s:\n%s\n", k, string(j))
				}
				return nil
			})
		}

		fmt.Println("\n--- USERS ---")
		ubName := []byte("users")
		ub := tx.Bucket(ubName)
		if ub != nil {
			ub.ForEach(func(k, v []byte) error {
				plain, err := fsm.DecryptValue(ubName, v)
				if err != nil {
					return nil
				}

				var u metadata.User
				if err := json.Unmarshal(plain, &u); err == nil {
					j, _ := json.MarshalIndent(u, "", "  ")
					fmt.Printf("User %s:\n%s\n", k, string(j))
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("DumpFSMState failed: %v", err)
	}

	fmt.Println("================================================================")
}
