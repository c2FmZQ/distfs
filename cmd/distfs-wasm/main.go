//go:build wasm

package main

import (
	"context"
	"encoding/hex"
	"syscall/js"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
)

var c *client.Client

// asyncFunc wraps a Go function that returns (interface{}, error) into a JavaScript Promise.
// This ensures that heavy cryptographic operations execute in the background Goroutine
// without blocking the main JavaScript thread (or Web Worker thread).
func asyncFunc(fn func(args []js.Value) (interface{}, error)) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		handler := js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				res, err := fn(args)
				if err != nil {
					reject.Invoke(err.Error())
				} else {
					resolve.Invoke(res)
				}
			}()
			return nil
		})
		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}

func initClient(args []js.Value) (interface{}, error) {
	serverURL := args[0].String()
	userID := args[1].String()
	decKeyHex := args[2].String()
	signKeyHex := args[3].String()
	serverKeyHex := args[4].String()

	decKeyBytes, _ := hex.DecodeString(decKeyHex)
	decKey, _ := crypto.UnmarshalDecapsulationKey(decKeyBytes)

	signKeyBytes, _ := hex.DecodeString(signKeyHex)
	signKey := crypto.UnmarshalIdentityKey(signKeyBytes)

	serverKeyBytes, _ := hex.DecodeString(serverKeyHex)
	serverKey, _ := crypto.UnmarshalEncapsulationKey(serverKeyBytes)

	c = client.NewClient(serverURL).
		WithIdentity(userID, decKey).
		WithSignKey(signKey).
		WithServerKey(serverKey).
		WithDisableDoH(true) // Always disable DoH in the browser, rely on native fetch

	return true, nil
}

func listDirectory(args []js.Value) (interface{}, error) {
	path := args[0].String()
	entries, err := c.ReadDir(context.Background(), path)
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		res = append(res, map[string]interface{}{
			"name":  e.Name(),
			"isDir": e.IsDir(),
			"size":  e.Size(),
		})
	}
	return res, nil
}

func main() {
	js.Global().Set("DistFS", map[string]interface{}{
		"init":          asyncFunc(initClient),
		"listDirectory": asyncFunc(listDirectory),
	})

	// Block indefinitely to keep the WASM instance alive
	<-make(chan struct{})
}
