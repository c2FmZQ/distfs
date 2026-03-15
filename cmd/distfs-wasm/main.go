//go:build wasm

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"syscall/js"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
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

func generateKeys(args []js.Value) (interface{}, error) {
	dk, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return nil, err
	}
	sk, err := crypto.GenerateIdentityKey()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"decKey":     hex.EncodeToString(crypto.MarshalDecapsulationKey(dk)),
		"encKey":     hex.EncodeToString(dk.EncapsulationKey().Bytes()),
		"signKey":    hex.EncodeToString(sk.MarshalPrivate()),
		"signPubKey": hex.EncodeToString(sk.Public()),
	}, nil
}

func encryptConfig(args []js.Value) (interface{}, error) {
	confStr := args[0].String()
	passphrase := args[1].String()

	var conf config.Config
	if err := json.Unmarshal([]byte(confStr), &conf); err != nil {
		return nil, err
	}

	blob, err := config.Encrypt(conf, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	blobBytes, err := json.Marshal(blob)
	if err != nil {
		return nil, err
	}

	return string(blobBytes), nil
}

func decryptConfig(args []js.Value) (interface{}, error) {
	blobStr := args[0].String()
	passphrase := args[1].String()

	var blob metadata.KeySyncBlob
	if err := json.Unmarshal([]byte(blobStr), &blob); err != nil {
		return nil, err
	}

	conf, err := config.Decrypt(blob, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	confBytes, err := json.Marshal(conf)
	if err != nil {
		return nil, err
	}

	return string(confBytes), nil
}

func pushKeySync(args []js.Value) (interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("client not initialized")
	}
	blobStr := args[0].String()
	var blob metadata.KeySyncBlob
	if err := json.Unmarshal([]byte(blobStr), &blob); err != nil {
		return nil, err
	}
	if err := c.PushKeySync(context.Background(), &blob); err != nil {
		return nil, err
	}
	return true, nil
}

func pullKeySync(args []js.Value) (interface{}, error) {
	serverURL := args[0].String()
	token := args[1].String()
	
	// Create a temporary unauthenticated client just to pull the blob
	tempClient := client.NewClient(serverURL).WithDisableDoH(true)
	
	blob, err := tempClient.PullKeySync(context.Background(), token)
	if err != nil {
		return nil, err
	}
	
	blobBytes, err := json.Marshal(blob)
	if err != nil {
		return nil, err
	}
	return string(blobBytes), nil
}

func fetchServerKey(args []js.Value) (interface{}, error) {
	serverURL := args[0].String()
	tempClient := client.NewClient(serverURL).WithDisableDoH(true)
	
	req, err := http.NewRequestWithContext(context.Background(), "GET", serverURL+"/v1/meta/key", nil)
	if err != nil {
		return nil, err
	}
	resp, err := tempClient.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch server key: %d", resp.StatusCode)
	}
	
	sKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return hex.EncodeToString(sKey), nil
}

func registerUser(args []js.Value) (interface{}, error) {
	serverURL := args[0].String()
	jwt := args[1].String()
	signKeyPubHex := args[2].String()
	encKeyHex := args[3].String()

	signKeyPubBytes, err := hex.DecodeString(signKeyPubHex)
	if err != nil {
		return nil, err
	}
	encKeyBytes, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"jwt":      jwt,
		"sign_key": signKeyPubBytes,
		"enc_key":  encKeyBytes,
	}
	body, _ := json.Marshal(payload)

	// We use the underlying HTTP client from a dummy client to handle native fetch logic
	tempClient := client.NewClient(serverURL).WithDisableDoH(true)
	
	req, err := http.NewRequestWithContext(context.Background(), "POST", serverURL+"/v1/user/register", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := tempClient.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed: %d %s", resp.StatusCode, string(b))
	}

	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return user.ID, nil
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
		"generateKeys":  asyncFunc(generateKeys),
		"fetchServerKey": asyncFunc(fetchServerKey),
		"encryptConfig": asyncFunc(encryptConfig),
		"decryptConfig": asyncFunc(decryptConfig),
		"pushKeySync":   asyncFunc(pushKeySync),
		"pullKeySync":   asyncFunc(pullKeySync),
		"registerUser":  asyncFunc(registerUser),
	})

	// Block indefinitely to keep the WASM instance alive
	<-make(chan struct{})
}
