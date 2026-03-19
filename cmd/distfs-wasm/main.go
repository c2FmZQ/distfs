//go:build wasm

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"syscall/js"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/config"
	"github.com/c2FmZQ/distfs/pkg/crypto"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"golang.org/x/oauth2"
)

var c *client.Client

func startDeviceAuth(args []js.Value) (interface{}, error) {
	authEndpoint := args[0].String()
	tokenEndpoint := args[1].String()
	
	oauthConfig := &oauth2.Config{
		ClientID: "distfs",
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: authEndpoint,
			TokenURL:      tokenEndpoint,
		},
		Scopes: []string{"openid"},
	}

	resp, err := oauthConfig.DeviceAuth(context.Background())
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"verificationURI":         resp.VerificationURI,
		"verificationURIComplete": resp.VerificationURIComplete,
		"userCode":                resp.UserCode,
		"deviceCode":              resp.DeviceCode,
		"interval":                resp.Interval,
	}, nil
}

func pollForToken(args []js.Value) (interface{}, error) {
	authEndpoint := args[0].String()
	tokenEndpoint := args[1].String()
	deviceCode := args[2].String()
	userCode := args[3].String()
	verificationURI := args[4].String()
	interval := args[5].Int()

	oauthConfig := &oauth2.Config{
		ClientID: "distfs",
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: authEndpoint,
			TokenURL:      tokenEndpoint,
		},
		Scopes: []string{"openid"},
	}

	// Reconstruct the response object for polling
	resp := &oauth2.DeviceAuthResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: verificationURI,
		Interval:        int64(interval),
	}

	token, err := oauthConfig.DeviceAccessToken(context.Background(), resp)
	if err != nil {
		return nil, err
	}

	return token.AccessToken, nil
}

// asyncFunc wraps a Go function that returns (interface{}, error) into a JavaScript Promise.
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
		WithDisableDoH(true)

	return true, nil
}

func listDirectory(args []js.Value) (interface{}, error) {
	path := args[0].String()
	
	offset := 0
	limit := -1
	if len(args) > 1 && !args[1].IsUndefined() {
		offset = args[1].Int()
	}
	if len(args) > 2 && !args[2].IsUndefined() {
		limit = args[2].Int()
	}

	var entries []*client.DistDirEntry
	var total int
	var err error

	if limit > 0 {
		entries, total, err = c.ReadDirPaginated(context.Background(), path, offset, limit)
	} else {
		entries, err = c.ReadDir(context.Background(), path)
		total = len(entries)
	}

	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		res = append(res, map[string]interface{}{
			"name":    e.Name(),
			"isDir":   e.IsDir(),
			"size":    e.Size(),
			"modTime": e.ModTime().Unix(),
		})
	}
	
	return map[string]interface{}{
		"entries": res,
		"total":   total,
	}, nil
}

func statFile(args []js.Value) (interface{}, error) {
	path := args[0].String()
	info, err := c.Stat(context.Background(), path)
	if err != nil {
		return nil, err
	}

	inode := info.Sys().(*metadata.Inode)

	mimeType := mime.TypeByExtension(filepath.Ext(path))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	lockbox := make(map[string]interface{})
	for k, v := range inode.Lockbox {
		lockbox[k] = map[string]interface{}{
			"kem": hex.EncodeToString(v.KEMCiphertext),
			"dem": hex.EncodeToString(v.DEMCiphertext),
		}
	}

	var accessACL map[string]interface{}
	if inode.AccessACL != nil {
		users := make(map[string]interface{})
		for k, v := range inode.AccessACL.Users {
			users[k] = v
		}
		groups := make(map[string]interface{})
		for k, v := range inode.AccessACL.Groups {
			groups[k] = v
		}
		accessACL = map[string]interface{}{"Users": users, "Groups": groups}
	}

	var defaultACL map[string]interface{}
	if inode.DefaultACL != nil {
		users := make(map[string]interface{})
		for k, v := range inode.DefaultACL.Users {
			users[k] = v
		}
		groups := make(map[string]interface{})
		for k, v := range inode.DefaultACL.Groups {
			groups[k] = v
		}
		defaultACL = map[string]interface{}{"Users": users, "Groups": groups}
	}

	return map[string]interface{}{
		"name":       info.Name(),
		"size":       info.Size(),
		"isDir":      info.IsDir(),
		"modTime":    info.ModTime().Unix(),
		"owner":      inode.OwnerID,
		"group":      inode.GroupID,
		"mode":       inode.Mode,
		"mimeType":   mimeType,
		"lockbox":    lockbox,
		"accessACL":  accessACL,
		"defaultACL": defaultACL,
	}, nil
}

func readFileChunk(args []js.Value) (interface{}, error) {
	path := args[0].String()
	offset := int64(args[1].Int())
	length := args[2].Int()

	if length < 0 || length > 10*1024*1024 {
		return nil, fmt.Errorf("invalid chunk length: %d", length)
	}

	f, err := c.Open(context.Background(), path, 0, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}

	uint8Array := js.Global().Get("Uint8Array").New(n)
	js.CopyBytesToJS(uint8Array, buf[:n])

	res := map[string]interface{}{
		"chunk": uint8Array,
	}
	// Sniff content type if reading from the beginning
	if offset == 0 && n > 0 {
		res["detectedMimeType"] = http.DetectContentType(buf[:n])
	}

	return res, nil
}

func getQuota(args []js.Value) (interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("client not initialized")
	}
	user, err := c.GetUser(context.Background(), c.UserID())
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"used_bytes":  user.Usage.TotalBytes,
		"total_bytes": user.Quota.MaxBytes,
		"used_inodes": user.Usage.InodeCount,
		"total_inodes": user.Quota.MaxInodes,
	}, nil
}

func readFile(args []js.Value) (interface{}, error) {
	path := args[0].String()
	f, err := c.Open(context.Background(), path, 0, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Cap reading at 10MB for UI text previews
	limitReader := io.LimitReader(f, 10*1024*1024)
	data, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, err
	}
	return string(data), nil
}

func writeFile(args []js.Value) (interface{}, error) {
	path := args[0].String()
	content := args[1].String()
	
	// Open or create file
	err := c.CreateFile(context.Background(), path, bytes.NewReader([]byte(content)), int64(len(content)))
	if err != nil {
		return nil, err
	}
	return true, nil
}

func mkdir(args []js.Value) (interface{}, error) {
	path := args[0].String()
	err := c.Mkdir(context.Background(), path, 0755)
	if err != nil {
		return nil, err
	}
	return true, nil
}

func mv(args []js.Value) (interface{}, error) {
	oldPath := args[0].String()
	newPath := args[1].String()
	err := c.Rename(context.Background(), oldPath, newPath)
	if err != nil {
		return nil, err
	}
	return true, nil
}

func rm(args []js.Value) (interface{}, error) {
	path := args[0].String()
	err := c.Remove(context.Background(), path)
	if err != nil {
		return nil, err
	}
	return true, nil
}

func setACL(args []js.Value) (interface{}, error) {
	path := args[0].String()
	aclJSON := args[1].String()

	var acl metadata.POSIXAccess
	if err := json.Unmarshal([]byte(aclJSON), &acl); err != nil {
		return nil, fmt.Errorf("invalid ACL JSON: %w", err)
	}

	err := c.SetAttr(context.Background(), path, metadata.SetAttrRequest{
		AccessACL: &acl,
	})
	if err != nil {
		return nil, err
	}
	return true, nil
}

func lookupUser(args []js.Value) (interface{}, error) {
	identifier := args[0].String()
	userID, _, err := c.ResolveUsername(context.Background(), identifier)
	if err != nil {
		return nil, err
	}
	return userID, nil
}

func main() {
	js.Global().Set("DistFS", map[string]interface{}{
		"init":            asyncFunc(initClient),
		"listDirectory":   asyncFunc(listDirectory),
		"statFile":        asyncFunc(statFile),
		"readFileChunk":   asyncFunc(readFileChunk),
		"readFile":        asyncFunc(readFile),
		"writeFile":       asyncFunc(writeFile),
		"mkdir":           asyncFunc(mkdir),
		"mv":              asyncFunc(mv),
		"rm":              asyncFunc(rm),
		"setACL":          asyncFunc(setACL),
		"lookupUser":      asyncFunc(lookupUser),
		"getQuota":        asyncFunc(getQuota),
		"generateKeys":    asyncFunc(generateKeys),
		"fetchServerKey":  asyncFunc(fetchServerKey),
		"encryptConfig":   asyncFunc(encryptConfig),
		"decryptConfig":   asyncFunc(decryptConfig),
		"pushKeySync":     asyncFunc(pushKeySync),
		"pullKeySync":     asyncFunc(pullKeySync),
		"registerUser":    asyncFunc(registerUser),
		"startDeviceAuth": asyncFunc(startDeviceAuth),
		"pollForToken":    asyncFunc(pollForToken),
	})

	<-make(chan struct{})
}
