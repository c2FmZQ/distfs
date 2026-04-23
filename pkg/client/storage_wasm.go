//go:build wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"fmt"
	"syscall/js"
)

type WASMStore struct {
	db js.Value
}

func NewWASMStore() (*WASMStore, error) {
	indexedDB := js.Global().Get("indexedDB")
	if indexedDB.IsUndefined() {
		return nil, fmt.Errorf("indexedDB not supported")
	}

	request := indexedDB.Call("open", "distfs-cache", 1)

	done := make(chan error, 1)

	var upgradeFn, successFn, errorFn js.Func

	upgradeFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		db := request.Get("result")
		buckets := []string{"chunks", "inodes", "groups", "users"}
		for _, b := range buckets {
			if !db.Get("objectStoreNames").Call("contains", b).Bool() {
				db.Call("createObjectStore", b)
			}
		}
		return nil
	})

	successFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- nil
		return nil
	})

	errorFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- fmt.Errorf("failed to open indexedDB: %s", request.Get("error").Call("toString").String())
		return nil
	})

	request.Set("onupgradeneeded", upgradeFn)
	request.Set("onsuccess", successFn)
	request.Set("onerror", errorFn)

	err := <-done
	upgradeFn.Release()
	successFn.Release()
	errorFn.Release()

	if err != nil {
		return nil, err
	}

	return &WASMStore{db: request.Get("result")}, nil
}

func (s *WASMStore) Get(bucket, key string) ([]byte, error) {
	txn := s.db.Call("transaction", []interface{}{bucket}, "readonly")
	store := txn.Call("objectStore", bucket)
	request := store.Call("get", key)

	done := make(chan struct{})
	var data []byte
	var err error

	var successFn, errorFn js.Func

	successFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		result := request.Get("result")
		if result.IsUndefined() || result.IsNull() {
			err = ErrNotFound
		} else {
			len := result.Get("length").Int()
			data = make([]byte, len)
			js.CopyBytesToGo(data, result)
		}
		close(done)
		return nil
	})

	errorFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		err = fmt.Errorf("indexedDB get error: %s", request.Get("error").Call("toString").String())
		close(done)
		return nil
	})

	request.Set("onsuccess", successFn)
	request.Set("onerror", errorFn)

	<-done
	successFn.Release()
	errorFn.Release()
	return data, err
}

func (s *WASMStore) Put(bucket, key string, value []byte) error {
	txn := s.db.Call("transaction", []interface{}{bucket}, "readwrite")
	store := txn.Call("objectStore", bucket)

	uint8Array := js.Global().Get("Uint8Array").New(len(value))
	js.CopyBytesToJS(uint8Array, value)

	request := store.Call("put", uint8Array, key)

	done := make(chan error, 1)
	var successFn, errorFn js.Func

	successFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- nil
		return nil
	})
	errorFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- fmt.Errorf("indexedDB put error: %s", request.Get("error").Call("toString").String())
		return nil
	})

	request.Set("onsuccess", successFn)
	request.Set("onerror", errorFn)

	err := <-done
	successFn.Release()
	errorFn.Release()
	return err
}

func (s *WASMStore) Delete(bucket, key string) error {
	txn := s.db.Call("transaction", []interface{}{bucket}, "readwrite")
	store := txn.Call("objectStore", bucket)
	request := store.Call("delete", key)

	done := make(chan error, 1)
	var successFn, errorFn js.Func

	successFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- nil
		return nil
	})
	errorFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- fmt.Errorf("indexedDB delete error: %s", request.Get("error").Call("toString").String())
		return nil
	})

	request.Set("onsuccess", successFn)
	request.Set("onerror", errorFn)

	err := <-done
	successFn.Release()
	errorFn.Release()
	return err
}

func (s *WASMStore) Close() error {
	s.db.Call("close")
	return nil
}
