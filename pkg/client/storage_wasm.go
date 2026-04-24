//go:build wasm

// Copyright 2026 TTBT Enterprises LLC
package client

import (
	"fmt"
	"sort"
	"strings"
	"syscall/js"
)

type WASMStore struct {
	db         js.Value
	maxEntries int
}

func NewWASMStore(maxEntries int) (*WASMStore, error) {
	indexedDB := js.Global().Get("indexedDB")
	if indexedDB.IsUndefined() {
		return nil, fmt.Errorf("indexedDB not supported")
	}

	request := indexedDB.Call("open", "distfs-cache", 1)

	done := make(chan error, 1)

	var upgradeFn, successFn, errorFn js.Func

	upgradeFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		db := request.Get("result")
		buckets := []string{"chunks", "inodes", "groups", "users", "last_access"}
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

	return &WASMStore{
		db:         request.Get("result"),
		maxEntries: maxEntries,
	}, nil
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

	// Update last_access in background
	if err == nil {
		go func() {
			txn := s.db.Call("transaction", []interface{}{"last_access"}, "readwrite")
			store := txn.Call("objectStore", "last_access")
			store.Call("put", js.Global().Get("Date").Call("now"), bucket+":"+key)
		}()
	}

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
	if err == nil {
		go func() {
			txn := s.db.Call("transaction", []interface{}{"last_access"}, "readwrite")
			store := txn.Call("objectStore", "last_access")
			store.Call("put", js.Global().Get("Date").Call("now"), bucket+":"+key)
			s.Prune()
		}()
	}

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
	if err == nil {
		go func() {
			txn := s.db.Call("transaction", []interface{}{"last_access"}, "readwrite")
			store := txn.Call("objectStore", "last_access")
			store.Call("delete", bucket+":"+key)
		}()
	}

	successFn.Release()
	errorFn.Release()
	return err
}

func (s *WASMStore) Close() error {
	s.db.Call("close")
	return nil
}

func (s *WASMStore) Prune() {
	if s.maxEntries <= 0 {
		return
	}

	txn := s.db.Call("transaction", []interface{}{"last_access"}, "readonly")
	store := txn.Call("objectStore", "last_access")
	reqKeys := store.Call("getAllKeys")
	reqVals := store.Call("getAll")

	doneKeys := make(chan struct{})
	doneVals := make(chan struct{})

	var keys []string
	var times []float64

	successKeysFn := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		res := reqKeys.Get("result")
		l := res.Get("length").Int()
		for i := 0; i < l; i++ {
			keys = append(keys, res.Index(i).String())
		}
		close(doneKeys)
		return nil
	})

	successValsFn := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		res := reqVals.Get("result")
		l := res.Get("length").Int()
		for i := 0; i < l; i++ {
			times = append(times, res.Index(i).Float())
		}
		close(doneVals)
		return nil
	})

	reqKeys.Set("onsuccess", successKeysFn)
	reqVals.Set("onsuccess", successValsFn)

	<-doneKeys
	<-doneVals

	successKeysFn.Release()
	successValsFn.Release()

	if len(keys) <= s.maxEntries || len(keys) != len(times) {
		return
	}

	type entry struct {
		key  string
		time float64
	}

	entries := make([]entry, len(keys))
	for i := range keys {
		entries[i] = entry{key: keys[i], time: times[i]}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].time < entries[j].time
	})

	toDelete := len(entries) - s.maxEntries
	for i := 0; i < toDelete; i++ {
		parts := strings.SplitN(entries[i].key, ":", 2)
		if len(parts) == 2 {
			s.Delete(parts[0], parts[1])

			// Also delete from last_access so it doesn't get stuck there
			txnDel := s.db.Call("transaction", []interface{}{"last_access"}, "readwrite")
			storeDel := txnDel.Call("objectStore", "last_access")

			delReq := storeDel.Call("delete", entries[i].key)
			doneDel := make(chan struct{})
			successDelFn := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				close(doneDel)
				return nil
			})
			delReq.Set("onsuccess", successDelFn)
			<-doneDel
			successDelFn.Release()
		}
	}
}

