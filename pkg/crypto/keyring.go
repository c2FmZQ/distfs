// Copyright 2026 TTBT Enterprises LLC
package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

// KeyRing manages multiple generations of symmetric keys.
type KeyRing struct {
	mu      sync.RWMutex
	keys    map[uint32][]byte
	current uint32
}

func NewKeyRing(initialKey []byte) *KeyRing {
	return &KeyRing{
		keys:    map[uint32][]byte{1: initialKey},
		current: 1,
	}
}

// Current returns the current key and its generation ID.
func (kr *KeyRing) Current() ([]byte, uint32) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.keys[kr.current], kr.current
}

// Get returns the key for a specific generation.
func (kr *KeyRing) Get(gen uint32) ([]byte, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	k, ok := kr.keys[gen]
	return k, ok
}

// Rotate generates a new key and increments the generation.
func (kr *KeyRing) Rotate() (uint32, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return 0, err
	}

	kr.current++
	kr.keys[kr.current] = newKey
	return kr.current, nil
}

// Marshal serializes the keyring for persistence.
// In a real system, this would be encrypted with a master key.
func (kr *KeyRing) Marshal() []byte {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, kr.current)

	for gen, key := range kr.keys {
		genBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(genBuf, gen)
		b = append(b, genBuf...)
		b = append(b, key...)
	}
	return b
}

func UnmarshalKeyRing(data []byte) (*KeyRing, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("invalid keyring data")
	}
	current := binary.BigEndian.Uint32(data[:4])
	keys := make(map[uint32][]byte)

	for i := 4; i+36 <= len(data); i += 36 {
		gen := binary.BigEndian.Uint32(data[i : i+4])
		key := make([]byte, 32)
		copy(key, data[i+4:i+36])
		keys[gen] = key
	}

	return &KeyRing{
		keys:    keys,
		current: current,
	}, nil
}
