// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.no_memoize

package memoize

import "sync"

type entry struct {
	value   any
	mu      sync.Mutex
	owners  map[uint64]struct{}
	deleted bool
}

var cache sync.Map // key -> *entry

// Memoizer caches expensive function calls with per-owner tracking.
// TinyGo variant without singleflight.
type Memoizer struct {
	ownerID uint64
}

// NewMemoizer creates a Memoizer that tracks cached entries under the given owner ID.
func NewMemoizer(ownerID uint64) *Memoizer {
	return &Memoizer{ownerID: ownerID}
}

// Do returns a cached value for key, or calls fn and caches the result.
func (m *Memoizer) Do(key string, fn func() (any, error)) (any, error) {
	if v, ok := cache.Load(key); ok {
		e := v.(*entry)
		e.mu.Lock()
		if !e.deleted {
			e.owners[m.ownerID] = struct{}{}
			e.mu.Unlock()
			return e.value, nil
		}
		e.mu.Unlock()
	}

	data, err := fn()
	if err == nil {
		e := &entry{
			value:  data,
			owners: map[uint64]struct{}{m.ownerID: {}},
		}
		cache.Store(key, e)
	}
	return data, err
}

// Release removes ownerID from all cached entries, deleting entries with no remaining owners.
func Release(ownerID uint64) {
	cache.Range(func(key, value any) bool {
		e := value.(*entry)
		e.mu.Lock()
		delete(e.owners, ownerID)
		if len(e.owners) == 0 {
			e.deleted = true
			cache.Delete(key)
		}
		e.mu.Unlock()
		return true
	})
}

// Reset clears the entire cache. Intended for testing.
func Reset() {
	cache.Range(func(key, _ any) bool {
		cache.Delete(key)
		return true
	})
}
