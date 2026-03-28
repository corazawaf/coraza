// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.no_memoize

package memoize

import (
	"sync"

	"golang.org/x/sync/singleflight"
)

type entry struct {
	value   any
	mu      sync.Mutex
	owners  map[uint64]struct{}
	deleted bool
}

var (
	cache sync.Map // key -> *entry
	group singleflight.Group
)

// Memoizer caches expensive function calls with per-owner tracking.
type Memoizer struct {
	ownerID uint64
}

// NewMemoizer creates a Memoizer that tracks cached entries under the given owner ID.
func NewMemoizer(ownerID uint64) *Memoizer {
	return &Memoizer{ownerID: ownerID}
}

// addOwner attempts to register the ownerID on the entry.
// Returns false if the entry has been marked as deleted.
func (m *Memoizer) addOwner(e *entry) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.deleted {
		return false
	}
	e.owners[m.ownerID] = struct{}{}
	return true
}

// Do returns a cached value for key, or calls fn and caches the result.
// Only one execution is in-flight for a given key at a time.
func (m *Memoizer) Do(key string, fn func() (any, error)) (any, error) {
	// Fast path: check cache
	if v, ok := cache.Load(key); ok {
		e := v.(*entry)
		if m.addOwner(e) {
			return e.value, nil
		}
		// Entry was deleted concurrently; fall through to slow path.
	}

	// Slow path: singleflight ensures only one compilation per key
	val, err, _ := group.Do(key, func() (any, error) {
		// Double-check after acquiring singleflight
		if v, ok := cache.Load(key); ok {
			e := v.(*entry)
			if m.addOwner(e) {
				return e.value, nil
			}
		}

		data, innerErr := fn()
		if innerErr == nil {
			e := &entry{
				value:  data,
				owners: map[uint64]struct{}{m.ownerID: {}},
			}
			cache.Store(key, e)
		}
		return data, innerErr
	})

	// Ensure this caller is registered as an owner even if its execution
	// was deduplicated by singleflight.
	if err == nil {
		if v, ok := cache.Load(key); ok {
			e := v.(*entry)
			m.addOwner(e)
		}
	}

	return val, err
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
