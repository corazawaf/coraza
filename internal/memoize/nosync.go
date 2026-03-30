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
//
// Deletions are deferred until after Range completes because TinyGo's sync.Map
// holds its internal lock for the entire Range call, so calling Delete inside
// the callback would deadlock.
func Release(ownerID uint64) {
	var toDelete []any
	cache.Range(func(key, value any) bool {
		e := value.(*entry)
		e.mu.Lock()
		delete(e.owners, ownerID)
		if len(e.owners) == 0 {
			e.deleted = true
			toDelete = append(toDelete, key)
		}
		e.mu.Unlock()
		return true
	})
	for _, key := range toDelete {
		cache.Delete(key)
	}
}

// Reset clears the entire cache. Intended for testing.
//
// Keys are collected first and deleted after Range returns to avoid deadlocking
// on TinyGo's mutex-based sync.Map (see Release comment).
func Reset() {
	var keys []any
	cache.Range(func(key, _ any) bool {
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		cache.Delete(key)
	}
}
