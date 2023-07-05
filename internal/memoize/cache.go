// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

// Highly inspired in https://github.com/patrickmn/go-cache/blob/master/cache.go

package memoize

import (
	"sync"
)

// Cache is a simple in-memory key-value store.
type cache struct {
	mu       sync.RWMutex
	isClosed bool
	entries  map[string]interface{}
}

// newCache returns a new cache.
func newCache() *cache {
	return &cache{
		entries: make(map[string]interface{}),
	}
}

// set the value for the given key.
func (c *cache) set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return
	}
	c.entries[key] = value
}

// get the value for the given key.
func (c *cache) get(key string) (interface{}, bool) {
	c.mu.RLock()
	item, found := c.entries[key]
	if !found {
		c.mu.RUnlock()
		return nil, false
	}
	c.mu.RUnlock()
	return item, true
}

// Close the cache.
func (c *cache) Close() {
	c.mu.Lock()
	c.isClosed = true
	c.entries = nil
	c.mu.Unlock()
}
