// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

// Highly inspired in https://github.com/patrickmn/go-cache/blob/master/cache.go

package memoize

import (
	"sync"
)

type cache struct {
	mu      sync.RWMutex
	entries map[string]interface{}
}

func newCache() *cache {
	return &cache{
		entries: make(map[string]interface{}),
	}
}

func (c *cache) set(key string, value interface{}) {
	c.mu.Lock()
	c.entries[key] = value
	c.mu.Unlock()
}

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
