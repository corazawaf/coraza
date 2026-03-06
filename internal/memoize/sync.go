// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.no_memoize

package memoize

import (
	"sync"

	"golang.org/x/sync/singleflight"
)

var (
	cache sync.Map
	group singleflight.Group
)

// Memoizer caches expensive function calls on a global cache.
type Memoizer struct{}

// NewMemoizer creates a new Memoizer.
func NewMemoizer() *Memoizer {
	return &Memoizer{}
}

// Do returns a cached value for key, or calls fn and caches the result.
// Only one execution is in-flight for a given key at a time.
func (m *Memoizer) Do(key string, fn func() (any, error)) (any, error) {
	// Fast path: check cache
	if value, ok := cache.Load(key); ok {
		return value, nil
	}

	// Slow path: singleflight ensures only one compilation per key
	value, err, _ := group.Do(key, func() (any, error) {
		// Double-check after acquiring singleflight
		if value, ok := cache.Load(key); ok {
			return value, nil
		}

		data, innerErr := fn()
		if innerErr == nil {
			cache.Store(key, data)
		}
		return data, innerErr
	})

	return value, err
}
