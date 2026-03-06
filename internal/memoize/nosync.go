// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.no_memoize

package memoize

import "sync"

var cache sync.Map

// Memoizer caches expensive function calls on a global cache.
// TinyGo variant without singleflight.
type Memoizer struct{}

// NewMemoizer creates a new Memoizer.
func NewMemoizer() *Memoizer {
	return &Memoizer{}
}

// Do returns a cached value for key, or calls fn and caches the result.
func (m *Memoizer) Do(key string, fn func() (any, error)) (any, error) {
	if value, ok := cache.Load(key); ok {
		return value, nil
	}

	data, err := fn()
	if err == nil {
		cache.Store(key, data)
	}
	return data, err
}
