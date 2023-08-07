// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && memoize_builders

// https://github.com/kofalt/go-memoize/blob/master/memoize.go

package memoize

import (
	"sync"

	"golang.org/x/sync/singleflight"
)

var doer = makeDoer(new(sync.Map), new(singleflight.Group))

// Do executes and returns the results of the given function, unless there was a cached
// value of the same key. Only one execution is in-flight for a given key at a time.
// The boolean return value indicates whether v was previously stored.
func Do(key string, fn func() (interface{}, error)) (interface{}, error) {
	value, err, _ := doer(key, fn)
	return value, err
}

// makeDoer returns a function that executes and returns the results of the given function
func makeDoer(cache *sync.Map, group *singleflight.Group) func(string, func() (interface{}, error)) (interface{}, error, bool) {
	return func(key string, fn func() (interface{}, error)) (interface{}, error, bool) {
		// Check cache
		value, found := cache.Load(key)
		if found {
			return value, nil, true
		}

		// Combine memoized function with a cache store
		value, err, _ := group.Do(key, func() (interface{}, error) {
			data, innerErr := fn()
			if innerErr == nil {
				cache.Store(key, data)
			}

			return data, innerErr
		})

		return value, err, false
	}
}
