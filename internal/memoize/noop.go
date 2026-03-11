// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.no_memoize

package memoize

// Memoizer is a no-op implementation when memoization is disabled.
type Memoizer struct{}

// NewMemoizer returns a no-op Memoizer.
func NewMemoizer(_ uint64) *Memoizer { return &Memoizer{} }

// Do always calls fn directly without caching.
func (m *Memoizer) Do(_ string, fn func() (any, error)) (any, error) { return fn() }

// Release is a no-op when memoization is disabled.
func Release(_ uint64) {}

// Reset is a no-op when memoization is disabled.
func Reset() {}
