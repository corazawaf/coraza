// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package operators implements SecLang rule operators for matching and validation.
//
// Operators are functions that evaluate input data and return true or false.
// They are used in `SecRule` directives with the syntax: `@operatorName argument`
//
// Example:
//
// ```seclang
// SecRule ARGS "@contains evil" "id:100,deny"
// ```
//
// Operators can be negated using the ! prefix:
//
// ```seclang
// SecRule REQUEST_LINE "!@beginsWith GET" "id:101,deny"
// ```
//
// For the complete list of available operators, see: https://coraza.io/docs/seclang/operators/
package operators

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var operators = map[string]plugintypes.OperatorFactory{}

func memoizeDo(m plugintypes.Memoizer, key string, fn func() (any, error)) (any, error) {
	if m != nil {
		return m.Do(key, fn)
	}
	return fn()
}

// memoizeKey builds the cache key for an operator's compiled artifact from the
// operator name and the content the artifact is built from. The memoizer's
// cache is shared by every WAF in the process, so a key that names where the
// content came from (a dataset name, a file path) instead of the content
// itself hands one WAF another WAF's matcher (GHSA-wc2q-x24m-8c5f), and a key
// without the operator name lets two operators with the same argument collide
// on an entry of the wrong type. SHA-256 keeps the key bounded and is
// FIPS-approved.
//
// Every caller of the memoizer, including the plain regexp ones outside this
// package, prefixes its key with its own name, so no caller can produce
// another caller's key through its argument.
//
// Each element is length-prefixed: with a separator byte instead, an element
// containing that byte reads as two elements, and a list crafted to hash like
// another list would take over its matcher.
func memoizeKey(op string, content ...string) string {
	h := sha256.New()
	var n [binary.MaxVarintLen64]byte
	for _, c := range content {
		h.Write(n[:binary.PutUvarint(n[:], uint64(len(c)))])
		_, _ = io.WriteString(h, c)
	}
	return op + ":" + hex.EncodeToString(h.Sum(nil))
}

// Get returns an operator by name
func Get(name string, options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	if op, ok := operators[name]; ok {
		return op(options)
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op plugintypes.OperatorFactory) {
	operators[name] = op
}
