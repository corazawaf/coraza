// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package sync

// Pool is an interface matching Go's sync.Pool. We delegate normally but reimplement for TinyGo
// since it does not have a pooling implementation.
type Pool interface {
	Get() interface{}
	Put(x interface{})
}
