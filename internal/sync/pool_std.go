// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package sync

import "sync"

func NewPool(new func() interface{}) Pool {
	return &stdPool{
		pool: sync.Pool{
			New: new,
		},
	}
}

type stdPool struct {
	pool sync.Pool
}

func (p *stdPool) Get() interface{} {
	return p.pool.Get()
}

func (p *stdPool) Put(x interface{}) {
	p.pool.Put(x)
}
