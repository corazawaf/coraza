// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package sync

func NewPool(new func() interface{}) Pool {
	return &tinygoPool{
		new: new,
	}
}

// TinyGo is not concurrent, so we do not need a complicated implementation. We just want to reuse memory.
type tinygoPool struct {
	pool []interface{}
	new  func() interface{}
}

func (p *tinygoPool) Get() interface{} {
	if len(p.pool) == 0 {
		return p.new()
	}
	x := p.pool[len(p.pool)-1]
	p.pool = p.pool[:len(p.pool)-1]
	return x
}

func (p *tinygoPool) Put(x interface{}) {
	p.pool = append(p.pool, x)
}
