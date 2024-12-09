// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type LazySingle[T any] struct {
	*Single
	initialize bool
	fn         func(T) string
	args       T
}

var (
	_ collection.Single = &LazySingle[int]{}
)

func NewLazySingle[T any](variable variables.RuleVariable) *LazySingle[T] {
	return &LazySingle[T]{
		Single: &Single{variable: variable},
	}
}

func (l *LazySingle[T]) initSingle() {
	if l.fn != nil {
		l.data = l.fn(l.args)
		l.fn = nil
	}
	var emptyT T
	l.args = emptyT
	l.initialize = true
}

func (l *LazySingle[T]) Get() string {
	if !l.initialize {
		l.initSingle()
	}

	return l.data
}

func (l *LazySingle[T]) Set(valFn func(T) string, args T) {
	l.fn = valFn
	l.args = args
}

func (l *LazySingle[T]) FindAll() []types.MatchData {
	if !l.initialize {
		l.initSingle()
	}

	return l.Single.FindAll()
}
