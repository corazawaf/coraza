// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type LazySingle struct {
	*Single
	initialize bool
	fn         func() string
}

var (
	_       collection.Single = &LazySingle{}
	emptyFn                   = func() string { return "" }
)

func NewLazySingle(variable variables.RuleVariable) *LazySingle {
	return &LazySingle{
		Single: &Single{variable: variable},
		fn:     emptyFn,
	}
}

func (l *LazySingle) initSingle() {
	l.data = l.fn()
	l.fn = nil
	l.initialize = true
}

func (l *LazySingle) Get() string {
	if !l.initialize {
		l.initSingle()
	}

	return l.data
}

func (l *LazySingle) Set(valFn func() string) {
	l.fn = valFn
}

func (l *LazySingle) FindAll() []types.MatchData {
	if !l.initialize {
		l.initSingle()
	}

	return l.Single.FindAll()
}
