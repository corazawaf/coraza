// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package bodyprocessors

import (
	"errors"
	"io"

	"github.com/corazawaf/coraza/v3/rules"
)

type xmlBodyProcessor struct{}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v rules.TransactionVariables, options Options) error {
	return errors.New("not implemented")
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v rules.TransactionVariables, options Options) error {
	return errors.New("not implemented")
}

var _ BodyProcessor = &xmlBodyProcessor{}

func init() {
	Register("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
