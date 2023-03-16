// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"io"

	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/rules"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v rules.TransactionVariables, options Options) error {
	x := v.RequestXML().(*collections.XML)
	if err := x.SetDoc(reader); err != nil {
		return err
	}
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v rules.TransactionVariables, options Options) error {
	x := v.ResponseXML().(*collections.XML)
	if err := x.SetDoc(reader); err != nil {
		return err
	}
	return nil
}

var (
	_ BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	Register("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
