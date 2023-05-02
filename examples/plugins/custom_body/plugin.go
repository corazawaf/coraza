// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"io"

	"github.com/corazawaf/coraza/v3/bodyprocessors"
	"github.com/corazawaf/coraza/v3/rules"
)

type customBodyProcessor struct {
}

func (*customBodyProcessor) ProcessRequest(reader io.Reader, v rules.TransactionVariables, _ bodyprocessors.Options) error {

	return nil
}

func (*customBodyProcessor) ProcessResponse(reader io.Reader, v rules.TransactionVariables, _ bodyprocessors.Options) error {
	return nil
}

func readCustom(reader io.Reader) (map[string]string, error) {

}

var (
	_ bodyprocessors.BodyProcessor = &customBodyProcessor{}
)

func init() {
	bodyprocessors.Register("custom", func() bodyprocessors.BodyProcessor {
		return &customBodyProcessor{}
	})
}
