// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"io"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/url"
	"github.com/corazawaf/coraza/v3/rules"
)

type urlencodedBodyProcessor struct {
}

func (*urlencodedBodyProcessor) ProcessRequest(reader io.Reader, v rules.TransactionVariables, options Options) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	values := url.ParseQuery(b, '&')
	argsCol := v.ArgsPost()
	for k, vs := range values {
		argsCol.Set(k, vs)
	}
	v.RequestBody().Set(b)
	v.RequestBodyLength().Set(strconv.Itoa(len(b)))
	return nil
}

func (*urlencodedBodyProcessor) ProcessResponse(reader io.Reader, v rules.TransactionVariables, options Options) error {
	return nil
}

var (
	_ BodyProcessor = &urlencodedBodyProcessor{}
)

func init() {
	Register("urlencoded", func() BodyProcessor {
		return &urlencodedBodyProcessor{}
	})
}
