// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"io"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/url"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type urlencodedBodyProcessor struct {
}

func (*urlencodedBodyProcessor) ProcessRequest(reader io.Reader, collections [types.VariablesCount]collection.Collection, options Options) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	values := url.ParseQuery(b, '&')
	argsCol := (collections[variables.ArgsPost]).(*collection.Map)
	for k, vs := range values {
		argsCol.Set(k, vs)
	}
	(collections[variables.RequestBody]).(*collection.Simple).Set(b)
	(collections[variables.RequestBodyLength]).(*collection.Simple).Set(strconv.Itoa(len(b)))
	return nil
}

func (*urlencodedBodyProcessor) ProcessResponse(reader io.Reader, collection [types.VariablesCount]collection.Collection, options Options) error {
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
