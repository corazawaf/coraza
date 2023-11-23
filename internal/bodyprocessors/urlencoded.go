// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"io"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	urlutil "github.com/corazawaf/coraza/v3/internal/url"
)

type urlencodedBodyProcessor struct {
}

const urlUnescape = true

func (*urlencodedBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	values := urlutil.ParseQuery(b, '&', urlUnescape)
	argsCol := v.ArgsPost()
	for k, vs := range values {
		argsCol.Set(k, vs)
	}
	v.RequestBody().(*collections.Single).Set(b)
	v.RequestBodyLength().(*collections.Single).Set(strconv.Itoa(len(b)))
	return nil
}

func (*urlencodedBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = &urlencodedBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("urlencoded", func() plugintypes.BodyProcessor {
		return &urlencodedBodyProcessor{}
	})
}
