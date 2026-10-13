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

func (*urlencodedBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	v.RequestBody().(*collections.Single).Set(b)
	v.RequestBodyLength().(*collections.Single).Set(strconv.Itoa(len(b)))
	// Arguments are decoded in document order straight into ARGS_POST, so the
	// limit truncates deterministically and arguments past it are never
	// decoded.
	argsCol := v.ArgsPost()
	limit := options.ArgumentLimit
	count := 0
	overLimit := false
	urlutil.EachQueryValue(b, '&', func(key, value string) bool {
		if limit > 0 && count >= limit {
			overLimit = true
			return false
		}
		argsCol.Add(key, value)
		count++
		return true
	})
	if overLimit {
		// Both signals: the variable is upstream's contract, the error is the
		// fork's, so the transaction raises REQBODY_ERROR as well.
		v.ArgumentsLimitReached().(*collections.Single).Set("1")
		return ErrArgumentsLimit
	}
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
