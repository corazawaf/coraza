// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
)

type bodyProcessorWrapper = func() plugintypes.BodyProcessor

var processors = map[string]bodyProcessorWrapper{}

// RegisterBodyProcessor registers a body processor
// by name. If the body processor is already registered,
// it will be overwritten
func RegisterBodyProcessor(name string, fn func() plugintypes.BodyProcessor) {
	processors[name] = fn
}

// GetBodyProcessor returns a body processor by name
// If the body processor is not found, it returns an error
func GetBodyProcessor(name string) (plugintypes.BodyProcessor, error) {
	if fn, ok := processors[strings.ToLower(name)]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}

// ArgumentsLimitExceededMsg is the request body error reason recorded when a
// request body argument is dropped because SecArgumentsLimit was reached.
const ArgumentsLimitExceededMsg = "SecArgumentsLimit exceeded"

// RecordRequestBodyError sets REQBODY_ERROR and adds reason to REQBODY_ERROR_MSG.
// The first reason is prefixed with the active body processor, as in
// "JSON: invalid JSON"; later reasons are joined with "; ". A reason already
// contained in the message is not repeated. It lives here so processors and the
// transaction share it.
func RecordRequestBodyError(v plugintypes.TransactionVariables, reason string) {
	v.RequestBodyError().(*collections.Single).Set("1")
	errMsg := v.RequestBodyErrorMsg().(*collections.Single)
	if current := errMsg.Get(); current == "" {
		if processor := v.RequestBodyProcessor().Get(); processor != "" {
			reason = processor + ": " + reason
		}
		errMsg.Set(reason)
	} else if !strings.Contains(current, reason) {
		errMsg.Set(current + "; " + reason)
	}
}

// setRequestArgumentsLimitReached records request-body truncation in
// ARGUMENTS_LIMIT_REACHED and REQBODY_ERROR. Not used for response bodies.
func setRequestArgumentsLimitReached(v plugintypes.TransactionVariables) {
	v.ArgumentsLimitReached().(*collections.Single).Set("1")
	RecordRequestBodyError(v, ArgumentsLimitExceededMsg)
}
