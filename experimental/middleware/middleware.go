// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"net/http"

	"github.com/corazawaf/coraza/v3"
)

// Options represents the options for the experimental middleware
type Options struct {
	// EnforceBlocking enables the blocking of requests that are interrupted
	// Interruption will be available under the request context as:
	// 	ctx.Value("coraza_interruption").(types.Interruption)
	EnforceBlocking bool

	// ProcessResponse enables the processing of the response
	// If the response is not processed, the middleware will only consume
	// request headers and request body. It will also just run phases 1 and 2.
	ProcessResponse bool

	// WAF represents the WAF instance to use
	// New transactions will be created using this WAF instance
	WAF coraza.WAF
}

// DefaultOptions returns the default options for the middleware
func DefaultOptions(waf coraza.WAF) Options {
	return Options{
		EnforceBlocking: true,
		ProcessResponse: false,
		WAF:             waf,
	}
}

// WrapHandler wraps an http.Handler with the HTTP middleware
// Request context will be used to store the transaction and interruption
// Keys are:
//   - coraza_transaction: types.Transaction
//   - coraza_interruption: types.Interruption
//
// The middleware will flush the request body and it will consume
// the response in case ProcessResponse Option is enabled
// Some additional Context variables are available to create transactions:
//   - coraza_transaction_id: string
func WrapHandler(options Options, h http.Handler) http.Handler {
	// TODO: implement
	return h
}
