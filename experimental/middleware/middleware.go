// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"embed"
	"net/http"

	"github.com/corazawaf/coraza/v3"
)

//go:embed error_template.html error_template.html
var embededTemplates embed.FS

var (
	errorTemplate        []byte
	interruptionTemplate []byte
)

func init() {
	var err error
	errorTemplate, err = embededTemplates.ReadFile("error_template.html")
	if err != nil {
		panic(err)
	}
	interruptionTemplate, err = embededTemplates.ReadFile("interruption_template.html")
	if err != nil {
		panic(err)
	}

}

// Options represents the options for the experimental middleware
type Options struct {
	// EnforceBlocking enables the blocking of requests that are interrupted
	// Interruption will be available under the request context as:
	// 	ctx.Value("coraza_interruption").(types.Interruption)
	EnforceBlocking bool

	// ProcessResponse enables the processing of the response
	// If the response is not processed, the middleware will only consume
	// request headers and request body, also, response will have to be
	// processed by the next handler.
	// The next handler will only have access to the request body through
	// the transaction object.
	ProcessResponse bool

	// AutoClose enables the automatic closing of the transaction
	// If the transaction is closed, request and body buffers cannot
	// be retrieved. Interruption will still be available under the
	// request context
	// Please note that if a Transaction is not properly closed,
	// it will lead to a memory leak. Transactions can be closed manually:
	// 	ctx.Value("coraza_transaction").(types.Transaction).Close()
	AutoClose bool

	// WAF represents the WAF instance to use
	// New transactions will be created using this WAF instance
	WAF coraza.WAF

	// SamplingRate represents the rate of sampling for the middleware
	// If the rate is 0, the middleware will not sample
	// If the rate is 100, the middleware will sample all requests
	SamplingRate int

	// CustomInterruptionTemplate represents the custom interruption template
	// If the interruption is not processed, the middleware will use a default
	// Interruption template supports variables in macro expansion format: %{var}
	// Variables are:
	//   - transaction_id
	CustomInterruptionTemplate []byte

	// CustomErrorTemplate represents the custom error template
	// If the middleware fails to process the request, it will use a default
	// Error template supports variables in macro expansion format: %{var}
	// Variables are:
	//   - transaction_id
	//   - error
	CustomErrorTemplate []byte
}

// DefaultOptions returns the default options for the middleware
// Default options are:
//   - EnforceBlocking: true
//   - AutoClose: true
//   - ProcessResponse: false
//   - SamplingRate: 0%
func DefaultOptions(waf coraza.WAF) Options {
	return Options{
		EnforceBlocking: true,
		AutoClose:       true,
		ProcessResponse: false,
		WAF:             waf,
		SamplingRate:    0,
	}
}

// WrapHandler wraps an http.Handler with the HTTP middleware
// Request context will be used to store the transaction and interruption
// Keys are:
//   - coraza_transaction: types.Transaction
//   - coraza_interruption: types.Interruption
//   - coraza_error: error
//
// If Coraza fails to process the request, the middleware will return a generic error.
// The next handler will not be executed and coraza_error will be available under
// the request context.
//
// The middleware will flush the request body and it will consume
// the response in case ProcessResponse Option is enabled.
// Request and Response bodies can be accessed through the transaction object.
// Some additional Context variables are available to create transactions:
//   - coraza_transaction_id: string
func WrapHandler(options Options, h http.Handler) http.Handler {
	// TODO: implement
	return h
}
