// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"io"
)

// Transaction is created from a WAF instance to handle web requests and responses,
// it contains a copy of most WAF configurations that can be safely changed.
// Transactions are used to store all data like URLs, request and response
// headers. Transactions are used to evaluate rules by phase and generate disruptive
// actions. Disruptive actions can be read from *tx.Interruption.
// It is safe to manage multiple transactions but transactions themself are not
// thread safe
type Transaction interface {
	// ProcessConnection should be called at very beginning of a request process, it is
	// expected to be executed prior to the virtual host resolution, when the
	// connection arrives on the server.
	// Important: Remember to check for a possible intervention.
	ProcessConnection(client string, cPort int, server string, sPort int)

	// ProcessURI Performs the analysis on the URI and all the query string variables.
	// This method should be called at very beginning of a request process, it is
	// expected to be executed prior to the virtual host resolution, when the
	// connection arrives on the server.
	// note: There is no direct connection between this function and any phase of
	//
	//	the SecLanguages phases. It is something that may occur between the
	//	SecLanguage phase 1 and 2.
	//
	// note: This function won't add GET arguments, they must be added with AddArgument
	ProcessURI(uri string, method string, httpVersion string)

	// AddRequestHeader Adds a request header
	//
	// With this method it is possible to feed Coraza with a request header.
	// Note: Golang's *http.Request object will not contain a "Host" header,
	// and you might have to force it
	AddRequestHeader(key string, value string)

	// ProcessRequestHeaders Performs the analysis on the request readers.
	//
	// This method perform the analysis on the request headers, notice however
	// that the headers should be added prior to the execution of this function.
	//
	// note: Remember to check for a possible intervention.
	ProcessRequestHeaders() *Interruption

	// RequestBodyWriter returns a io.Writer for writing the request body to.
	// Contents will be buffered until the transaction is closed.
	RequestBodyWriter() io.Writer

	// RequestBodyReader returns a reader for content that has been written by
	// RequestBodyWriter. This can be useful for buffering the request body
	// within the Transaction while also passing it further in an HTTP framework.
	RequestBodyReader() (io.Reader, error)

	// ProcessRequestBody Performs the request body (if any)
	//
	// This method perform the analysis on the request body. It is optional to
	// call that function. If this API consumer already know that there isn't a
	// body for inspect it is recommended to skip this step.
	//
	// Remember to check for a possible intervention.
	ProcessRequestBody() (*Interruption, error)

	// AddResponseHeader Adds a response header variable
	//
	// With this method it is possible to feed Coraza with a response header.
	AddResponseHeader(key string, value string)

	// ProcessResponseHeaders Perform the analysis on the response readers.
	//
	// This method perform the analysis on the response headers, notice however
	// that the headers should be added prior to the execution of this function.
	//
	// note: Remember to check for a possible intervention.
	ProcessResponseHeaders(code int, proto string) *Interruption

	// ResponseBodyWriter returns a io.Writer for writing the response body to.
	// Contents will be buffered until the transaction is closed.
	ResponseBodyWriter() io.Writer

	// ResponseBodyReader returns a reader for content that has been written by
	// ResponseBodyWriter. This can be useful for buffering the response body
	// within the Transaction while also passing it further in an HTTP framework.
	ResponseBodyReader() (io.Reader, error)

	// ProcessResponseBody Perform the request body (if any)
	//
	// This method perform the analysis on the request body. It is optional to
	// call that method. If this API consumer already know that there isn't a
	// body for inspect it is recommended to skip this step.
	//
	// note Remember to check for a possible intervention.
	ProcessResponseBody() (*Interruption, error)

	// ProcessLogging Logging all information relative to this transaction.
	// An error log
	// At this point there is not need to hold the connection, the response can be
	// delivered prior to the execution of this method.
	ProcessLogging()

	// IsRuleEngineOff will return true if RuleEngine is set to Off
	IsRuleEngineOff() bool

	// RequestBodyAccessible will return true if RequestBody access has been enabled by RequestBodyAccess
	//
	// This can be used to perform checks just before calling request body related functions.
	// In order to avoid any risk of performing wrong early assumptions, perform early checks on this value
	// only if the API consumer requires them for specific server/proxy actions
	// (such as avoiding proxy side buffering).
	// Note: it returns the current status, later rules may still change it via ctl actions.
	RequestBodyAccessible() bool

	// ResponseBodyAccessible will return true if ResponseBody access has been enabled by ResponseBodyAccess
	//
	// This can be used to perform checks just before calling response body related functions.
	// In order to avoid any risk of performing wrong early assumptions, perform early checks on this value
	// only if the API consumer requires them for specific server/proxy actions
	// (such as avoiding proxy side buffering).
	// Note: it returns the current status, later rules may still change it via ctl actions.
	ResponseBodyAccessible() bool

	// Interrupted will return true if the transaction was interrupted
	Interrupted() bool

	// Interruption returns the types.Interruption if the request was interrupted,
	// or nil otherwise.
	Interruption() *Interruption

	// MatchedRules returns the rules that have matched the requests with associated information.
	MatchedRules() []MatchedRule

	// Closer closes the transaction and releases any resources associated with it such as request/response bodies.
	io.Closer
}
