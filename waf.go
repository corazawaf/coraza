// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"fmt"
	"io"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

// WAF instance is used to store configurations and rules
// Every web application should have a different WAF instance,
// but you can share an instance if you are ok with sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a WAF instance
// You can use as many WAF instances as you want, and they are
// concurrent safe
type WAF interface {
	// NewTransaction Creates a new initialized transaction for this WAF instance
	NewTransaction(ctx context.Context) Transaction
}

// NewWAFWithConfig creates a new WAF instance with the provided configuration.
func NewWAFWithConfig(config WAFConfig) (WAF, error) {
	c := config.(*wafConfig)

	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)

	if c.fsRoot != nil {
		parser.SetRoot(c.fsRoot)
	}

	for _, r := range c.rules {
		switch {
		case r.rule != nil:
			if err := waf.Rules.Add(r.rule); err != nil {
				return nil, fmt.Errorf("invalid WAF config: %w", err)
			}
		case r.str != "":
			if err := parser.FromString(r.str); err != nil {
				return nil, fmt.Errorf("invalid WAF config: %w", err)
			}
		case r.file != "":
			if err := parser.FromFile(r.file); err != nil {
				return nil, fmt.Errorf("invalid WAF config: %w", err)
			}
		}
	}

	if a := c.auditLog; a != nil {
		// TODO(anuraaga): Can't override AuditEngineOn from rules to off this way.
		if a.relevantOnly {
			waf.AuditEngine = types.AuditEngineRelevantOnly
		} else {
			waf.AuditEngine = types.AuditEngineOn
		}

		waf.AuditLogParts = a.parts

		if a.logger != nil {
			waf.AuditLogWriter = a.logger
		}
	}

	if c.contentInjection {
		waf.ContentInjection = true
	}

	if r := c.requestBody; r != nil {
		waf.RequestBodyAccess = true
		waf.RequestBodyLimit = int64(r.limit)
		waf.RequestBodyInMemoryLimit = int64(r.inMemoryLimit)
	}

	if r := c.responseBody; r != nil {
		waf.ResponseBodyAccess = true
		waf.ResponseBodyLimit = int64(r.limit)
	}

	if c.debugLogger != nil {
		waf.Logger = c.debugLogger
	}

	if c.errorLogger != nil {
		waf.ErrorLogCb = c.errorLogger
	}

	return wafWrapper{waf: waf}, nil
}

type wafWrapper struct {
	waf *corazawaf.WAF
}

// NewTransaction implements the same method on WAF.
func (w wafWrapper) NewTransaction(ctx context.Context) Transaction {
	return w.waf.NewTransaction(ctx)
}

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
	ProcessRequestHeaders() *types.Interruption

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
	ProcessRequestBody() (*types.Interruption, error)

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
	ProcessResponseHeaders(code int, proto string) *types.Interruption

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
	ProcessResponseBody() (*types.Interruption, error)

	// ProcessLogging Logging all information relative to this transaction.
	// An error log
	// At this point there is not need to hold the connection, the response can be
	// delivered prior to the execution of this method.
	ProcessLogging()

	// Interrupted will return true if the transaction was interrupted
	Interrupted() bool

	// GetInterruption returns the types.Interruption if the request was interrupted,
	// or nil otherwise.
	GetInterruption() *types.Interruption

	// GetMatchedRules returns the rules that have matched the requests with associated information.
	GetMatchedRules() []types.MatchedRule

	// Closer closes the transaction and releases any resources associated with it such as request/response bodies.
	io.Closer
}
