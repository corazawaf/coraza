// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// processRequest fills all transaction variables from an http.Request object
// Most implementations of Coraza will probably use http.Request objects
// so this will implement all phase 0, 1 and 2 variables
// Note: This function will stop after an interruption
// Note: Do not manually fill any request variables
func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	// Host will always be removed from req.Headers() and promoted to the
	// Request.Host field, so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(req.Host)
	}

	// Transfer-Encoding header is removed by go/http
	// We manually add it to make rules relying on it work (E.g. CRS rule 920171)
	if req.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}

	if tx.IsRequestBodyAccessible() {
		// We only do body buffering if the transaction requires request
		// body inspection, otherwise we just let the request follow its
		// regular flow.
		if req.Body != nil && req.Body != http.NoBody {
			it, _, err := tx.ReadRequestBodyFrom(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to append request body: %s", err.Error())
			}

			if it != nil {
				return it, nil
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				return nil, fmt.Errorf("failed to get the request body: %s", err.Error())
			}

			// Adds all remaining bytes beyond the coraza limit to its buffer
			// It happens when the partial body has been processed and it did not trigger an interruption
			body := io.MultiReader(rbr, req.Body)
			// req.Body is transparently reinizialied with a new io.ReadCloser.
			// The http handler will be able to read it.
			// Prior to Go 1.19 NopCloser does not implement WriterTo if the reader implements it.
			// - https://github.com/golang/go/issues/51566
			// - https://tip.golang.org/doc/go1.19#minor_library_changes
			// This avoid errors like "failed to process request: malformed chunked encoding" when
			// using io.Copy.
			// In Go 1.19 we just do `req.Body = io.NopCloser(reader)`
			if rwt, ok := body.(io.WriterTo); ok {
				req.Body = struct {
					io.Reader
					io.WriterTo
					io.Closer
				}{body, rwt, req.Body}
			} else {
				req.Body = struct {
					io.Reader
					io.Closer
				}{body, req.Body}
			}
		}
	}

	return tx.ProcessRequestBody()
}

var (
	forbiddenMessage []byte = []byte("Forbidden")
	errorMessage     []byte = []byte("Internal Server Error")
)

// Options represents the options for the experimental middleware
type Options struct {
	// OnInterruption is a function that will be called when an interruption is triggered
	// This function will render the error page and write the response
	OnInterruption func(types.Interruption, http.ResponseWriter, *http.Request)

	// OnError is a function that will be called when an error is triggered
	// This function will render the error page and write the response
	OnError func(error, http.ResponseWriter, *http.Request)

	// BeforeClose is a function that will be called before the transaction is closed
	// If this function is overwritten tx.ProcessLogging() has to be called manually
	// It is useful to complement observability signals like metrics, traces and logs
	// by providing additional context about the transaction and the rules that were matched.
	BeforeClose func(types.Transaction, *http.Request)

	// OnTransactionStarted is called when a new transaction is started. It is useful to
	// complement observability signals like metrics, traces and logs by providing additional
	// context about the transaction.
	OnTransactionStarted func(tx plugintypes.TransactionState)

	// ProcessResponse enables the processing of the response
	// If the response is not processed, the middleware will only consume
	// request headers and request body, also, response will have to be
	// processed by the next handler.
	ProcessResponse bool

	// WAF represents the WAF instance to use
	// New transactions will be created using this WAF instance
	WAF coraza.WAF

	// SamplingRate represents the rate of sampling for the middleware
	// If the rate is 0, the middleware will not sample
	// If the rate is 100, the middleware will sample all requests
	SamplingRate int
}

var defaultOptions = Options{
	OnInterruption: func(i types.Interruption, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write(forbiddenMessage) //nolint:errcheck
	},
	OnError: func(e error, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(errorMessage) //nolint:errcheck
		// TODO generate log?
	},
	BeforeClose: func(tx types.Transaction, r *http.Request) {
		tx.ProcessLogging()
	},
	OnTransactionStarted: func(tx plugintypes.TransactionState) {
		// Nothing to do here
	},
	ProcessResponse: false,
	SamplingRate:    0,
}

func (o *Options) loadDefaults() {
	if o.OnInterruption == nil {
		o.OnInterruption = defaultOptions.OnInterruption
	}

	if o.OnError == nil {
		o.OnError = defaultOptions.OnError
	}

	if o.BeforeClose == nil {
		o.BeforeClose = defaultOptions.BeforeClose
	}

	if o.OnTransactionStarted == nil {
		o.OnTransactionStarted = defaultOptions.OnTransactionStarted
	}

}

// DefaultOptions returns the default options for the middleware
func DefaultOptions(waf coraza.WAF) Options {
	opts := Options{
		WAF: waf,
	}
	opts.loadDefaults()
	return opts
}

func WrapHandler(waf coraza.WAF, h http.Handler) http.Handler {
	return wrapHandler(h, DefaultOptions(waf))
}

func WrapHandlerWithOptions(h http.Handler, opts Options) http.Handler {
	opts.loadDefaults()
	return wrapHandler(h, opts)
}

func wrapHandler(h http.Handler, opts Options) http.Handler {
	if opts.WAF == nil {
		return h
	}

	newTX := func(*http.Request) types.Transaction {
		return opts.WAF.NewTransaction()
	}

	if ctxwaf, ok := opts.WAF.(experimental.WAFWithOptions); ok {
		newTX = func(r *http.Request) types.Transaction {
			return ctxwaf.NewTransactionWithOptions(experimental.Options{
				Context: r.Context(),
			})
		}
	}

	fn := func(w http.ResponseWriter, r *http.Request) {
		tx := newTX(r)
		txs := tx.(plugintypes.TransactionState)
		opts.OnTransactionStarted(txs)
		defer func() {
			// BeforeClose should call tx.ProcessLogging() for phase 5 processing
			opts.BeforeClose(tx, r)
			// we remove temporary files and free some memory
			if err := tx.Close(); err != nil {
				tx.DebugLogger().Error().Err(err).Msg("Failed to close the transaction")
			}
		}()

		// Early return, Coraza is not going to process any rule
		if tx.IsRuleEngineOff() {
			// response writer is not going to be wrapped, but used as-is
			// to generate the response
			h.ServeHTTP(w, r)
			return
		}

		// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
		// ProcessRequestHeaders and ProcessRequestBody.
		// It fails if any of these functions returns an error and it stops on interruption.
		if it, err := processRequest(tx, r); err != nil {
			tx.DebugLogger().Error().Err(err).Msg("Failed to process request")
			return
		} else if it != nil {
			w.WriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK))
			return
		}

		ww, processResponse := wrap(w, r, tx)

		// We continue with the other middlewares by catching the response
		h.ServeHTTP(ww, r)

		if err := processResponse(tx, r); err != nil {
			tx.DebugLogger().Error().Err(err).Msg("Failed to close the response")
			return
		}
	}

	return http.HandlerFunc(fn)
}

// obtainStatusCodeFromInterruptionOrDefault returns the desired status code derived from the interruption
// on a "deny" action or a default value.
func obtainStatusCodeFromInterruptionOrDefault(it *types.Interruption, defaultStatusCode int) int {
	if it.Action == "deny" {
		statusCode := it.Status
		if statusCode == 0 {
			statusCode = 403
		}

		return statusCode
	}

	return defaultStatusCode
}
