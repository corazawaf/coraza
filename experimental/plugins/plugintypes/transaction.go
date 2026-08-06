// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import (
	"context"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// TransactionState tracks the state of a transaction for use in actions and operators.
type TransactionState interface {
	// ID returns the ID of the transaction.
	ID() string // TODO(anuraaga): If only for logging, can be built into logger

	// Variables returns the TransactionVariables of the transaction.
	Variables() TransactionVariables

	// Collection returns a collection from the transaction.
	Collection(idx variables.RuleVariable) collection.Collection

	// Interrupt interrupts the transaction.
	Interrupt(interruption *types.Interruption)

	// DebugLogger returns the logger for this transaction.
	DebugLogger() debuglog.Logger

	// Capturing returns whether the transaction is capturing. CaptureField only works if capturing, this can be used
	// as an optimization to avoid processing specific to capturing fields.
	Capturing() bool // TODO(anuraaga): Only needed in operators?

	// CaptureField captures a field.
	CaptureField(idx int, value string)

	// LastPhase that was evaluated
	LastPhase() types.RulePhase

	// Context returns the context of the transaction.
	Context() context.Context
}

// TransactionVariables has pointers to all the variables of the transaction
type TransactionVariables interface {
	// All iterates over all the variables in this TransactionVariables, invoking f for each.
	// Results are passed in no defined order. If f returns false, iteration stops.
	All(f func(v variables.RuleVariable, col collection.Collection) bool)

	// Simple Variables
	UrlencodedError() collection.Single
	ResponseContentType() collection.Single
	UniqueID() collection.Single
	ArgsCombinedSize() collection.Collection
	FilesCombinedSize() collection.Single
	FullRequestLength() collection.Single
	InboundDataError() collection.Single
	MatchedVar() collection.Single
	MatchedVarName() collection.Single
	MultipartDataAfter() collection.Single
	MultipartPartHeaders() collection.Map
	OutboundDataError() collection.Single
	QueryString() collection.Single
	RemoteAddr() collection.Single
	RemoteHost() collection.Single
	RemotePort() collection.Single
	RequestBodyError() collection.Single
	RequestBodyErrorMsg() collection.Single
	RequestBodyProcessorError() collection.Single
	RequestBodyProcessorErrorMsg() collection.Single
	RequestBodyProcessor() collection.Single
	RequestBasename() collection.Single
	RequestBody() collection.Single
	RequestBodyLength() collection.Single
	RequestFilename() collection.Single
	RequestLine() collection.Single
	RequestMethod() collection.Single
	RequestProtocol() collection.Single
	RequestURI() collection.Single
	RequestURIRaw() collection.Single
	ResponseBody() collection.Single
	ResponseArgs() collection.Map
	ResponseContentLength() collection.Single
	ResponseProtocol() collection.Single
	ResponseStatus() collection.Single
	ResponseBodyProcessor() collection.Single
	ServerAddr() collection.Single
	ServerName() collection.Single
	ServerPort() collection.Single
	HighestSeverity() collection.Single
	StatusLine() collection.Single
	Env() collection.Map
	TX() collection.Map
	Rule() collection.Map
	Duration() collection.Single
	Args() collection.Keyed
	ArgsGet() collection.Map
	ArgsPost() collection.Map
	ArgsPath() collection.Map
	FilesTmpNames() collection.Map
	Geo() collection.Map
	Files() collection.Map
	RequestCookies() collection.Map
	RequestHeaders() collection.Map
	ResponseHeaders() collection.Map
	MultipartName() collection.Map
	MatchedVarsNames() collection.Keyed
	MultipartFilename() collection.Map
	MatchedVars() collection.Map
	FilesSizes() collection.Map
	FilesNames() collection.Map
	FilesTmpContent() collection.Map
	ResponseHeadersNames() collection.Keyed
	RequestHeadersNames() collection.Keyed
	RequestCookiesNames() collection.Keyed
	XML() collection.Map
	RequestXML() collection.Map
	ResponseXML() collection.Map
	ArgsNames() collection.Keyed
	ArgsGetNames() collection.Keyed
	ArgsPostNames() collection.Keyed
	MultipartStrictError() collection.Single
}
