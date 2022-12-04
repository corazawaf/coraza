// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"io"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/loggers"
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

	// ResponseBodyWriter allows writing to the response body.
	// TODO(anuraaga): Should this be combined with interruption? Any action writing anything to response can be dangerous.
	ResponseBodyWriter() io.Writer

	// ContentInjection returns whether content injection is enabled for this transaction.
	ContentInjection() bool // TODO(anuraaga): Should be resolved at Init time when WAF is truly immutable.
	// DebugLogger returns the logger for this transaction.
	DebugLogger() loggers.DebugLogger

	// Capturing returns whether the transaction is capturing. CaptureField only works if capturing, this can be used
	// as an optimization to avoid processing specific to capturing fields.
	Capturing() bool // TODO(anuraaga): Only needed in operators?
	// CaptureField captures a field.
	CaptureField(idx int, value string)
}

// TransactionVariables has pointers to all the variables of the transaction
type TransactionVariables interface {
	// Simple Variables
	UserID() *collection.Simple
	UrlencodedError() *collection.Simple
	ResponseContentType() *collection.Simple
	UniqueID() *collection.Simple
	ArgsCombinedSize() *collection.SizeProxy
	AuthType() *collection.Simple
	FilesCombinedSize() *collection.Simple
	FullRequest() *collection.Simple
	FullRequestLength() *collection.Simple
	InboundDataError() *collection.Simple
	MatchedVar() *collection.Simple
	MatchedVarName() *collection.Simple
	MultipartBoundaryQuoted() *collection.Simple
	MultipartBoundaryWhitespace() *collection.Simple
	MultipartCrlfLfLines() *collection.Simple
	MultipartDataAfter() *collection.Simple
	MultipartDataBefore() *collection.Simple
	MultipartFileLimitExceeded() *collection.Simple
	MultipartPartHeaders() *collection.Map
	MultipartHeaderFolding() *collection.Simple
	MultipartInvalidHeaderFolding() *collection.Simple
	MultipartInvalidPart() *collection.Simple
	MultipartInvalidQuoting() *collection.Simple
	MultipartLfLine() *collection.Simple
	MultipartMissingSemicolon() *collection.Simple
	MultipartStrictError() *collection.Simple
	MultipartUnmatchedBoundary() *collection.Simple
	OutboundDataError() *collection.Simple
	PathInfo() *collection.Simple
	QueryString() *collection.Simple
	RemoteAddr() *collection.Simple
	RemoteHost() *collection.Simple
	RemotePort() *collection.Simple
	RequestBodyError() *collection.Simple
	RequestBodyErrorMsg() *collection.Simple
	RequestBodyProcessorError() *collection.Simple
	RequestBodyProcessorErrorMsg() *collection.Simple
	RequestBodyProcessor() *collection.Simple
	RequestBasename() *collection.Simple
	RequestBody() *collection.Simple
	RequestBodyLength() *collection.Simple
	RequestFilename() *collection.Simple
	RequestLine() *collection.Simple
	RequestMethod() *collection.Simple
	RequestProtocol() *collection.Simple
	RequestURI() *collection.Simple
	RequestURIRaw() *collection.Simple
	ResponseBody() *collection.Simple
	ResponseContentLength() *collection.Simple
	ResponseProtocol() *collection.Simple
	ResponseStatus() *collection.Simple
	ServerAddr() *collection.Simple
	ServerName() *collection.Simple
	ServerPort() *collection.Simple
	SessionID() *collection.Simple
	HighestSeverity() *collection.Simple
	StatusLine() *collection.Simple
	InboundErrorData() *collection.Simple
	// Custom
	Env() *collection.Map
	TX() *collection.Map
	Rule() *collection.Map
	Duration() *collection.Simple
	// Proxy Variables
	Args() *collection.Proxy
	// Maps Variables
	ArgsGet() *collection.Map
	ArgsPost() *collection.Map
	ArgsPath() *collection.Map
	FilesTmpNames() *collection.Map
	Geo() *collection.Map
	Files() *collection.Map
	RequestCookies() *collection.Map
	RequestHeaders() *collection.Map
	ResponseHeaders() *collection.Map
	MultipartName() *collection.Map
	MatchedVarsNames() *collection.Map
	MultipartFilename() *collection.Map
	MatchedVars() *collection.Map
	FilesSizes() *collection.Map
	FilesNames() *collection.Map
	FilesTmpContent() *collection.Map
	ResponseHeadersNames() *collection.Map
	RequestHeadersNames() *collection.Map
	RequestCookiesNames() *collection.Map
	XML() *collection.Map
	// Persistent variables
	IP() *collection.Map
	// Translation Proxy Variables
	ArgsNames() *collection.TranslationProxy
	ArgsGetNames() *collection.TranslationProxy
	ArgsPostNames() *collection.TranslationProxy
}
