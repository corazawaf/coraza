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
	// GetID returns the ID of the transaction.
	GetID() string // TODO(anuraaga): If only for logging, can be built into logger

	// GetVariables returns the TransactionVariables of the transaction.
	GetVariables() TransactionVariables

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
	GetUserid() *collection.Simple
	GetUrlencodedError() *collection.Simple
	GetResponseContentType() *collection.Simple
	GetUniqueID() *collection.Simple
	GetArgsCombinedSize() *collection.SizeProxy
	GetAuthType() *collection.Simple
	GetFilesCombinedSize() *collection.Simple
	GetFullRequest() *collection.Simple
	GetFullRequestLength() *collection.Simple
	GetInboundDataError() *collection.Simple
	GetMatchedVar() *collection.Simple
	GetMatchedVarName() *collection.Simple
	GetMultipartBoundaryQuoted() *collection.Simple
	GetMultipartBoundaryWhitespace() *collection.Simple
	GetMultipartCrlfLfLines() *collection.Simple
	GetMultipartDataAfter() *collection.Simple
	GetMultipartDataBefore() *collection.Simple
	GetMultipartFileLimitExceeded() *collection.Simple
	GetMultipartHeaderFolding() *collection.Simple
	GetMultipartInvalidHeaderFolding() *collection.Simple
	GetMultipartInvalidPart() *collection.Simple
	GetMultipartInvalidQuoting() *collection.Simple
	GetMultipartLfLine() *collection.Simple
	GetMultipartMissingSemicolon() *collection.Simple
	GetMultipartStrictError() *collection.Simple
	GetMultipartUnmatchedBoundary() *collection.Simple
	GetOutboundDataError() *collection.Simple
	GetPathInfo() *collection.Simple
	GetQueryString() *collection.Simple
	GetRemoteAddr() *collection.Simple
	GetRemoteHost() *collection.Simple
	GetRemotePort() *collection.Simple
	GetReqbodyError() *collection.Simple
	GetReqbodyErrorMsg() *collection.Simple
	GetReqbodyProcessorError() *collection.Simple
	GetReqbodyProcessorErrorMsg() *collection.Simple
	GetReqbodyProcessor() *collection.Simple
	GetRequestBasename() *collection.Simple
	GetRequestBody() *collection.Simple
	GetRequestBodyLength() *collection.Simple
	GetRequestFilename() *collection.Simple
	GetRequestLine() *collection.Simple
	GetRequestMethod() *collection.Simple
	GetRequestProtocol() *collection.Simple
	GetRequestURI() *collection.Simple
	GetRequestURIRaw() *collection.Simple
	GetResponseBody() *collection.Simple
	GetResponseContentLength() *collection.Simple
	GetResponseProtocol() *collection.Simple
	GetResponseStatus() *collection.Simple
	GetServerAddr() *collection.Simple
	GetServerName() *collection.Simple
	GetServerPort() *collection.Simple
	GetSessionid() *collection.Simple
	GetHighestSeverity() *collection.Simple
	GetStatusLine() *collection.Simple
	GetInboundErrorData() *collection.Simple
	// Custom
	GetEnv() *collection.Map
	GetTX() *collection.Map
	GetRule() *collection.Map
	GetDuration() *collection.Simple
	// Proxy Variables
	GetArgs() *collection.Proxy
	// Maps Variables
	GetArgsGet() *collection.Map
	GetArgsPost() *collection.Map
	GetArgsPath() *collection.Map
	GetFilesTmpNames() *collection.Map
	GetGeo() *collection.Map
	GetFiles() *collection.Map
	GetRequestCookies() *collection.Map
	GetRequestHeaders() *collection.Map
	GetResponseHeaders() *collection.Map
	GetMultipartName() *collection.Map
	GetMatchedVarsNames() *collection.Map
	GetMultipartFilename() *collection.Map
	GetMatchedVars() *collection.Map
	GetFilesSizes() *collection.Map
	GetFilesNames() *collection.Map
	GetFilesTmpContent() *collection.Map
	GetResponseHeadersNames() *collection.Map
	GetRequestHeadersNames() *collection.Map
	GetRequestCookiesNames() *collection.Map
	GetXML() *collection.Map
	GetRequestXML() *collection.Map
	GetResponseXML() *collection.Map
	// Persistent variables
	GetIP() *collection.Map
	// Translation Proxy Variables
	GetArgsNames() *collection.TranslationProxy
	GetArgsGetNames() *collection.TranslationProxy
	GetArgsPostNames() *collection.TranslationProxy
}
