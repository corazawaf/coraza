// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// TransactionVariables has pointers to all the variables of the transaction
type TransactionVariables struct {
	args                     *collections.ConcatKeyed
	argsCombinedSize         *collections.SizeCollection
	argsGet                  *collections.NamedCollection
	argsGetNames             collection.Keyed
	argsNames                *collections.ConcatKeyed
	argsPath                 *collections.NamedCollection
	argsPost                 *collections.NamedCollection
	argsPostNames            collection.Keyed
	duration                 *collections.Single
	env                      *collections.Map
	files                    *collections.Map
	filesCombinedSize        *collections.Single
	filesNames               *collections.Map
	filesSizes               *collections.Map
	filesTmpContent          *collections.Map
	filesTmpNames            *collections.Map
	fullRequestLength        *collections.Single
	geo                      *collections.Map
	highestSeverity          *collections.Single
	inboundDataError         *collections.Single
	matchedVar               *collections.Single
	matchedVarName           *collections.Single
	matchedVars              *collections.NamedCollection
	matchedVarsNames         collection.Keyed
	multipartDataAfter       *collections.Single
	multipartFilename        *collections.Map
	multipartName            *collections.Map
	multipartPartHeaders     *collections.Map
	multipartStrictError     *collections.Single
	outboundDataError        *collections.Single
	queryString              *collections.Single
	remoteAddr               *collections.Single
	remoteHost               *collections.Single
	remotePort               *collections.Single
	reqbodyError             *collections.Single
	reqbodyErrorMsg          *collections.Single
	reqbodyProcessor         *collections.Single
	reqbodyProcessorError    *collections.Single
	reqbodyProcessorErrorMsg *collections.Single
	requestBasename          *collections.Single
	requestBody              *collections.Single
	requestBodyLength        *collections.Single
	requestCookies           *collections.NamedCollection
	requestCookiesNames      collection.Keyed
	requestFilename          *collections.Single
	requestHeaders           *collections.NamedCollection
	requestHeadersNames      collection.Keyed
	requestLine              *collections.Single
	requestMethod            *collections.Single
	requestProtocol          *collections.Single
	requestURI               *collections.Single
	requestURIRaw            *collections.Single
	requestXML               *collections.Map
	responseBody             *collections.Single
	responseContentLength    *collections.Single
	responseContentType      *collections.Single
	responseHeaders          *collections.NamedCollection
	responseHeadersNames     collection.Keyed
	responseProtocol         *collections.Single
	responseStatus           *collections.Single
	responseXML              *collections.Map
	responseArgs             *collections.Map
	resBodyProcessor         *collections.Single
	rule                     *collections.Map
	serverAddr               *collections.Single
	serverName               *collections.Single
	serverPort               *collections.Single
	statusLine               *collections.Single
	tx                       *collections.Map
	uniqueID                 *collections.Single
	urlencodedError          *collections.Single
	xml                      *collections.Map
	resBodyError             *collections.Single
	resBodyErrorMsg          *collections.Single
	resBodyProcessorError    *collections.Single
	resBodyProcessorErrorMsg *collections.Single
	time                     *collections.Single
	timeDay                  *collections.Single
	timeEpoch                *collections.Single
	timeHour                 *collections.Single
	timeMin                  *collections.Single
	timeMon                  *collections.Single
	timeSec                  *collections.Single
	timeWday                 *collections.Single
	timeYear                 *collections.Single
}

func NewTransactionVariables() *TransactionVariables {
	v := &TransactionVariables{}
	v.urlencodedError = collections.NewSingle(variables.UrlencodedError)
	v.responseContentType = collections.NewSingle(variables.ResponseContentType)
	v.uniqueID = collections.NewSingle(variables.UniqueID)
	v.filesCombinedSize = collections.NewSingle(variables.FilesCombinedSize)
	v.fullRequestLength = collections.NewSingle(variables.FullRequestLength)
	v.inboundDataError = collections.NewSingle(variables.InboundDataError)
	v.matchedVar = collections.NewSingle(variables.MatchedVar)
	v.matchedVarName = collections.NewSingle(variables.MatchedVarName)
	v.multipartDataAfter = collections.NewSingle(variables.MultipartDataAfter)
	v.outboundDataError = collections.NewSingle(variables.OutboundDataError)
	v.queryString = collections.NewSingle(variables.QueryString)
	v.remoteAddr = collections.NewSingle(variables.RemoteAddr)
	v.remoteHost = collections.NewSingle(variables.RemoteHost)
	v.remotePort = collections.NewSingle(variables.RemotePort)
	v.reqbodyError = collections.NewSingle(variables.ReqbodyError)
	v.reqbodyErrorMsg = collections.NewSingle(variables.ReqbodyErrorMsg)
	v.reqbodyProcessorError = collections.NewSingle(variables.ReqbodyProcessorError)
	v.reqbodyProcessorErrorMsg = collections.NewSingle(variables.ReqbodyProcessorErrorMsg)
	v.reqbodyProcessor = collections.NewSingle(variables.ReqbodyProcessor)
	v.requestBasename = collections.NewSingle(variables.RequestBasename)
	v.requestBody = collections.NewSingle(variables.RequestBody)
	v.requestBodyLength = collections.NewSingle(variables.RequestBodyLength)
	v.requestFilename = collections.NewSingle(variables.RequestFilename)
	v.requestLine = collections.NewSingle(variables.RequestLine)
	v.requestMethod = collections.NewSingle(variables.RequestMethod)
	v.requestProtocol = collections.NewSingle(variables.RequestProtocol)
	v.requestURI = collections.NewSingle(variables.RequestURI)
	v.requestURIRaw = collections.NewSingle(variables.RequestURIRaw)
	v.responseBody = collections.NewSingle(variables.ResponseBody)
	v.responseContentLength = collections.NewSingle(variables.ResponseContentLength)
	v.responseProtocol = collections.NewSingle(variables.ResponseProtocol)
	v.responseStatus = collections.NewSingle(variables.ResponseStatus)
	v.responseArgs = collections.NewMap(variables.ResponseArgs)
	v.serverAddr = collections.NewSingle(variables.ServerAddr)
	v.serverName = collections.NewSingle(variables.ServerName)
	v.serverPort = collections.NewSingle(variables.ServerPort)
	v.highestSeverity = collections.NewSingle(variables.HighestSeverity)
	v.statusLine = collections.NewSingle(variables.StatusLine)
	v.duration = collections.NewSingle(variables.Duration)
	v.resBodyError = collections.NewSingle(variables.ResBodyError)
	v.resBodyErrorMsg = collections.NewSingle(variables.ResBodyErrorMsg)
	v.resBodyProcessorError = collections.NewSingle(variables.ResBodyProcessorError)
	v.resBodyProcessorErrorMsg = collections.NewSingle(variables.ResBodyProcessorErrorMsg)

	v.filesSizes = collections.NewMap(variables.FilesSizes)
	v.filesTmpContent = collections.NewMap(variables.FilesTmpContent)
	v.multipartFilename = collections.NewMap(variables.MultipartFilename)
	v.multipartName = collections.NewMap(variables.MultipartName)
	v.matchedVars = collections.NewNamedCollection(variables.MatchedVars)
	v.matchedVarsNames = v.matchedVars.Names(variables.MatchedVarsNames)
	v.requestCookies = collections.NewNamedCollection(variables.RequestCookies)
	v.requestCookiesNames = v.requestCookies.Names(variables.RequestCookiesNames)
	v.requestHeaders = collections.NewNamedCollection(variables.RequestHeaders)
	v.requestHeadersNames = v.requestHeaders.Names(variables.RequestHeadersNames)
	v.responseHeaders = collections.NewNamedCollection(variables.ResponseHeaders)
	v.responseHeadersNames = v.responseHeaders.Names(variables.ResponseHeadersNames)
	v.resBodyProcessor = collections.NewSingle(variables.ResBodyProcessor)
	v.geo = collections.NewMap(variables.Geo)
	v.tx = collections.NewMap(variables.TX)
	v.rule = collections.NewMap(variables.Rule)
	v.env = collections.NewMap(variables.Env)
	v.files = collections.NewMap(variables.Files)
	v.filesNames = collections.NewMap(variables.FilesNames)
	v.filesTmpNames = collections.NewMap(variables.FilesTmpNames)
	v.responseXML = collections.NewMap(variables.ResponseXML)
	v.requestXML = collections.NewMap(variables.RequestXML)
	v.multipartPartHeaders = collections.NewMap(variables.MultipartPartHeaders)
	v.multipartStrictError = collections.NewSingle(variables.MultipartStrictError)
	v.time = collections.NewSingle(variables.Time)
	v.timeDay = collections.NewSingle(variables.TimeDay)
	v.timeEpoch = collections.NewSingle(variables.TimeEpoch)
	v.timeHour = collections.NewSingle(variables.TimeHour)
	v.timeMin = collections.NewSingle(variables.TimeMin)
	v.timeMon = collections.NewSingle(variables.TimeMon)
	v.timeSec = collections.NewSingle(variables.TimeSec)
	v.timeWday = collections.NewSingle(variables.TimeWday)
	v.timeYear = collections.NewSingle(variables.TimeYear)

	// XML is a pointer to RequestXML
	v.xml = v.requestXML

	if shouldUseCaseSensitiveNamedCollection {
		v.argsGet = collections.NewCaseSensitiveNamedCollection(variables.ArgsGet)
		v.argsPost = collections.NewCaseSensitiveNamedCollection(variables.ArgsPost)
		v.argsPath = collections.NewCaseSensitiveNamedCollection(variables.ArgsPath)
	} else {
		v.argsGet = collections.NewNamedCollection(variables.ArgsGet)
		v.argsPost = collections.NewNamedCollection(variables.ArgsPost)
		v.argsPath = collections.NewNamedCollection(variables.ArgsPath)
	}

	v.argsGetNames = v.argsGet.Names(variables.ArgsGetNames)
	v.argsPostNames = v.argsPost.Names(variables.ArgsPostNames)
	v.argsCombinedSize = collections.NewSizeCollection(variables.ArgsCombinedSize, v.argsGet, v.argsPost)
	v.args = collections.NewConcatKeyed(
		variables.Args,
		v.argsGet,
		v.argsPost,
		v.argsPath,
	)
	v.argsNames = collections.NewConcatKeyed(
		variables.ArgsNames,
		v.argsGetNames,
		v.argsPostNames,
		// Only used in a concatenating collection so variable name doesn't matter.
		v.argsPath.Names(variables.Unknown),
	)
	return v
}

func (v *TransactionVariables) UrlencodedError() collection.Single {
	return v.urlencodedError
}

func (v *TransactionVariables) ResponseContentType() collection.Single {
	return v.responseContentType
}

func (v *TransactionVariables) UniqueID() collection.Single {
	return v.uniqueID
}

func (v *TransactionVariables) ArgsCombinedSize() collection.Collection {
	return v.argsCombinedSize
}

func (v *TransactionVariables) FilesCombinedSize() collection.Single {
	return v.filesCombinedSize
}

func (v *TransactionVariables) FullRequestLength() collection.Single {
	return v.fullRequestLength
}

func (v *TransactionVariables) InboundDataError() collection.Single {
	return v.inboundDataError
}

func (v *TransactionVariables) MatchedVar() collection.Single {
	return v.matchedVar
}

func (v *TransactionVariables) MatchedVarName() collection.Single {
	return v.matchedVarName
}

func (v *TransactionVariables) MultipartDataAfter() collection.Single {
	return v.multipartDataAfter
}

func (v *TransactionVariables) MultipartPartHeaders() collection.Map {
	return v.multipartPartHeaders
}

func (v *TransactionVariables) OutboundDataError() collection.Single {
	return v.outboundDataError
}

func (v *TransactionVariables) QueryString() collection.Single {
	return v.queryString
}

func (v *TransactionVariables) RemoteAddr() collection.Single {
	return v.remoteAddr
}

func (v *TransactionVariables) RemoteHost() collection.Single {
	return v.remoteHost
}

func (v *TransactionVariables) RemotePort() collection.Single {
	return v.remotePort
}

func (v *TransactionVariables) RequestBodyError() collection.Single {
	return v.reqbodyError
}

func (v *TransactionVariables) RequestBodyErrorMsg() collection.Single {
	return v.reqbodyErrorMsg
}

func (v *TransactionVariables) RequestBodyProcessorError() collection.Single {
	return v.reqbodyProcessorError
}

func (v *TransactionVariables) RequestBodyProcessorErrorMsg() collection.Single {
	return v.reqbodyProcessorErrorMsg
}

func (v *TransactionVariables) RequestBodyProcessor() collection.Single {
	return v.reqbodyProcessor
}

func (v *TransactionVariables) RequestBasename() collection.Single {
	return v.requestBasename
}

func (v *TransactionVariables) RequestBody() collection.Single {
	return v.requestBody
}

func (v *TransactionVariables) RequestBodyLength() collection.Single {
	return v.requestBodyLength
}

func (v *TransactionVariables) RequestFilename() collection.Single {
	return v.requestFilename
}

func (v *TransactionVariables) RequestLine() collection.Single {
	return v.requestLine
}

func (v *TransactionVariables) RequestMethod() collection.Single {
	return v.requestMethod
}

func (v *TransactionVariables) RequestProtocol() collection.Single {
	return v.requestProtocol
}

func (v *TransactionVariables) RequestURI() collection.Single {
	return v.requestURI
}

func (v *TransactionVariables) RequestURIRaw() collection.Single {
	return v.requestURIRaw
}

func (v *TransactionVariables) ResponseBody() collection.Single {
	return v.responseBody
}

func (v *TransactionVariables) ResponseContentLength() collection.Single {
	return v.responseContentLength
}

func (v *TransactionVariables) ResponseProtocol() collection.Single {
	return v.responseProtocol
}

func (v *TransactionVariables) ResponseStatus() collection.Single {
	return v.responseStatus
}

func (v *TransactionVariables) ServerAddr() collection.Single {
	return v.serverAddr
}

func (v *TransactionVariables) ServerName() collection.Single {
	return v.serverName
}

func (v *TransactionVariables) ServerPort() collection.Single {
	return v.serverPort
}

func (v *TransactionVariables) HighestSeverity() collection.Single {
	return v.highestSeverity
}

func (v *TransactionVariables) StatusLine() collection.Single {
	return v.statusLine
}

func (v *TransactionVariables) Env() collection.Map {
	return v.env
}

func (v *TransactionVariables) TX() collection.Map {
	return v.tx
}

func (v *TransactionVariables) Rule() collection.Map {
	return v.rule
}

func (v *TransactionVariables) Duration() collection.Single {
	return v.duration
}

func (v *TransactionVariables) Args() collection.Keyed {
	return v.args
}

func (v *TransactionVariables) ArgsGet() collection.Map {
	return v.argsGet
}

func (v *TransactionVariables) ArgsPost() collection.Map {
	return v.argsPost
}

func (v *TransactionVariables) ArgsPath() collection.Map {
	return v.argsPath
}

func (v *TransactionVariables) FilesTmpNames() collection.Map {
	return v.filesTmpNames
}

func (v *TransactionVariables) Geo() collection.Map {
	return v.geo
}

func (v *TransactionVariables) Files() collection.Map {
	return v.files
}

func (v *TransactionVariables) RequestCookies() collection.Map {
	return v.requestCookies
}

func (v *TransactionVariables) RequestHeaders() collection.Map {
	return v.requestHeaders
}

func (v *TransactionVariables) ResponseHeaders() collection.Map {
	return v.responseHeaders
}

func (v *TransactionVariables) MultipartName() collection.Map {
	return v.multipartName
}

func (v *TransactionVariables) MatchedVarsNames() collection.Keyed {
	return v.matchedVarsNames
}

func (v *TransactionVariables) MultipartFilename() collection.Map {
	return v.multipartFilename
}

func (v *TransactionVariables) MatchedVars() collection.Map {
	return v.matchedVars
}

func (v *TransactionVariables) FilesSizes() collection.Map {
	return v.filesSizes
}

func (v *TransactionVariables) FilesNames() collection.Map {
	return v.filesNames
}

func (v *TransactionVariables) FilesTmpContent() collection.Map {
	return v.filesTmpContent
}

func (v *TransactionVariables) ResponseHeadersNames() collection.Keyed {
	return v.responseHeadersNames
}

func (v *TransactionVariables) ResponseArgs() collection.Map {
	return v.responseArgs
}

func (v *TransactionVariables) RequestHeadersNames() collection.Keyed {
	return v.requestHeadersNames
}

func (v *TransactionVariables) RequestCookiesNames() collection.Keyed {
	return v.requestCookiesNames
}

func (v *TransactionVariables) XML() collection.Map {
	return v.xml
}

func (v *TransactionVariables) RequestXML() collection.Map {
	return v.requestXML
}

func (v *TransactionVariables) ResponseXML() collection.Map {
	return v.responseXML
}

func (v *TransactionVariables) ResponseBodyProcessor() collection.Single {
	return v.resBodyProcessor
}

func (v *TransactionVariables) ArgsNames() collection.Keyed {
	return v.argsNames
}

func (v *TransactionVariables) ArgsGetNames() collection.Keyed {
	return v.argsGetNames
}

func (v *TransactionVariables) ArgsPostNames() collection.Keyed {
	return v.argsPostNames
}

func (v *TransactionVariables) ResBodyError() collection.Single {
	return v.resBodyError
}

func (v *TransactionVariables) ResBodyErrorMsg() collection.Single {
	return v.resBodyErrorMsg
}

func (v *TransactionVariables) ResBodyProcessorError() collection.Single {
	return v.resBodyProcessorError
}

func (v *TransactionVariables) ResBodyProcessorErrorMsg() collection.Single {
	return v.resBodyProcessorErrorMsg
}

func (v *TransactionVariables) MultipartStrictError() collection.Single {
	return v.multipartStrictError
}

// All iterates over the variables. We return both variable and its collection, i.e. key/value, to follow
// general range iteration in Go which always has a key and value (key is int index for slices). Notably,
// this is consistent with discussions for custom iterable types in a future language version
// https://github.com/golang/go/discussions/56413
func (v *TransactionVariables) All(f func(v variables.RuleVariable, col collection.Collection) bool) {
	if !f(variables.Args, v.args) {
		return
	}
	if !f(variables.ArgsCombinedSize, v.argsCombinedSize) {
		return
	}
	if !f(variables.ArgsGet, v.argsGet) {
		return
	}
	if !f(variables.ArgsGetNames, v.argsGetNames) {
		return
	}
	if !f(variables.ArgsNames, v.argsNames) {
		return
	}
	if !f(variables.ArgsPath, v.argsPath) {
		return
	}
	if !f(variables.ArgsPost, v.argsPost) {
		return
	}
	if !f(variables.ArgsPostNames, v.argsPostNames) {
		return
	}
	if !f(variables.Duration, v.duration) {
		return
	}
	if !f(variables.Env, v.env) {
		return
	}
	if !f(variables.Files, v.files) {
		return
	}
	if !f(variables.FilesCombinedSize, v.filesCombinedSize) {
		return
	}
	if !f(variables.FilesNames, v.filesNames) {
		return
	}
	if !f(variables.FilesSizes, v.filesSizes) {
		return
	}
	if !f(variables.FilesTmpContent, v.filesTmpContent) {
		return
	}
	if !f(variables.FilesTmpNames, v.filesTmpNames) {
		return
	}
	if !f(variables.FullRequestLength, v.fullRequestLength) {
		return
	}
	if !f(variables.Geo, v.geo) {
		return
	}
	if !f(variables.HighestSeverity, v.highestSeverity) {
		return
	}
	if !f(variables.InboundDataError, v.inboundDataError) {
		return
	}
	if !f(variables.MatchedVar, v.matchedVar) {
		return
	}
	if !f(variables.MatchedVarName, v.matchedVarName) {
		return
	}
	if !f(variables.MatchedVars, v.matchedVars) {
		return
	}
	if !f(variables.MatchedVarsNames, v.matchedVarsNames) {
		return
	}
	if !f(variables.MultipartDataAfter, v.multipartDataAfter) {
		return
	}
	if !f(variables.MultipartFilename, v.multipartFilename) {
		return
	}
	if !f(variables.MultipartName, v.multipartName) {
		return
	}
	if !f(variables.MultipartPartHeaders, v.multipartPartHeaders) {
		return
	}
	if !f(variables.MultipartStrictError, v.multipartStrictError) {
		return
	}
	if !f(variables.OutboundDataError, v.outboundDataError) {
		return
	}
	if !f(variables.QueryString, v.queryString) {
		return
	}
	if !f(variables.RemoteAddr, v.remoteAddr) {
		return
	}
	if !f(variables.RemoteHost, v.remoteHost) {
		return
	}
	if !f(variables.RemotePort, v.remotePort) {
		return
	}
	if !f(variables.ReqbodyError, v.reqbodyError) {
		return
	}
	if !f(variables.ReqbodyErrorMsg, v.reqbodyErrorMsg) {
		return
	}
	if !f(variables.ReqbodyProcessor, v.reqbodyProcessor) {
		return
	}
	if !f(variables.ReqbodyProcessorError, v.reqbodyProcessorError) {
		return
	}
	if !f(variables.ReqbodyProcessorErrorMsg, v.reqbodyProcessorErrorMsg) {
		return
	}
	if !f(variables.RequestBasename, v.requestBasename) {
		return
	}
	if !f(variables.RequestBody, v.requestBody) {
		return
	}
	if !f(variables.RequestBodyLength, v.requestBodyLength) {
		return
	}
	if !f(variables.RequestCookies, v.requestCookies) {
		return
	}
	if !f(variables.RequestCookiesNames, v.requestCookiesNames) {
		return
	}
	if !f(variables.RequestFilename, v.requestFilename) {
		return
	}
	if !f(variables.RequestHeaders, v.requestHeaders) {
		return
	}
	if !f(variables.RequestHeadersNames, v.requestHeadersNames) {
		return
	}
	if !f(variables.RequestLine, v.requestLine) {
		return
	}
	if !f(variables.RequestMethod, v.requestMethod) {
		return
	}
	if !f(variables.RequestProtocol, v.requestProtocol) {
		return
	}
	if !f(variables.RequestURI, v.requestURI) {
		return
	}
	if !f(variables.RequestURIRaw, v.requestURIRaw) {
		return
	}
	if !f(variables.RequestXML, v.requestXML) {
		return
	}
	if !f(variables.ResponseBody, v.responseBody) {
		return
	}
	if !f(variables.ResponseContentLength, v.responseContentLength) {
		return
	}
	if !f(variables.ResponseContentType, v.responseContentType) {
		return
	}
	if !f(variables.ResponseHeaders, v.responseHeaders) {
		return
	}
	if !f(variables.ResponseHeadersNames, v.responseHeadersNames) {
		return
	}
	if !f(variables.ResponseProtocol, v.responseProtocol) {
		return
	}
	if !f(variables.ResponseStatus, v.responseStatus) {
		return
	}
	if !f(variables.ResponseXML, v.responseXML) {
		return
	}
	if !f(variables.ResponseArgs, v.responseArgs) {
		return
	}
	if !f(variables.ResBodyProcessor, v.resBodyProcessor) {
		return
	}
	if !f(variables.Rule, v.rule) {
		return
	}
	if !f(variables.ServerAddr, v.serverAddr) {
		return
	}
	if !f(variables.ServerName, v.serverName) {
		return
	}
	if !f(variables.ServerPort, v.serverPort) {
		return
	}
	if !f(variables.StatusLine, v.statusLine) {
		return
	}
	if !f(variables.TX, v.tx) {
		return
	}
	if !f(variables.UniqueID, v.uniqueID) {
		return
	}
	if !f(variables.UrlencodedError, v.urlencodedError) {
		return
	}
	if !f(variables.XML, v.xml) {
		return
	}
	if !f(variables.Time, v.time) {
		return
	}
	if !f(variables.TimeDay, v.timeDay) {
		return
	}
	if !f(variables.TimeEpoch, v.timeEpoch) {
		return
	}
	if !f(variables.TimeHour, v.timeHour) {
		return
	}
	if !f(variables.TimeMin, v.timeMin) {
		return
	}
	if !f(variables.TimeMon, v.timeMon) {
		return
	}
	if !f(variables.TimeSec, v.timeSec) {
		return
	}
	if !f(variables.TimeWday, v.timeWday) {
		return
	}
	if !f(variables.TimeYear, v.timeYear) {
		return
	}
}

type formattable interface {
	Format(res *strings.Builder)
}

func (v *TransactionVariables) format(res *strings.Builder) {
	v.All(func(_ variables.RuleVariable, col collection.Collection) bool {
		if f, ok := col.(formattable); ok {
			f.Format(res)
		} else {
			fmt.Fprintln(res, col)
		}
		return true
	})
}

type resettable interface {
	Reset()
}

func (v *TransactionVariables) reset() {
	v.All(func(_ variables.RuleVariable, col collection.Collection) bool {
		if r, ok := col.(resettable); ok {
			r.Reset()
		}
		return true
	})
}
