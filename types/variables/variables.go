// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package variables contains the representation of the variables used in the rules
// Variables are created as bytes and they have a string representation
package variables

import (
	"github.com/corazawaf/coraza/v3/internal/variables"
)

// This file repeats the same content many times in order to make access
// efficient for seclang and transactions

// RuleVariable is used to identify information from a transaction
type RuleVariable = variables.RuleVariable

const (
	// Unknown is used as placeholder for errors
	Unknown = variables.Unknown
	// ResponseContentType is the content type of the response
	ResponseContentType = variables.ResponseContentType
	// UniqueID is the unique id of the transaction
	UniqueID = variables.UniqueID
	// ArgsCombinedSize is the combined size of the arguments
	ArgsCombinedSize = variables.ArgsCombinedSize
	// FilesCombinedSize is the combined size of the uploaded files
	FilesCombinedSize = variables.FilesCombinedSize
	// FullRequestLength is the length of the full request
	FullRequestLength = variables.FullRequestLength
	// InboundDataError represents errors for inbound data
	InboundDataError = variables.InboundDataError
	// MatchedVar is the value of the matched variable
	MatchedVar = variables.MatchedVar
	// MatchedVarName is the name of the matched variable
	MatchedVarName = variables.MatchedVarName
	// MultipartDataAfter kept for compatibility
	MultipartDataAfter = variables.MultipartDataAfter
	// OutboundDataError will be set to 1 when the response body size
	// is above the setting configured by SecResponseBodyLimit
	OutboundDataError = variables.OutboundDataError
	// QueryString contains the raw query string part of a request URI
	QueryString = variables.QueryString
	// RemoteAddr is the remote address of the connection
	RemoteAddr = variables.RemoteAddr
	// RemoteHost is the remote host of the connection, not implemented
	RemoteHost = variables.RemoteHost
	// RemotePort is the remote port of the connection
	RemotePort = variables.RemotePort
	// ReqbodyError contains the status of the request body processor used
	// for request body parsing, 0 means no error, 1 means error
	ReqbodyError = variables.ReqbodyError
	// ReqbodyErrorMsg contains the error message of the request body processor error
	ReqbodyErrorMsg = variables.ReqbodyErrorMsg
	// ReqbodyProcessorError is the same as ReqbodyErrr ?
	ReqbodyProcessorError = variables.ReqbodyProcessorError
	// ReqbodyProcessorErrorMsg is the same as ReqbodyErrorMsg ?
	ReqbodyProcessorErrorMsg = variables.ReqbodyProcessorErrorMsg
	// ReqbodyProcessor contains the name of the request body processor used, default
	// ones are: URLENCODED, MULTIPART, and XML. They can be extended using plugins.
	ReqbodyProcessor = variables.ReqbodyProcessor
	// RequestBasename contains the name after the last slash in the request URI
	// It does not pass through any anti-evasion, use with transformations
	RequestBasename = variables.RequestBasename
	// RequestBody contains the full request body, it will only be available
	// For urlencoded requests. It is possible to force it's presence by using
	// the ctl:forceRequestBodyVariable action
	RequestBody = variables.RequestBody
	// RequestBodyLength contains the length of the request body in bytes calculated from
	// the BodyBuffer, not from the content-type header
	RequestBodyLength = variables.RequestBodyLength
	// RequestFilename holds the relative request URL without the query string part.
	// Anti-evasion transformations are not used by default
	RequestFilename = variables.RequestFilename
	// RequestLine This variable holds the complete request line sent to the server
	// (including the request method and HTTP version information).
	RequestLine = variables.RequestLine
	// RequestMethod is the request method
	RequestMethod = variables.RequestMethod
	// RequestProtocol is the protocol used in the request
	RequestProtocol = variables.RequestProtocol
	// RequestURI holds the full request URL including the query string data without
	// the domain name
	RequestURI = variables.RequestURI
	// RequestURIRaw is the same as RequestURI but with the domain name in case
	// it was provided in the request line
	RequestURIRaw = variables.RequestURIRaw
	// ResponseBody contains the full response body, it will only be available if
	// responseBodyAccess is set to on and the response mime matches the configured
	// processable mime types
	ResponseBody = variables.ResponseBody
	// ResponseContentLength contains the length of the response body in bytes calculated from
	// the BodyBuffer, not from the content-type header
	ResponseContentLength = variables.ResponseContentLength
	// ResponseProtocol is the protocol used in the response
	ResponseProtocol = variables.ResponseProtocol
	// ResponseStatus is the status code of the response
	ResponseStatus = variables.ResponseStatus
	// ResBodyProcessor contains the name of the response body processor used, no default
	ResBodyProcessor = variables.ResBodyProcessor
	// ServerAddr is the address of the server
	ServerAddr = variables.ServerAddr
	// ServerName is the name of the server
	ServerName = variables.ServerName
	// ServerPort is the port of the server
	ServerPort = variables.ServerPort
	// HighestSeverity is the highest severity from all matched rules
	HighestSeverity = variables.HighestSeverity
	// StatusLine is the status line of the response, including the request method
	// and HTTP version information
	StatusLine = variables.StatusLine
	// InboundErrorData will be set to 1 when the request body size
	// is above the setting configured by SecRequesteBodyLimit
	InboundErrorData = variables.InboundErrorData
	// Duration contains the time in miliseconds from
	// the beginning of the transaction until this point
	Duration = variables.Duration
	// ResponseHeadersNames contains the names of the response headers
	ResponseHeadersNames = variables.ResponseHeadersNames
	// RequestHeadersNames contains the names of the request headers
	RequestHeadersNames = variables.RequestHeadersNames
	// Args contains copies of ArgsGet and ArgsPost
	Args = variables.Args
	// ArgsGet contains the GET (URL) arguments
	ArgsGet = variables.ArgsGet
	// ArgsPost contains the POST (BODY) arguments
	ArgsPost = variables.ArgsPost
	// ArgsPath contains the url path parts
	ArgsPath = variables.ArgsPath
	// FilesSizes contains the sizes of the uploaded files
	FilesSizes = variables.FilesSizes
	// FilesNames contains the names of the uploaded files
	FilesNames = variables.FilesNames
	// FilesTmpContent is not supported
	FilesTmpContent = variables.FilesTmpContent
	// MultipartFilename contains the multipart data from field FILENAME
	MultipartFilename = variables.MultipartFilename
	// MultipartName contains the multipart data from field NAME.
	MultipartName = variables.MultipartName
	// MatchedVarsNames is similar to MATCHED_VAR_NAME except that it is
	// a collection of all matches for the current operator check.
	MatchedVarsNames = variables.MatchedVarsNames
	// MatchedVars is similar to MATCHED_VAR except that it is a collection
	// of all matches for the current operator check
	MatchedVars = variables.MatchedVars
	// Files contains a collection of original file names
	// (as they were called on the remote user’s filesys- tem).
	// Available only on inspected multipart/form-data requests.
	Files = variables.Files
	// RequestCookies is a collection of all of request cookies (values only
	RequestCookies = variables.RequestCookies
	// RequestHeaders can be used as either a collection of all of the request
	// headers or can be used to inspect selected headers
	RequestHeaders = variables.RequestHeaders
	// ResponseHeaders can be used as either a collection of all of the response
	// headers or can be used to inspect selected headers
	ResponseHeaders = variables.ResponseHeaders
	// Geo contains the location information of the client
	Geo = variables.Geo
	// RequestCookiesNames contains the names of the request cookies
	RequestCookiesNames = variables.RequestCookiesNames
	// FilesTmpNames contains the names of the uploaded temporal files
	FilesTmpNames = variables.FilesTmpNames
	// ArgsNames contains the names of the arguments (POST and GET)
	ArgsNames = variables.ArgsNames
	// ArgsGetNames contains the names of the GET arguments
	ArgsGetNames = variables.ArgsGetNames
	// ArgsPostNames contains the names of the POST arguments
	ArgsPostNames = variables.ArgsPostNames
	// TX contains transaction specific variables created with setvar
	TX = variables.TX
	// Rule contains rule metadata
	Rule = variables.Rule
	// JSON does not provide any data, might be removed
	JSON = variables.JSON
	// Env contains the process environment variables
	Env = variables.Env
	// UrlencodedError equals 1 if we failed to parse de URL
	// It applies for URL query part and urlencoded post body
	UrlencodedError = variables.UrlencodedError
	// ResponseArgs contains the response parsed arguments
	ResponseArgs = variables.ResponseArgs
	// ResponseXML contains the response parsed XML
	ResponseXML = variables.ResponseXML
	// RequestXML contains the request parsed XML
	RequestXML = variables.RequestXML
	// XML is a pointer to ResponseXML
	XML = variables.XML
	// MultipartPartHeaders contains the multipart headers
	MultipartPartHeaders = variables.MultipartPartHeaders
)

// Parse returns the byte interpretation
// of a variable from a string
// Returns error if there is no representation
func Parse(v string) (RuleVariable, error) {
	return variables.Parse(v)
}
