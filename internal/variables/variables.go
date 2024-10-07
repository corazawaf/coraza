// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run generator/main.go

// Package variables contains the representation of the variables used in the rules
// Variables are created as bytes and they have a string representation
package variables

// This internal file contains all variables supported by handling of SecLang, such as
// the parser and actions like setvar. Several of these variables are no-op and not
// supported by Coraza - the public variables package only exposes the set of supported
// variables for programmatic access.

// RuleVariable is used to identify information from a transaction
type RuleVariable byte

const (
	// Unknown is used as placeholder for errors
	Unknown RuleVariable = iota
	// ResponseContentType is the content type of the response
	ResponseContentType
	// UniqueID is the unique id of the transaction
	UniqueID
	// ArgsCombinedSize is the combined size of the arguments
	ArgsCombinedSize
	// FilesCombinedSize is the combined size of the uploaded files
	FilesCombinedSize
	// FullRequestLength is the length of the full request
	FullRequestLength
	// InboundDataError will be set to 1 when the request body size
	// is above the setting configured by SecRequesteBodyLimit
	InboundDataError
	// MatchedVar is the value of the matched variable
	MatchedVar
	// MatchedVarName is the name of the matched variable
	MatchedVarName
	// MultipartDataAfter kept for compatibility
	MultipartDataAfter
	// OutboundDataError will be set to 1 when the response body size
	// is above the setting configured by SecResponseBodyLimit
	OutboundDataError
	// QueryString contains the raw query string part of a request URI
	QueryString
	// RemoteAddr is the remote address of the connection
	RemoteAddr
	// RemoteHost is the remote host of the connection, not implemented
	RemoteHost
	// RemotePort is the remote port of the connection
	RemotePort
	// ReqbodyError contains the status of the request body processor used
	// for request body parsing, 0 means no error, 1 means error
	ReqbodyError
	// ReqbodyErrorMsg contains the error message of the request body processor error
	ReqbodyErrorMsg
	// ReqbodyProcessorError is the same as ReqbodyErrr ?
	ReqbodyProcessorError
	// ReqbodyProcessorErrorMsg is the same as ReqbodyErrorMsg ?
	ReqbodyProcessorErrorMsg
	// ReqbodyProcessor contains the name of the request body processor used, default
	// ones are: URLENCODED, MULTIPART, and XML. They can be extended using plugins.
	ReqbodyProcessor
	// RequestBasename contains the name after the last slash in the request URI
	// It does not pass through any anti-evasion, use with transformations
	RequestBasename
	// RequestBody contains the full request body, it will only be available
	// For urlencoded requests. It is possible to force it's presence by using
	// the ctl:forceRequestBodyVariable action
	RequestBody
	// RequestBodyLength contains the length of the request body in bytes calculated from
	// the BodyBuffer, not from the content-type header
	RequestBodyLength
	// RequestFilename holds the relative request URL without the query string part.
	// Anti-evasion transformations are not used by default
	RequestFilename
	// RequestLine This variable holds the complete request line sent to the server
	// (including the request method and HTTP version information).
	RequestLine
	// RequestMethod is the request method
	RequestMethod
	// RequestProtocol is the protocol used in the request
	RequestProtocol
	// RequestURI holds the full request URL including the query string data without
	// the domain name
	RequestURI
	// RequestURIRaw is the same as RequestURI but with the domain name in case
	// it was provided in the request line
	RequestURIRaw
	// ResponseBody contains the full response body, it will only be available if
	// responseBodyAccess is set to on and the response mime matches the configured
	// processable mime types
	ResponseBody
	// ResponseContentLength contains the length of the response body in bytes calculated from
	// the BodyBuffer, not from the content-type header
	ResponseContentLength
	// ResponseProtocol is the protocol used in the response
	ResponseProtocol
	// ResponseStatus is the status code of the response
	ResponseStatus
	// ServerAddr is the address of the server
	ServerAddr
	// ServerName is the name of the server
	ServerName
	// ServerPort is the port of the server
	ServerPort
	// HighestSeverity is the highest severity from all matched rules
	HighestSeverity
	// StatusLine is the status line of the response, including the request method
	// and HTTP version information
	StatusLine
	// Duration contains the time in miliseconds from
	// the beginning of the transaction until this point
	Duration
	// ResponseHeadersNames contains the names of the response headers
	ResponseHeadersNames // CanBeSelected
	// RequestHeadersNames contains the names of the request headers
	RequestHeadersNames // CanBeSelected
	// Args contains copies of ArgsGet and ArgsPost
	Args // CanBeSelected
	// ArgsGet contains the GET (URL) arguments
	ArgsGet // CanBeSelected
	// ArgsPost contains the POST (BODY) arguments
	ArgsPost // CanBeSelected
	// ArgsPath contains the url path parts
	ArgsPath
	// FilesSizes contains the sizes of the uploaded files
	FilesSizes
	// FilesNames contains the names of the uploaded files
	FilesNames // CanBeSelected
	// FilesTmpContent is not supported
	FilesTmpContent
	// MultipartFilename contains the multipart data from field FILENAME
	MultipartFilename
	// MultipartName contains the multipart data from field NAME.
	MultipartName
	// MatchedVarsNames is similar to MATCHED_VAR_NAME except that it is
	// a collection of all matches for the current operator check.
	MatchedVarsNames // CanBeSelected
	// MatchedVars is similar to MATCHED_VAR except that it is a collection
	// of all matches for the current operator check
	MatchedVars // CanBeSelected
	// Files contains a collection of original file names
	// (as they were called on the remote user’s filesys- tem).
	// Available only on inspected multipart/form-data requests.
	Files
	// RequestCookies is a collection of all of request cookies (values only
	RequestCookies // CanBeSelected
	// RequestHeaders can be used as either a collection of all of the request
	// headers or can be used to inspect selected headers
	RequestHeaders // CanBeSelected
	// ResponseHeaders can be used as either a collection of all of the response
	// headers or can be used to inspect selected headers
	ResponseHeaders // CanBeSelected
	// ReseBodyProcessor contains the name of the response body processor used,
	// no default
	ResBodyProcessor
	// Geo contains the location information of the client
	Geo
	// RequestCookiesNames contains the names of the request cookies
	RequestCookiesNames // CanBeSelected
	// FilesTmpNames contains the names of the uploaded temporal files
	FilesTmpNames // CanBeSelected
	// ArgsNames contains the names of the arguments (POST and GET)
	ArgsNames // CanBeSelected
	// ArgsGetNames contains the names of the GET arguments
	ArgsGetNames // CanBeSelected
	// ArgsPostNames contains the names of the POST arguments
	ArgsPostNames // CanBeSelected
	// TX contains transaction specific variables created with setvar
	TX // CanBeSelected
	// Rule contains rule metadata
	Rule
	// JSON does not provide any data, might be removed
	JSON // CanBeSelected
	// Env contains the process environment variables
	Env // CanBeSelected
	// UrlencodedError equals 1 if we failed to parse de URL
	// It applies for URL query part and urlencoded post body
	UrlencodedError
	// ResponseArgs contains the response parsed arguments
	ResponseArgs // CanBeSelected
	// ResponseXML contains the response parsed XML
	ResponseXML // CanBeSelected
	// RequestXML contains the request parsed XML
	RequestXML // CanBeSelected
	// XML is a pointer to ResponseXML
	XML // CanBeSelected
	// MultipartPartHeaders contains the multipart headers
	MultipartPartHeaders // CanBeSelected

	// Unsupported variables

	// AuthType is the authentication type
	AuthType
	// FullRequest is the full request
	FullRequest
	// MultipartBoundaryQuoted kept for compatibility
	MultipartBoundaryQuoted
	// MultipartBoundaryWhitespace kept for compatibility
	MultipartBoundaryWhitespace
	// MultipartCrlfLfLines kept for compatibility
	MultipartCrlfLfLines
	// MultipartDataBefore kept for compatibility
	MultipartDataBefore
	// MultipartFileLimitExceeded kept for compatibility
	MultipartFileLimitExceeded
	// MultipartHeaderFolding kept for compatibility
	MultipartHeaderFolding
	// MultipartInvalidHeaderFolding kept for compatibility
	MultipartInvalidHeaderFolding
	// MultipartInvalidPart kept for compatibility
	MultipartInvalidPart
	// MultipartInvalidQuoting kept for compatibility
	MultipartInvalidQuoting
	// MultipartLfLine kept for compatibility
	MultipartLfLine
	// MultipartMissingSemicolon kept for compatibility
	MultipartMissingSemicolon
	// MultipartStrictError kept for compatibility
	MultipartStrictError
	// MultipartUnmatchedBoundary kept for compatibility
	MultipartUnmatchedBoundary
	// PathInfo is kept for compatibility
	PathInfo
	// Sessionid is not supported
	Sessionid
	// Userid is not supported
	Userid
	// IP is kept for compatibility
	IP
	// ResBodyError
	ResBodyError
	// ResBodyErrorMsg
	ResBodyErrorMsg
	// ResBodyProcessorError
	ResBodyProcessorError
	// ResBodyProcessorErrorMsg
	ResBodyProcessorErrorMsg
)
