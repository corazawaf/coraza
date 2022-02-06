/*
Package variables contains the representation of the variables used in the rules
Variables are created as bytes and they have a string representation
*/
// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package variables

import (
	"errors"
	"strings"
)

// This file repeats the same content many times in order to make access
// efficient for seclang and transactions

// VariablesCount contains the number of existing variables
const VariablesCount = 87

// RuleVariable is used to identify information from a transaction
type RuleVariable byte

const (
	// Unknown is used as placeholder for errors
	Unknown RuleVariable = iota
	// ResponseContentType is the content type of the response
	ResponseContentType RuleVariable = iota
	// UniqueID is the unique id of the transaction
	UniqueID RuleVariable = iota
	// ArgsCombinedSize is the combined size of the arguments
	ArgsCombinedSize RuleVariable = iota
	// AuthType is the authentication type
	AuthType RuleVariable = iota
	// FilesCombinedSize is the combined size of the uploaded files
	FilesCombinedSize RuleVariable = iota
	// FullRequest is the full request
	FullRequest RuleVariable = iota
	// FullRequestLength is the length of the full request
	FullRequestLength RuleVariable = iota
	// InboundDataError represents errors for inbound data
	InboundDataError RuleVariable = iota
	// MatchedVar is the value of the matched variable
	MatchedVar RuleVariable = iota
	// MatchedVarName is the name of the matched variable
	MatchedVarName RuleVariable = iota
	// MultipartBoundaryQuoted kept for compatibility
	MultipartBoundaryQuoted RuleVariable = iota
	// MultipartBoundaryWhitespace kept for compatibility
	MultipartBoundaryWhitespace RuleVariable = iota
	// MultipartCrlfLfLines kept for compatibility
	MultipartCrlfLfLines RuleVariable = iota
	// MultipartDataAfter kept for compatibility
	MultipartDataAfter RuleVariable = iota
	// MultipartDataBefore kept for compatibility
	MultipartDataBefore RuleVariable = iota
	// MultipartFileLimitExceeded kept for compatibility
	MultipartFileLimitExceeded RuleVariable = iota
	// MultipartHeaderFolding kept for compatibility
	MultipartHeaderFolding RuleVariable = iota
	// MultipartInvalidHeaderFolding kept for compatibility
	MultipartInvalidHeaderFolding RuleVariable = iota
	// MultipartInvalidPart kept for compatibility
	MultipartInvalidPart RuleVariable = iota
	// MultipartInvalidQuoting kept for compatibility
	MultipartInvalidQuoting RuleVariable = iota
	// MultipartLfLine kept for compatibility
	MultipartLfLine RuleVariable = iota
	// MultipartMissingSemicolon kept for compatibility
	MultipartMissingSemicolon RuleVariable = iota
	// MultipartStrictError kept for compatibility
	MultipartStrictError RuleVariable = iota
	// MultipartUnmatchedBoundary kept for compatibility
	MultipartUnmatchedBoundary RuleVariable = iota
	// OutboundDataError will be set to 1 when the response body size
	// is above the setting configured by SecResponseBodyLimit
	OutboundDataError RuleVariable = iota
	// PathInfo is kept for compatibility
	PathInfo RuleVariable = iota
	// QueryString contains the raw query string part of a request URI
	QueryString RuleVariable = iota
	// RemoteAddr is the remote address of the connection
	RemoteAddr RuleVariable = iota
	// RemoteHost is the remote host of the connection, not implemented
	RemoteHost RuleVariable = iota
	// RemotePort is the remote port of the connection
	RemotePort RuleVariable = iota
	// ReqbodyError contains the status of the request body processor used
	// for request body parsing, 0 means no error, 1 means error
	ReqbodyError RuleVariable = iota
	// ReqbodyErrorMsg contains the error message of the request body processor error
	ReqbodyErrorMsg RuleVariable = iota
	// ReqbodyProcessorError is the same as ReqbodyErrr ?
	ReqbodyProcessorError RuleVariable = iota
	// ReqbodyProcessorErrorMsg is the same as ReqbodyErrorMsg ?
	ReqbodyProcessorErrorMsg RuleVariable = iota
	// ReqbodyProcessor contains the name of the request body processor used, default
	// ones are: URLENCODED, MULTIPART, and XML. They can be extended using plugins.
	ReqbodyProcessor RuleVariable = iota
	// RequestBasename contains the name after the last slash in the request URI
	// It does not pass through any anti-evasion, use with transformations
	RequestBasename RuleVariable = iota
	// RequestBody contains the full request body, it will only be available
	// For urlencoded requests. It is possible to force it's presence by using
	// the ctl:forceRequestBodyVariable action
	RequestBody RuleVariable = iota
	// RequestBodyLength contains the length of the request body in bytes calculated from
	// the BodyBuffer, not from the content-type header
	RequestBodyLength RuleVariable = iota
	// RequestFilename holds the relative request URL without the query string part.
	// Anti-evasion transformations are not used by default
	RequestFilename RuleVariable = iota
	// RequestLine This variable holds the complete request line sent to the server
	// (including the request method and HTTP version information).
	RequestLine RuleVariable = iota
	// RequestMethod is the request method
	RequestMethod RuleVariable = iota
	// RequestProtocol is the protocol used in the request
	RequestProtocol RuleVariable = iota
	// RequestURI holds the full request URL including the query string data without
	// the domain name
	RequestURI RuleVariable = iota
	// RequestURIRaw is the same as RequestURI but with the domain name in case
	// it was provided in the request line
	RequestURIRaw RuleVariable = iota
	// ResponseBody contains the full response body, it will only be available if
	// responseBodyAccess is set to on and the response mime matches the configured
	// processable mime types
	ResponseBody RuleVariable = iota
	// ResponseContentLength contains the length of the response body in bytes calculated from
	// the BodyBuffer, not from the content-type header
	ResponseContentLength RuleVariable = iota
	// ResponseProtocol is the protocol used in the response
	ResponseProtocol RuleVariable = iota
	// ResponseStatus is the status code of the response
	ResponseStatus RuleVariable = iota
	// ServerAddr is the address of the server
	ServerAddr RuleVariable = iota
	// ServerName is the name of the server
	ServerName RuleVariable = iota
	// ServerPort is the port of the server
	ServerPort RuleVariable = iota
	// Sessionid is not supported
	Sessionid RuleVariable = iota
	// HighestSeverity is the highest severity from all matched rules
	HighestSeverity RuleVariable = iota
	// StatusLine is the status line of the response, including the request method
	// and HTTP version information
	StatusLine RuleVariable = iota
	// InboundErrorData will be set to 1 when the request body size
	// is above the setting configured by SecRequesteBodyLimit
	InboundErrorData RuleVariable = iota
	// Duration contains the time in miliseconds from
	// the beginning of the transaction until this point
	Duration RuleVariable = iota
	// ResponseHeadersNames contains the names of the response headers
	ResponseHeadersNames RuleVariable = iota
	// RequestHeadersNames contains the names of the request headers
	RequestHeadersNames RuleVariable = iota
	// Userid is not supported
	Userid RuleVariable = iota
	// Args contains copies of ArgsGet and ArgsPost
	Args RuleVariable = iota
	// ArgsGet contains the GET (URL) arguments
	ArgsGet RuleVariable = iota
	// ArgsPost contains the POST (BODY) arguments
	ArgsPost RuleVariable = iota
	// FilesSizes contains the sizes of the uploaded files
	FilesSizes RuleVariable = iota
	// FilesNames contains the names of the uploaded files
	FilesNames RuleVariable = iota
	// FilesTmpContent is not supported
	FilesTmpContent RuleVariable = iota
	// MultipartFilename contains the multipart data from field FILENAME
	MultipartFilename RuleVariable = iota
	// MultipartName contains the multipart data from field NAME.
	MultipartName RuleVariable = iota
	// MatchedVarsNames is similar to MATCHED_VAR_NAME except that it is
	// a collection of all matches for the current operator check.
	MatchedVarsNames RuleVariable = iota
	// MatchedVars is similar to MATCHED_VAR except that it is a collection
	// of all matches for the current operator check
	MatchedVars RuleVariable = iota
	// Files contains a collection of original file names
	// (as they were called on the remote user’s filesys- tem).
	// Available only on inspected multipart/form-data requests.
	Files RuleVariable = iota
	// RequestCookies is a collection of all of request cookies (values only
	RequestCookies RuleVariable = iota
	// RequestHeaders can be used as either a collection of all of the request
	// headers or can be used to inspect selected headers
	RequestHeaders RuleVariable = iota
	// ResponseHeaders can be used as either a collection of all of the response
	// headers or can be used to inspect selected headers
	ResponseHeaders RuleVariable = iota
	// Geo contains the location information of the client
	Geo RuleVariable = iota
	// RequestCookiesNames contains the names of the request cookies
	RequestCookiesNames RuleVariable = iota
	// FilesTmpNames contains the names of the uploaded temporal files
	FilesTmpNames RuleVariable = iota
	// ArgsNames contains the names of the arguments (POST and GET)
	ArgsNames RuleVariable = iota
	// ArgsGetNames contains the names of the GET arguments
	ArgsGetNames RuleVariable = iota
	// ArgsPostNames contains the names of the POST arguments
	ArgsPostNames RuleVariable = iota
	// TX contains transaction specific variables created with setvar
	TX RuleVariable = iota
	// Rule contains rule metadata
	Rule RuleVariable = iota
	// XML provides minimal XPATH support
	XML RuleVariable = iota
	// JSON does not provide any data, might be removed
	JSON RuleVariable = iota
	// Env contains the process environment variables
	Env RuleVariable = iota
	// IP is kept for compatibility
	IP RuleVariable = iota
	// UrlencodedError equals 1 if we failed to parse de URL
	// It applies for URL query part and urlencoded post body
	UrlencodedError RuleVariable = iota
)

var rulemap = map[RuleVariable]string{
	Unknown:                       "UNKNOWN",
	UrlencodedError:               "URLENCODED_ERROR",
	ResponseContentType:           "RESPONSE_CONTENT_TYPE",
	UniqueID:                      "UNIQUE_ID",
	ArgsCombinedSize:              "ARGS_COMBINED_SIZE",
	AuthType:                      "AUTH_TYPE",
	FilesCombinedSize:             "FILES_COMBINED_SIZE",
	FullRequest:                   "FULL_REQUEST",
	FullRequestLength:             "FULL_REQUEST_LENGTH",
	InboundDataError:              "INBOUND_DATA_ERROR",
	MatchedVar:                    "MATCHED_VAR",
	MatchedVarName:                "MATCHED_VAR_NAME",
	MultipartBoundaryQuoted:       "MULTIPART_BOUNDARY_QUOTED",
	MultipartBoundaryWhitespace:   "MULTIPART_BOUNDARY_WHITESPACE",
	MultipartCrlfLfLines:          "MULTIPART_CRLF_LF_LINES",
	MultipartDataAfter:            "MULTIPART_DATA_AFTER",
	MultipartDataBefore:           "MULTIPART_DATA_BEFORE",
	MultipartFileLimitExceeded:    "MULTIPART_FILE_LIMIT_EXCEEDED",
	MultipartHeaderFolding:        "MULTIPART_HEADER_FOLDING",
	MultipartInvalidHeaderFolding: "MULTIPART_INVALID_HEADER_FOLDING",
	MultipartInvalidPart:          "MULTIPART_INVALID_PART",
	MultipartInvalidQuoting:       "MULTIPART_INVALID_QUOTING",
	MultipartLfLine:               "MULTIPART_LF_LINE",
	MultipartMissingSemicolon:     "MULTIPART_MISSING_SEMICOLON",
	MultipartStrictError:          "MULTIPART_STRICT_ERROR",
	MultipartUnmatchedBoundary:    "MULTIPART_UNMATCHED_BOUNDARY",
	OutboundDataError:             "OUTBOUND_DATA_ERROR",
	PathInfo:                      "PATH_INFO",
	QueryString:                   "QUERY_STRING",
	RemoteAddr:                    "REMOTE_ADDR",
	RemoteHost:                    "REMOTE_HOST",
	RemotePort:                    "REMOTE_PORT",
	ReqbodyError:                  "REQBODY_ERROR",
	ReqbodyErrorMsg:               "REQBODY_ERROR_MSG",
	ReqbodyProcessorError:         "REQBODY_PROCESSOR_ERROR",
	ReqbodyProcessorErrorMsg:      "REQBODY_PROCESSOR_ERROR_MSG",
	ReqbodyProcessor:              "REQBODY_PROCESSOR",
	RequestBasename:               "REQUEST_BASENAME",
	RequestBody:                   "REQUEST_BODY",
	RequestBodyLength:             "REQUEST_BODY_LENGTH",
	RequestFilename:               "REQUEST_FILENAME",
	RequestLine:                   "REQUEST_LINE",
	RequestMethod:                 "REQUEST_METHOD",
	RequestProtocol:               "REQUEST_PROTOCOL",
	RequestURI:                    "REQUEST_URI",
	RequestURIRaw:                 "REQUEST_URI_RAW",
	ResponseBody:                  "RESPONSE_BODY",
	ResponseContentLength:         "RESPONSE_CONTENT_LENGTH",
	ResponseProtocol:              "RESPONSE_PROTOCOL",
	ResponseStatus:                "RESPONSE_STATUS",
	ServerAddr:                    "SERVER_ADDR",
	ServerName:                    "SERVER_NAME",
	ServerPort:                    "SERVER_PORT",
	Sessionid:                     "SESSIONID",
	HighestSeverity:               "HIGHEST_SEVERITY",
	StatusLine:                    "STATUS_LINE",
	InboundErrorData:              "INBOUND_ERROR_DATA",
	Duration:                      "DURATION",
	ResponseHeadersNames:          "RESPONSE_HEADERS_NAMES",
	RequestHeadersNames:           "REQUEST_HEADERS_NAMES",
	Userid:                        "USERID",
	Args:                          "ARGS",
	ArgsGet:                       "ARGS_GET",
	ArgsPost:                      "ARGS_POST",
	FilesSizes:                    "FILES_SIZES",
	FilesNames:                    "FILES_NAMES",
	FilesTmpContent:               "FILES_TMP_CONTENT",
	MultipartFilename:             "MULTIPART_FILENAME",
	MultipartName:                 "MULTIPART_NAME",
	MatchedVarsNames:              "MATCHED_VARS_NAMES",
	MatchedVars:                   "MATCHED_VARS",
	Files:                         "FILES",
	RequestCookies:                "REQUEST_COOKIES",
	RequestHeaders:                "REQUEST_HEADERS",
	ResponseHeaders:               "RESPONSE_HEADERS",
	Geo:                           "GEO",
	RequestCookiesNames:           "REQUEST_COOKIES_NAMES",
	FilesTmpNames:                 "FILES_TMPNAMES",
	ArgsNames:                     "ARGS_NAMES",
	ArgsGetNames:                  "ARGS_GET_NAMES",
	ArgsPostNames:                 "ARGS_POST_NAMES",
	TX:                            "TX",
	Rule:                          "RULE",
	XML:                           "XML",
	JSON:                          "JSON",
	Env:                           "ENV",
	IP:                            "IP",
}

var rulemapRev = map[string]RuleVariable{}

// Name transforms a VARIABLE representation
// into a string, it's used for audit and logging
func (v RuleVariable) Name() string {
	if name, ok := rulemap[v]; ok {
		return name
	}
	return "INVALID_VARIABLE"
}

var errUnknownVariable = errors.New("Unknown variable")

// Parse returns the byte interpretation
// of a variable from a string
// Returns error if there is no representation
func Parse(v string) (RuleVariable, error) {
	if v, ok := rulemapRev[strings.ToUpper(v)]; ok {
		return v, nil
	}
	return 0, errUnknownVariable
}

func init() {
	// we fill the rulemapRev with the reverse of rulemap
	for k, v := range rulemap {
		rulemapRev[v] = k
	}
}
