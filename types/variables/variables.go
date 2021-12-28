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
	OutboundDataError          RuleVariable = iota
	PathInfo                   RuleVariable = iota
	QueryString                RuleVariable = iota
	RemoteAddr                 RuleVariable = iota
	RemoteHost                 RuleVariable = iota
	RemotePort                 RuleVariable = iota
	ReqbodyError               RuleVariable = iota
	ReqbodyErrorMsg            RuleVariable = iota
	ReqbodyProcessorError      RuleVariable = iota
	ReqbodyProcessorErrorMsg   RuleVariable = iota
	ReqbodyProcessor           RuleVariable = iota
	RequestBasename            RuleVariable = iota
	RequestBody                RuleVariable = iota
	RequestBodyLength          RuleVariable = iota
	RequestFilename            RuleVariable = iota
	RequestLine                RuleVariable = iota
	RequestMethod              RuleVariable = iota
	RequestProtocol            RuleVariable = iota
	RequestURI                 RuleVariable = iota
	RequestURIRaw              RuleVariable = iota
	ResponseBody               RuleVariable = iota
	ResponseContentLength      RuleVariable = iota
	ResponseProtocol           RuleVariable = iota
	ResponseStatus             RuleVariable = iota
	ServerAddr                 RuleVariable = iota
	ServerName                 RuleVariable = iota
	ServerPort                 RuleVariable = iota
	Sessionid                  RuleVariable = iota
	HighestSeverity            RuleVariable = iota
	StatusLine                 RuleVariable = iota
	InboundErrorData           RuleVariable = iota
	// Duration contains the time in miliseconds from
	// the beginning of the transaction until this point
	Duration RuleVariable = iota
	// ResponseHeadersNames contains the names of the response headers
	ResponseHeadersNames RuleVariable = iota
	// RequestHeadersNames contains the names of the request headers
	RequestHeadersNames RuleVariable = iota
	Userid              RuleVariable = iota
	// Args contains copies of ArgsGet and ArgsPost
	Args RuleVariable = iota
	// ArgsGet contains the GET (URL) arguments
	ArgsGet RuleVariable = iota
	// ArgsPost contains the POST (BODY) arguments
	ArgsPost RuleVariable = iota
	// FilesSizes contains the sizes of the uploaded files
	FilesSizes RuleVariable = iota
	// FilesNames contains the names of the uploaded files
	FilesNames        RuleVariable = iota
	FilesTmpContent   RuleVariable = iota
	MultipartFilename RuleVariable = iota
	MultipartName     RuleVariable = iota
	MatchedVarsNames  RuleVariable = iota
	MatchedVars       RuleVariable = iota
	Files             RuleVariable = iota
	RequestCookies    RuleVariable = iota
	RequestHeaders    RuleVariable = iota
	ResponseHeaders   RuleVariable = iota
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
