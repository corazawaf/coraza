// Copyright 2021 Juan Pablo Tosso
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
	"fmt"
	"strings"
)

// This file repeats the same content many times in order to make access
// efficient for seclang and transactions

// RuleVariable is used for the rule to identify information
// Each RuleVariable is unique and represents a variable
type RuleVariable byte

const (
	// Unknown is the default value for a variable
	// it's using for testing and error catching
	Unknown                       RuleVariable = RuleVariable(0)
	ResponseContentType           RuleVariable = RuleVariable(1)
	UniqueID                      RuleVariable = RuleVariable(2)
	ArgsCombinedSize              RuleVariable = RuleVariable(3)
	AuthType                      RuleVariable = RuleVariable(4)
	FilesCombinedSize             RuleVariable = RuleVariable(5)
	FullRequest                   RuleVariable = RuleVariable(6)
	FullRequestLength             RuleVariable = RuleVariable(7)
	InboundDataError              RuleVariable = RuleVariable(8)
	MatchedVar                    RuleVariable = RuleVariable(9)
	MatchedVarName                RuleVariable = RuleVariable(10)
	MultipartBoundaryQuoted       RuleVariable = RuleVariable(11)
	MultipartBoundaryWhitespace   RuleVariable = RuleVariable(12)
	MultipartCrlfLfLines          RuleVariable = RuleVariable(13)
	MultipartDataAfter            RuleVariable = RuleVariable(14)
	MultipartDataBefore           RuleVariable = RuleVariable(15)
	MultipartFileLimitExceeded    RuleVariable = RuleVariable(16)
	MultipartHeaderFolding        RuleVariable = RuleVariable(17)
	MultipartInvalidHeaderFolding RuleVariable = RuleVariable(18)
	MultipartInvalidPart          RuleVariable = RuleVariable(19)
	MultipartInvalidQuoting       RuleVariable = RuleVariable(20)
	MultipartLfLine               RuleVariable = RuleVariable(21)
	MultipartMissingSemicolon     RuleVariable = RuleVariable(22)
	MultipartStrictError          RuleVariable = RuleVariable(23)
	MultipartUnmatchedBoundary    RuleVariable = RuleVariable(24)
	OutboundDataError             RuleVariable = RuleVariable(25)
	PathInfo                      RuleVariable = RuleVariable(26)
	QueryString                   RuleVariable = RuleVariable(27)
	RemoteAddr                    RuleVariable = RuleVariable(28)
	RemoteHost                    RuleVariable = RuleVariable(29)
	RemotePort                    RuleVariable = RuleVariable(30)
	ReqbodyError                  RuleVariable = RuleVariable(31)
	ReqbodyErrorMsg               RuleVariable = RuleVariable(32)
	ReqbodyProcessorError         RuleVariable = RuleVariable(33)
	ReqbodyProcessorErrorMsg      RuleVariable = RuleVariable(34)
	ReqbodyProcessor              RuleVariable = RuleVariable(35)
	RequestBasename               RuleVariable = RuleVariable(36)
	RequestBody                   RuleVariable = RuleVariable(37)
	RequestBodyLength             RuleVariable = RuleVariable(38)
	RequestFilename               RuleVariable = RuleVariable(39)
	RequestLine                   RuleVariable = RuleVariable(40)
	RequestMethod                 RuleVariable = RuleVariable(41)
	RequestProtocol               RuleVariable = RuleVariable(42)
	RequestURI                    RuleVariable = RuleVariable(43)
	RequestURIRaw                 RuleVariable = RuleVariable(44)
	ResponseBody                  RuleVariable = RuleVariable(45)
	ResponseContentLength         RuleVariable = RuleVariable(46)
	ResponseProtocol              RuleVariable = RuleVariable(47)
	ResponseStatus                RuleVariable = RuleVariable(48)
	ServerAddr                    RuleVariable = RuleVariable(49)
	ServerName                    RuleVariable = RuleVariable(50)
	ServerPort                    RuleVariable = RuleVariable(51)
	Sessionid                     RuleVariable = RuleVariable(52)
	HighestSeverity               RuleVariable = RuleVariable(53)
	StatusLine                    RuleVariable = RuleVariable(54)
	InboundErrorData              RuleVariable = RuleVariable(55)
	Duration                      RuleVariable = RuleVariable(56)

	ResponseHeadersNames RuleVariable = RuleVariable(57)
	RequestHeadersNames  RuleVariable = RuleVariable(58)
	Userid               RuleVariable = RuleVariable(59)
	Args                 RuleVariable = RuleVariable(60)
	ArgsGet              RuleVariable = RuleVariable(61)
	ArgsPost             RuleVariable = RuleVariable(62)
	FilesSizes           RuleVariable = RuleVariable(63)
	FilesNames           RuleVariable = RuleVariable(64)
	FilesTmpContent      RuleVariable = RuleVariable(65)
	MultipartFilename    RuleVariable = RuleVariable(66)
	MultipartName        RuleVariable = RuleVariable(67)
	MatchedVarsNames     RuleVariable = RuleVariable(68)
	MatchedVars          RuleVariable = RuleVariable(69)
	Files                RuleVariable = RuleVariable(70)
	RequestCookies       RuleVariable = RuleVariable(71)
	RequestHeaders       RuleVariable = RuleVariable(72)
	ResponseHeaders      RuleVariable = RuleVariable(73)
	Geo                  RuleVariable = RuleVariable(74)
	RequestCookiesNames  RuleVariable = RuleVariable(75)
	FilesTmpnames        RuleVariable = RuleVariable(76)
	ArgsNames            RuleVariable = RuleVariable(77)
	ArgsGetNames         RuleVariable = RuleVariable(78)
	ArgsPostNames        RuleVariable = RuleVariable(79)
	TX                   RuleVariable = RuleVariable(80)
	Rule                 RuleVariable = RuleVariable(81)
	XML                  RuleVariable = RuleVariable(82)
	JSON                 RuleVariable = RuleVariable(83)
	Env                  RuleVariable = RuleVariable(84)

	// Persisten storage kepy for compatibility
	IP RuleVariable = RuleVariable(85)

	UrlencodedError RuleVariable = RuleVariable(86)
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
	FilesTmpnames:                 "FILES_TMPNAMES",
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
	return "UNKNOWN"
}

// ParseRuleVariable returns the byte interpretation
// of a variable from a string
// Returns error if there is no representation
func ParseVariable(v string) (RuleVariable, error) {
	if v, ok := rulemapRev[strings.ToUpper(v)]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("unknown variable %s", v)
}

func init() {
	// we fill the rulemapRev with the reverse of rulemap
	for k, v := range rulemap {
		rulemapRev[v] = k
	}
}
