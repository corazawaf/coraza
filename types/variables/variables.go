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

type RuleVariable byte

const (
	Unknown                       RuleVariable = RuleVariable(0)
	ResponseContentType           RuleVariable = RuleVariable(1)
	UniqueId                      RuleVariable = RuleVariable(2)
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
	RequestUri                    RuleVariable = RuleVariable(43)
	RequestUriRaw                 RuleVariable = RuleVariable(44)
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
	Tx                   RuleVariable = RuleVariable(80)
	Rule                 RuleVariable = RuleVariable(81)
	Xml                  RuleVariable = RuleVariable(82)
	Json                 RuleVariable = RuleVariable(83)
	Env                  RuleVariable = RuleVariable(84)

	// Persisten storage kepy for compatibility
	Ip RuleVariable = RuleVariable(85)

	UrlencodedError RuleVariable = RuleVariable(86)
)

// Name transforms a VARIABLE representation
// into a string, it's used for audit and logging
func (v RuleVariable) Name() string {
	switch v {
	case UrlencodedError:
		return "URLENCODED_ERROR"
	case ResponseContentType:
		return "RESPONSE_CONTENT_TYPE"
	case UniqueId:
		return "UNIQUE_ID"
	case ArgsCombinedSize:
		return "ARGS_COMBINED_SIZE"
	case AuthType:
		return "AUTH_TYPE"
	case FilesCombinedSize:
		return "FILES_COMBINED_SIZE"
	case FullRequest:
		return "FULL_REQUEST"
	case FullRequestLength:
		return "FULL_REQUEST_LENGTH"
	case InboundDataError:
		return "INBOUND_DATA_ERROR"
	case MatchedVar:
		return "MATCHED_VAR"
	case MatchedVarName:
		return "MATCHED_VAR_NAME"
	case MultipartBoundaryQuoted:
		return "MULTIPART_BOUNDARY_QUOTED"
	case MultipartBoundaryWhitespace:
		return "MULTIPART_BOUNDARY_WHITESPACE"
	case MultipartCrlfLfLines:
		return "MULTIPART_CRLF_LF_LINES"
	case MultipartDataAfter:
		return "MULTIPART_DATA_AFTER"
	case MultipartDataBefore:
		return "MULTIPART_DATA_BEFORE"
	case MultipartFileLimitExceeded:
		return "MULTIPART_FILE_LIMIT_EXCEEDED"
	case MultipartHeaderFolding:
		return "MULTIPART_HEADER_FOLDING"
	case MultipartInvalidHeaderFolding:
		return "MULTIPART_INVALID_HEADER_FOLDING"
	case MultipartInvalidPart:
		return "MULTIPART_INVALID_PART"
	case MultipartInvalidQuoting:
		return "MULTIPART_INVALID_QUOTING"
	case MultipartLfLine:
		return "MULTIPART_LF_LINE"
	case MultipartMissingSemicolon:
		return "MULTIPART_MISSING_SEMICOLON"
	case MultipartStrictError:
		return "MULTIPART_STRICT_ERROR"
	case MultipartUnmatchedBoundary:
		return "MULTIPART_UNMATCHED_BOUNDARY"
	case OutboundDataError:
		return "OUTBOUND_DATA_ERROR"
	case PathInfo:
		return "PATH_INFO"
	case QueryString:
		return "QUERY_STRING"
	case RemoteAddr:
		return "REMOTE_ADDR"
	case RemoteHost:
		return "REMOTE_HOST"
	case RemotePort:
		return "REMOTE_PORT"
	case ReqbodyError:
		return "REQBODY_ERROR"
	case ReqbodyErrorMsg:
		return "REQBODY_ERROR_MSG"
	case ReqbodyProcessorError:
		return "REQBODY_PROCESSOR_ERROR"
	case ReqbodyProcessorErrorMsg:
		return "REQBODY_PROCESSOR_ERROR_MSG"
	case ReqbodyProcessor:
		return "REQBODY_PROCESSOR"
	case RequestBasename:
		return "REQUEST_BASENAME"
	case RequestBody:
		return "REQUEST_BODY"
	case RequestBodyLength:
		return "REQUEST_BODY_LENGTH"
	case RequestFilename:
		return "REQUEST_FILENAME"
	case RequestLine:
		return "REQUEST_LINE"
	case RequestMethod:
		return "REQUEST_METHOD"
	case RequestProtocol:
		return "REQUEST_PROTOCOL"
	case RequestUri:
		return "REQUEST_URI"
	case RequestUriRaw:
		return "REQUEST_URI_RAW"
	case ResponseBody:
		return "RESPONSE_BODY"
	case ResponseContentLength:
		return "RESPONSE_CONTENT_LENGTH"
	case ResponseProtocol:
		return "RESPONSE_PROTOCOL"
	case ResponseStatus:
		return "RESPONSE_STATUS"
	case ServerAddr:
		return "SERVER_ADDR"
	case ServerName:
		return "SERVER_NAME"
	case ServerPort:
		return "SERVER_PORT"
	case Sessionid:
		return "SESSIONID"
	case HighestSeverity:
		return "HIGHEST_SEVERITY"
	case StatusLine:
		return "STATUS_LINE"
	case InboundErrorData:
		return "INBOUND_ERROR_DATA"
	case Duration:
		return "DURATION"
	case ResponseHeadersNames:
		return "RESPONSE_HEADERS_NAMES"
	case RequestHeadersNames:
		return "REQUEST_HEADERS_NAMES"
	case Userid:
		return "USERID"
	case Args:
		return "ARGS"
	case ArgsGet:
		return "ARGS_GET"
	case ArgsPost:
		return "ARGS_POST"
	case FilesSizes:
		return "FILES_SIZES"
	case FilesNames:
		return "FILES_NAMES"
	case FilesTmpContent:
		return "FILES_TMP_CONTENT"
	case MultipartFilename:
		return "MULTIPART_FILENAME"
	case MultipartName:
		return "MULTIPART_NAME"
	case MatchedVarsNames:
		return "MATCHED_VARS_NAMES"
	case MatchedVars:
		return "MATCHED_VARS"
	case Files:
		return "FILES"
	case RequestCookies:
		return "REQUEST_COOKIES"
	case RequestHeaders:
		return "REQUEST_HEADERS"
	case ResponseHeaders:
		return "RESPONSE_HEADERS"
	case Geo:
		return "GEO"
	case RequestCookiesNames:
		return "REQUEST_COOKIES_NAMES"
	case FilesTmpnames:
		return "FILES_TMPNAMES"
	case ArgsNames:
		return "ARGS_NAMES"
	case ArgsGetNames:
		return "ARGS_GET_NAMES"
	case ArgsPostNames:
		return "ARGS_POST_NAMES"
	case Tx:
		return "TX"
	case Rule:
		return "RULE"
	case Xml:
		return "XML"
	case Json:
		return "JSON"
	case Env:
		return "ENV"
	case Ip:
		return "IP"
	}
	return "UNKNOWN"
}

// ParseRuleVariable returns the byte interpretation
// of a variable from a string
// Returns error if there is no representation
func ParseVariable(v string) (RuleVariable, error) {
	switch strings.ToUpper(v) {
	case "URLENCODED_ERROR":
		return UrlencodedError, nil
	case "RESPONSE_CONTENT_TYPE":
		return ResponseContentType, nil
	case "UNIQUE_ID":
		return UniqueId, nil
	case "ARGS_COMBINED_SIZE":
		return ArgsCombinedSize, nil
	case "AUTH_TYPE":
		return AuthType, nil
	case "FILES_COMBINED_SIZE":
		return FilesCombinedSize, nil
	case "FULL_REQUEST":
		return FullRequest, nil
	case "FULL_REQUEST_LENGTH":
		return FullRequestLength, nil
	case "INBOUND_DATA_ERROR":
		return InboundDataError, nil
	case "MATCHED_VAR":
		return MatchedVar, nil
	case "MATCHED_VAR_NAME":
		return MatchedVarName, nil
	case "MULTIPART_BOUNDARY_QUOTED":
		return MultipartBoundaryQuoted, nil
	case "MULTIPART_BOUNDARY_WHITESPACE":
		return MultipartBoundaryWhitespace, nil
	case "MULTIPART_CRLF_LF_LINES":
		return MultipartCrlfLfLines, nil
	case "MULTIPART_DATA_AFTER":
		return MultipartDataAfter, nil
	case "MULTIPART_DATA_BEFORE":
		return MultipartDataBefore, nil
	case "MULTIPART_FILE_LIMIT_EXCEEDED":
		return MultipartFileLimitExceeded, nil
	case "MULTIPART_HEADER_FOLDING":
		return MultipartHeaderFolding, nil
	case "MULTIPART_INVALID_HEADER_FOLDING":
		return MultipartInvalidHeaderFolding, nil
	case "MULTIPART_INVALID_PART":
		return MultipartInvalidPart, nil
	case "MULTIPART_INVALID_QUOTING":
		return MultipartInvalidQuoting, nil
	case "MULTIPART_LF_LINE":
		return MultipartLfLine, nil
	case "MULTIPART_MISSING_SEMICOLON":
		return MultipartMissingSemicolon, nil
	case "MULTIPART_STRICT_ERROR":
		return MultipartStrictError, nil
	case "MULTIPART_UNMATCHED_BOUNDARY":
		return MultipartUnmatchedBoundary, nil
	case "OUTBOUND_DATA_ERROR":
		return OutboundDataError, nil
	case "PATH_INFO":
		return PathInfo, nil
	case "QUERY_STRING":
		return QueryString, nil
	case "REMOTE_ADDR":
		return RemoteAddr, nil
	case "REMOTE_HOST":
		return RemoteHost, nil
	case "REMOTE_PORT":
		return RemotePort, nil
	case "REQBODY_ERROR":
		return ReqbodyError, nil
	case "REQBODY_ERROR_MSG":
		return ReqbodyErrorMsg, nil
	case "REQBODY_PROCESSOR_ERROR":
		return ReqbodyProcessorError, nil
	case "REQBODY_PROCESSOR_ERROR_MSG":
		return ReqbodyProcessorErrorMsg, nil
	case "REQBODY_PROCESSOR":
		return ReqbodyProcessor, nil
	case "REQUEST_BASENAME":
		return RequestBasename, nil
	case "REQUEST_BODY":
		return RequestBody, nil
	case "REQUEST_BODY_LENGTH":
		return RequestBodyLength, nil
	case "REQUEST_FILENAME":
		return RequestFilename, nil
	case "REQUEST_LINE":
		return RequestLine, nil
	case "REQUEST_METHOD":
		return RequestMethod, nil
	case "REQUEST_PROTOCOL":
		return RequestProtocol, nil
	case "REQUEST_URI":
		return RequestUri, nil
	case "REQUEST_URI_RAW":
		return RequestUriRaw, nil
	case "RESPONSE_BODY":
		return ResponseBody, nil
	case "RESPONSE_CONTENT_LENGTH":
		return ResponseContentLength, nil
	case "RESPONSE_PROTOCOL":
		return ResponseProtocol, nil
	case "RESPONSE_STATUS":
		return ResponseStatus, nil
	case "SERVER_ADDR":
		return ServerAddr, nil
	case "SERVER_NAME":
		return ServerName, nil
	case "SERVER_PORT":
		return ServerPort, nil
	case "SESSIONID":
		return Sessionid, nil
	case "HIGHEST_SEVERITY":
		return HighestSeverity, nil
	case "STATUS_LINE":
		return StatusLine, nil
	case "INBOUND_ERROR_DATA":
		return InboundErrorData, nil
	case "DURATION":
		return Duration, nil
	case "RESPONSE_HEADERS_NAMES":
		return ResponseHeadersNames, nil
	case "REQUEST_HEADERS_NAMES":
		return RequestHeadersNames, nil
	case "USERID":
		return Userid, nil
	case "ARGS":
		return Args, nil
	case "ARGS_GET":
		return ArgsGet, nil
	case "ARGS_POST":
		return ArgsPost, nil
	case "FILES_SIZES":
		return FilesSizes, nil
	case "FILES_NAMES":
		return FilesNames, nil
	case "FILES_TMP_CONTENT":
		return FilesTmpContent, nil
	case "MULTIPART_FILENAME":
		return MultipartFilename, nil
	case "MULTIPART_NAME":
		return MultipartName, nil
	case "MATCHED_VARS_NAMES":
		return MatchedVarsNames, nil
	case "MATCHED_VARS":
		return MatchedVars, nil
	case "FILES":
		return Files, nil
	case "REQUEST_COOKIES":
		return RequestCookies, nil
	case "REQUEST_HEADERS":
		return RequestHeaders, nil
	case "RESPONSE_HEADERS":
		return ResponseHeaders, nil
	case "GEO":
		return Geo, nil
	case "REQUEST_COOKIES_NAMES":
		return RequestCookiesNames, nil
	case "FILES_TMPNAMES":
		return FilesTmpnames, nil
	case "ARGS_NAMES":
		return ArgsNames, nil
	case "ARGS_GET_NAMES":
		return ArgsGetNames, nil
	case "ARGS_POST_NAMES":
		return ArgsPostNames, nil
	case "TX":
		return Tx, nil
	case "RULE":
		return Rule, nil
	case "XML":
		return Xml, nil
	case "JSON":
		return Json, nil
	case "ENV":
		return Env, nil
	case "IP":
		return Ip, nil
	}
	return 0, fmt.Errorf("unknown variable %s", v)
}
