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
package coraza

import (
	"errors"
	"strings"
)

// This file repeats the same content many times in order to make access
// efficient for seclang and transactions

type RuleVariable byte

const ruleVariablesCount = 100 //TODO fix
const (
	VARIABLE_URLENCODED_ERROR                 RuleVariable = RuleVariable(0)
	VARIABLE_RESPONSE_CONTENT_TYPE            RuleVariable = RuleVariable(1)
	VARIABLE_UNIQUE_ID                        RuleVariable = RuleVariable(2)
	VARIABLE_ARGS_COMBINED_SIZE               RuleVariable = RuleVariable(3)
	VARIABLE_AUTH_TYPE                        RuleVariable = RuleVariable(4)
	VARIABLE_FILES_COMBINED_SIZE              RuleVariable = RuleVariable(5)
	VARIABLE_FULL_REQUEST                     RuleVariable = RuleVariable(6)
	VARIABLE_FULL_REQUEST_LENGTH              RuleVariable = RuleVariable(7)
	VARIABLE_INBOUND_DATA_ERROR               RuleVariable = RuleVariable(8)
	VARIABLE_MATCHED_VAR                      RuleVariable = RuleVariable(9)
	VARIABLE_MATCHED_VAR_NAME                 RuleVariable = RuleVariable(10)
	VARIABLE_MULTIPART_BOUNDARY_QUOTED        RuleVariable = RuleVariable(11)
	VARIABLE_MULTIPART_BOUNDARY_WHITESPACE    RuleVariable = RuleVariable(12)
	VARIABLE_MULTIPART_CRLF_LF_LINES          RuleVariable = RuleVariable(13)
	VARIABLE_MULTIPART_DATA_AFTER             RuleVariable = RuleVariable(14)
	VARIABLE_MULTIPART_DATA_BEFORE            RuleVariable = RuleVariable(15)
	VARIABLE_MULTIPART_FILE_LIMIT_EXCEEDED    RuleVariable = RuleVariable(16)
	VARIABLE_MULTIPART_HEADER_FOLDING         RuleVariable = RuleVariable(17)
	VARIABLE_MULTIPART_INVALID_HEADER_FOLDING RuleVariable = RuleVariable(18)
	VARIABLE_MULTIPART_INVALID_PART           RuleVariable = RuleVariable(19)
	VARIABLE_MULTIPART_INVALID_QUOTING        RuleVariable = RuleVariable(20)
	VARIABLE_MULTIPART_LF_LINE                RuleVariable = RuleVariable(21)
	VARIABLE_MULTIPART_MISSING_SEMICOLON      RuleVariable = RuleVariable(22)
	VARIABLE_MULTIPART_STRICT_ERROR           RuleVariable = RuleVariable(23)
	VARIABLE_MULTIPART_UNMATCHED_BOUNDARY     RuleVariable = RuleVariable(24)
	VARIABLE_OUTBOUND_DATA_ERROR              RuleVariable = RuleVariable(25)
	VARIABLE_PATH_INFO                        RuleVariable = RuleVariable(26)
	VARIABLE_QUERY_STRING                     RuleVariable = RuleVariable(27)
	VARIABLE_REMOTE_ADDR                      RuleVariable = RuleVariable(28)
	VARIABLE_REMOTE_HOST                      RuleVariable = RuleVariable(29)
	VARIABLE_REMOTE_PORT                      RuleVariable = RuleVariable(30)
	VARIABLE_REQBODY_ERROR                    RuleVariable = RuleVariable(31)
	VARIABLE_REQBODY_ERROR_MSG                RuleVariable = RuleVariable(32)
	VARIABLE_REQBODY_PROCESSOR_ERROR          RuleVariable = RuleVariable(33)
	VARIABLE_REQBODY_PROCESSOR_ERROR_MSG      RuleVariable = RuleVariable(34)
	VARIABLE_REQBODY_PROCESSOR                RuleVariable = RuleVariable(35)
	VARIABLE_REQUEST_BASENAME                 RuleVariable = RuleVariable(36)
	VARIABLE_REQUEST_BODY                     RuleVariable = RuleVariable(37)
	VARIABLE_REQUEST_BODY_LENGTH              RuleVariable = RuleVariable(38)
	VARIABLE_REQUEST_FILENAME                 RuleVariable = RuleVariable(39)
	VARIABLE_REQUEST_LINE                     RuleVariable = RuleVariable(40)
	VARIABLE_REQUEST_METHOD                   RuleVariable = RuleVariable(41)
	VARIABLE_REQUEST_PROTOCOL                 RuleVariable = RuleVariable(42)
	VARIABLE_REQUEST_URI                      RuleVariable = RuleVariable(43)
	VARIABLE_REQUEST_URI_RAW                  RuleVariable = RuleVariable(44)
	VARIABLE_RESPONSE_BODY                    RuleVariable = RuleVariable(45)
	VARIABLE_RESPONSE_CONTENT_LENGTH          RuleVariable = RuleVariable(46)
	VARIABLE_RESPONSE_PROTOCOL                RuleVariable = RuleVariable(47)
	VARIABLE_RESPONSE_STATUS                  RuleVariable = RuleVariable(48)
	VARIABLE_SERVER_ADDR                      RuleVariable = RuleVariable(49)
	VARIABLE_SERVER_NAME                      RuleVariable = RuleVariable(50)
	VARIABLE_SERVER_PORT                      RuleVariable = RuleVariable(51)
	VARIABLE_SESSIONID                        RuleVariable = RuleVariable(52)
	VARIABLE_HIGHEST_SEVERITY                 RuleVariable = RuleVariable(53)
	VARIABLE_STATUS_LINE                      RuleVariable = RuleVariable(54)
	VARIABLE_INBOUND_ERROR_DATA               RuleVariable = RuleVariable(55)
	VARIABLE_DURATION                         RuleVariable = RuleVariable(56)

	VARIABLE_RESPONSE_HEADERS_NAMES RuleVariable = RuleVariable(57)
	VARIABLE_REQUEST_HEADERS_NAMES  RuleVariable = RuleVariable(58)
	VARIABLE_USERID                 RuleVariable = RuleVariable(59)
	VARIABLE_ARGS                   RuleVariable = RuleVariable(60)
	VARIABLE_ARGS_GET               RuleVariable = RuleVariable(61)
	VARIABLE_ARGS_POST              RuleVariable = RuleVariable(62)
	VARIABLE_FILES_SIZES            RuleVariable = RuleVariable(63)
	VARIABLE_FILES_NAMES            RuleVariable = RuleVariable(64)
	VARIABLE_FILES_TMP_CONTENT      RuleVariable = RuleVariable(65)
	VARIABLE_MULTIPART_FILENAME     RuleVariable = RuleVariable(66)
	VARIABLE_MULTIPART_NAME         RuleVariable = RuleVariable(67)
	VARIABLE_MATCHED_VARS_NAMES     RuleVariable = RuleVariable(68)
	VARIABLE_MATCHED_VARS           RuleVariable = RuleVariable(69)
	VARIABLE_FILES                  RuleVariable = RuleVariable(70)
	VARIABLE_REQUEST_COOKIES        RuleVariable = RuleVariable(71)
	VARIABLE_REQUEST_HEADERS        RuleVariable = RuleVariable(72)
	VARIABLE_RESPONSE_HEADERS       RuleVariable = RuleVariable(73)
	VARIABLE_GEO                    RuleVariable = RuleVariable(74)
	VARIABLE_REQUEST_COOKIES_NAMES  RuleVariable = RuleVariable(75)
	VARIABLE_FILES_TMPNAMES         RuleVariable = RuleVariable(76)
	VARIABLE_ARGS_NAMES             RuleVariable = RuleVariable(77)
	VARIABLE_ARGS_GET_NAMES         RuleVariable = RuleVariable(78)
	VARIABLE_ARGS_POST_NAMES        RuleVariable = RuleVariable(79)
	VARIABLE_TX                     RuleVariable = RuleVariable(80)
	VARIABLE_RULE                   RuleVariable = RuleVariable(81)
	VARIABLE_XML                    RuleVariable = RuleVariable(82)
	VARIABLE_JSON                   RuleVariable = RuleVariable(83)
	VARIABLE_ENV                    RuleVariable = RuleVariable(84)

	// Persisten storage kepy for compatibility
	VARIABLE_IP RuleVariable = RuleVariable(85)
)

// ParseRuleVariable returns the byte interpretation
// of a variable from a string
// Returns error if there is no representation
func ParseRuleVariable(name string) (RuleVariable, error) {
	name = strings.ToUpper(name)
	switch name {
	case "URLENCODED_ERROR":
		return VARIABLE_URLENCODED_ERROR, nil
	case "RESPONSE_CONTENT_TYPE":
		return VARIABLE_RESPONSE_CONTENT_TYPE, nil
	case "UNIQUE_ID":
		return VARIABLE_UNIQUE_ID, nil
	case "ARGS_COMBINED_SIZE":
		return VARIABLE_ARGS_COMBINED_SIZE, nil
	case "AUTH_TYPE":
		return VARIABLE_AUTH_TYPE, nil
	case "FILES_COMBINED_SIZE":
		return VARIABLE_FILES_COMBINED_SIZE, nil
	case "FULL_REQUEST":
		return VARIABLE_FULL_REQUEST, nil
	case "FULL_REQUEST_LENGTH":
		return VARIABLE_FULL_REQUEST_LENGTH, nil
	case "INBOUND_DATA_ERROR":
		return VARIABLE_INBOUND_DATA_ERROR, nil
	case "MATCHED_VAR":
		return VARIABLE_MATCHED_VAR, nil
	case "MATCHED_VAR_NAME":
		return VARIABLE_MATCHED_VAR_NAME, nil
	case "MULTIPART_BOUNDARY_QUOTED":
		return VARIABLE_MULTIPART_BOUNDARY_QUOTED, nil
	case "MULTIPART_BOUNDARY_WHITESPACE":
		return VARIABLE_MULTIPART_BOUNDARY_WHITESPACE, nil
	case "MULTIPART_CRLF_LF_LINES":
		return VARIABLE_MULTIPART_CRLF_LF_LINES, nil
	case "MULTIPART_DATA_AFTER":
		return VARIABLE_MULTIPART_DATA_AFTER, nil
	case "MULTIPART_DATA_BEFORE":
		return VARIABLE_MULTIPART_DATA_BEFORE, nil
	case "MULTIPART_FILE_LIMIT_EXCEEDED":
		return VARIABLE_MULTIPART_FILE_LIMIT_EXCEEDED, nil
	case "MULTIPART_HEADER_FOLDING":
		return VARIABLE_MULTIPART_HEADER_FOLDING, nil
	case "MULTIPART_INVALID_HEADER_FOLDING":
		return VARIABLE_MULTIPART_INVALID_HEADER_FOLDING, nil
	case "MULTIPART_INVALID_PART":
		return VARIABLE_MULTIPART_INVALID_PART, nil
	case "MULTIPART_INVALID_QUOTING":
		return VARIABLE_MULTIPART_INVALID_QUOTING, nil
	case "MULTIPART_LF_LINE":
		return VARIABLE_MULTIPART_LF_LINE, nil
	case "MULTIPART_MISSING_SEMICOLON":
		return VARIABLE_MULTIPART_MISSING_SEMICOLON, nil
	case "MULTIPART_STRICT_ERROR":
		return VARIABLE_MULTIPART_STRICT_ERROR, nil
	case "MULTIPART_UNMATCHED_BOUNDARY":
		return VARIABLE_MULTIPART_UNMATCHED_BOUNDARY, nil
	case "OUTBOUND_DATA_ERROR":
		return VARIABLE_OUTBOUND_DATA_ERROR, nil
	case "PATH_INFO":
		return VARIABLE_PATH_INFO, nil
	case "QUERY_STRING":
		return VARIABLE_QUERY_STRING, nil
	case "REMOTE_ADDR":
		return VARIABLE_REMOTE_ADDR, nil
	case "REMOTE_HOST":
		return VARIABLE_REMOTE_HOST, nil
	case "REMOTE_PORT":
		return VARIABLE_REMOTE_PORT, nil
	case "REQBODY_ERROR":
		return VARIABLE_REQBODY_ERROR, nil
	case "REQBODY_ERROR_MSG":
		return VARIABLE_REQBODY_ERROR_MSG, nil
	case "REQBODY_PROCESSOR_ERROR":
		return VARIABLE_REQBODY_PROCESSOR_ERROR, nil
	case "REQBODY_PROCESSOR_ERROR_MSG":
		return VARIABLE_REQBODY_PROCESSOR_ERROR_MSG, nil
	case "REQBODY_PROCESSOR":
		return VARIABLE_REQBODY_PROCESSOR, nil
	case "REQUEST_BASENAME":
		return VARIABLE_REQUEST_BASENAME, nil
	case "REQUEST_BODY":
		return VARIABLE_REQUEST_BODY, nil
	case "REQUEST_BODY_LENGTH":
		return VARIABLE_REQUEST_BODY_LENGTH, nil
	case "REQUEST_FILENAME":
		return VARIABLE_REQUEST_FILENAME, nil
	case "REQUEST_LINE":
		return VARIABLE_REQUEST_LINE, nil
	case "REQUEST_METHOD":
		return VARIABLE_REQUEST_METHOD, nil
	case "REQUEST_PROTOCOL":
		return VARIABLE_REQUEST_PROTOCOL, nil
	case "REQUEST_URI":
		return VARIABLE_REQUEST_URI, nil
	case "REQUEST_URI_RAW":
		return VARIABLE_REQUEST_URI_RAW, nil
	case "RESPONSE_BODY":
		return VARIABLE_RESPONSE_BODY, nil
	case "RESPONSE_CONTENT_LENGTH":
		return VARIABLE_RESPONSE_CONTENT_LENGTH, nil
	case "RESPONSE_PROTOCOL":
		return VARIABLE_RESPONSE_PROTOCOL, nil
	case "RESPONSE_STATUS":
		return VARIABLE_RESPONSE_STATUS, nil
	case "SERVER_ADDR":
		return VARIABLE_SERVER_ADDR, nil
	case "SERVER_NAME":
		return VARIABLE_SERVER_NAME, nil
	case "SERVER_PORT":
		return VARIABLE_SERVER_PORT, nil
	case "SESSIONID":
		return VARIABLE_SESSIONID, nil
	case "RESPONSE_HEADERS_NAMES":
		return VARIABLE_RESPONSE_HEADERS_NAMES, nil
	case "REQUEST_HEADERS_NAMES":
		return VARIABLE_REQUEST_HEADERS_NAMES, nil
	case "USERID":
		return VARIABLE_USERID, nil
	case "ARGS":
		return VARIABLE_ARGS, nil
	case "ARGS_GET":
		return VARIABLE_ARGS_GET, nil
	case "ARGS_POST":
		return VARIABLE_ARGS_POST, nil
	case "FILES_SIZES":
		return VARIABLE_FILES_SIZES, nil
	case "FILES_NAMES":
		return VARIABLE_FILES_NAMES, nil
	case "FILES_TMP_CONTENT":
		return VARIABLE_FILES_TMP_CONTENT, nil
	case "MULTIPART_FILENAME":
		return VARIABLE_MULTIPART_FILENAME, nil
	case "MULTIPART_NAME":
		return VARIABLE_MULTIPART_NAME, nil
	case "MATCHED_VARS_NAMES":
		return VARIABLE_MATCHED_VARS_NAMES, nil
	case "MATCHED_VARS":
		return VARIABLE_MATCHED_VARS, nil
	case "FILES":
		return VARIABLE_FILES, nil
	case "REQUEST_COOKIES":
		return VARIABLE_REQUEST_COOKIES, nil
	case "REQUEST_HEADERS":
		return VARIABLE_REQUEST_HEADERS, nil
	case "RESPONSE_HEADERS":
		return VARIABLE_RESPONSE_HEADERS, nil
	case "GEO":
		return VARIABLE_GEO, nil
	case "REQUEST_COOKIES_NAMES":
		return VARIABLE_REQUEST_COOKIES_NAMES, nil
	case "FILES_TMPNAMES":
		return VARIABLE_FILES_TMPNAMES, nil
	case "ARGS_NAMES":
		return VARIABLE_ARGS_NAMES, nil
	case "ARGS_GET_NAMES":
		return VARIABLE_ARGS_GET_NAMES, nil
	case "ARGS_POST_NAMES":
		return VARIABLE_ARGS_POST_NAMES, nil
	case "RULE":
		return VARIABLE_RULE, nil
	case "XML":
		return VARIABLE_XML, nil
	case "TX":
		return VARIABLE_TX, nil
	case "DURATION":
		return VARIABLE_DURATION, nil
	case "JSON":
		return VARIABLE_JSON, nil
	case "ENV":
		return VARIABLE_ENV, nil
	case "HIGHEST_SEVERITY":
		return VARIABLE_HIGHEST_SEVERITY, nil
	case "STATUS_LINE":
		return VARIABLE_STATUS_LINE, nil
	case "IP":
		return VARIABLE_IP, nil
	}
	return 0, errors.New("Invalid variable " + name)
}

// Name transforms a VARIABLE representation
// into a string, it's used for audit and logging
func (v RuleVariable) Name() string {
	switch v {
	case VARIABLE_URLENCODED_ERROR:
		return "URLENCODED_ERROR"
	case VARIABLE_RESPONSE_CONTENT_TYPE:
		return "RESPONSE_CONTENT_TYPE"
	case VARIABLE_UNIQUE_ID:
		return "UNIQUE_ID"
	case VARIABLE_ARGS_COMBINED_SIZE:
		return "ARGS_COMBINED_SIZE"
	case VARIABLE_AUTH_TYPE:
		return "AUTH_TYPE"
	case VARIABLE_FILES_COMBINED_SIZE:
		return "FILES_COMBINED_SIZE"
	case VARIABLE_FULL_REQUEST:
		return "FULL_REQUEST"
	case VARIABLE_FULL_REQUEST_LENGTH:
		return "FULL_REQUEST_LENGTH"
	case VARIABLE_INBOUND_DATA_ERROR:
		return "INBOUND_DATA_ERROR"
	case VARIABLE_MATCHED_VAR:
		return "MATCHED_VAR"
	case VARIABLE_MATCHED_VAR_NAME:
		return "MATCHED_VAR_NAME"
	case VARIABLE_MULTIPART_BOUNDARY_QUOTED:
		return "MULTIPART_BOUNDARY_QUOTED"
	case VARIABLE_MULTIPART_BOUNDARY_WHITESPACE:
		return "MULTIPART_BOUNDARY_WHITESPACE"
	case VARIABLE_MULTIPART_CRLF_LF_LINES:
		return "MULTIPART_CRLF_LF_LINES"
	case VARIABLE_MULTIPART_DATA_AFTER:
		return "MULTIPART_DATA_AFTER"
	case VARIABLE_MULTIPART_DATA_BEFORE:
		return "MULTIPART_DATA_BEFORE"
	case VARIABLE_MULTIPART_FILE_LIMIT_EXCEEDED:
		return "MULTIPART_FILE_LIMIT_EXCEEDED"
	case VARIABLE_MULTIPART_HEADER_FOLDING:
		return "MULTIPART_HEADER_FOLDING"
	case VARIABLE_MULTIPART_INVALID_HEADER_FOLDING:
		return "MULTIPART_INVALID_HEADER_FOLDING"
	case VARIABLE_MULTIPART_INVALID_PART:
		return "MULTIPART_INVALID_PART"
	case VARIABLE_MULTIPART_INVALID_QUOTING:
		return "MULTIPART_INVALID_QUOTING"
	case VARIABLE_MULTIPART_LF_LINE:
		return "MULTIPART_LF_LINE"
	case VARIABLE_MULTIPART_MISSING_SEMICOLON:
		return "MULTIPART_MISSING_SEMICOLON"
	case VARIABLE_MULTIPART_STRICT_ERROR:
		return "MULTIPART_STRICT_ERROR"
	case VARIABLE_MULTIPART_UNMATCHED_BOUNDARY:
		return "MULTIPART_UNMATCHED_BOUNDARY"
	case VARIABLE_OUTBOUND_DATA_ERROR:
		return "OUTBOUND_DATA_ERROR"
	case VARIABLE_PATH_INFO:
		return "PATH_INFO"
	case VARIABLE_QUERY_STRING:
		return "QUERY_STRING"
	case VARIABLE_REMOTE_ADDR:
		return "REMOTE_ADDR"
	case VARIABLE_REMOTE_HOST:
		return "REMOTE_HOST"
	case VARIABLE_REMOTE_PORT:
		return "REMOTE_PORT"
	case VARIABLE_REQBODY_ERROR:
		return "REQBODY_ERROR"
	case VARIABLE_REQBODY_ERROR_MSG:
		return "REQBODY_ERROR_MSG"
	case VARIABLE_REQBODY_PROCESSOR_ERROR:
		return "REQBODY_PROCESSOR_ERROR"
	case VARIABLE_REQBODY_PROCESSOR_ERROR_MSG:
		return "REQBODY_PROCESSOR_ERROR_MSG"
	case VARIABLE_REQBODY_PROCESSOR:
		return "REQBODY_PROCESSOR"
	case VARIABLE_REQUEST_BASENAME:
		return "REQUEST_BASENAME"
	case VARIABLE_REQUEST_BODY:
		return "REQUEST_BODY"
	case VARIABLE_REQUEST_BODY_LENGTH:
		return "REQUEST_BODY_LENGTH"
	case VARIABLE_REQUEST_FILENAME:
		return "REQUEST_FILENAME"
	case VARIABLE_REQUEST_LINE:
		return "REQUEST_LINE"
	case VARIABLE_REQUEST_METHOD:
		return "REQUEST_METHOD"
	case VARIABLE_REQUEST_PROTOCOL:
		return "REQUEST_PROTOCOL"
	case VARIABLE_REQUEST_URI:
		return "REQUEST_URI"
	case VARIABLE_REQUEST_URI_RAW:
		return "REQUEST_URI_RAW"
	case VARIABLE_RESPONSE_BODY:
		return "RESPONSE_BODY"
	case VARIABLE_RESPONSE_CONTENT_LENGTH:
		return "RESPONSE_CONTENT_LENGTH"
	case VARIABLE_RESPONSE_PROTOCOL:
		return "RESPONSE_PROTOCOL"
	case VARIABLE_RESPONSE_STATUS:
		return "RESPONSE_STATUS"
	case VARIABLE_SERVER_ADDR:
		return "SERVER_ADDR"
	case VARIABLE_SERVER_NAME:
		return "SERVER_NAME"
	case VARIABLE_SERVER_PORT:
		return "SERVER_PORT"
	case VARIABLE_SESSIONID:
		return "SESSIONID"
	case VARIABLE_RESPONSE_HEADERS_NAMES:
		return "RESPONSE_HEADERS_NAMES"
	case VARIABLE_REQUEST_HEADERS_NAMES:
		return "REQUEST_HEADERS_NAMES"
	case VARIABLE_USERID:
		return "USERID"
	case VARIABLE_ARGS:
		return "ARGS"
	case VARIABLE_ARGS_GET:
		return "ARGS_GET"
	case VARIABLE_ARGS_POST:
		return "ARGS_POST"
	case VARIABLE_FILES_SIZES:
		return "FILES_SIZES"
	case VARIABLE_FILES_NAMES:
		return "FILES_NAMES"
	case VARIABLE_FILES_TMP_CONTENT:
		return "FILES_TMP_CONTENT"
	case VARIABLE_MULTIPART_FILENAME:
		return "MULTIPART_FILENAME"
	case VARIABLE_MULTIPART_NAME:
		return "MULTIPART_NAME"
	case VARIABLE_MATCHED_VARS_NAMES:
		return "MATCHED_VARS_NAMES"
	case VARIABLE_MATCHED_VARS:
		return "MATCHED_VARS"
	case VARIABLE_FILES:
		return "FILES"
	case VARIABLE_REQUEST_COOKIES:
		return "REQUEST_COOKIES"
	case VARIABLE_REQUEST_HEADERS:
		return "REQUEST_HEADERS"
	case VARIABLE_RESPONSE_HEADERS:
		return "RESPONSE_HEADERS"
	case VARIABLE_GEO:
		return "GEO"
	case VARIABLE_REQUEST_COOKIES_NAMES:
		return "REQUEST_COOKIES_NAMES"
	case VARIABLE_FILES_TMPNAMES:
		return "FILES_TMPNAMES"
	case VARIABLE_ARGS_NAMES:
		return "ARGS_NAMES"
	case VARIABLE_ARGS_GET_NAMES:
		return "ARGS_GET_NAMES"
	case VARIABLE_ARGS_POST_NAMES:
		return "ARGS_POST_NAMES"
	case VARIABLE_TX:
		return "TX"
	case VARIABLE_DURATION:
		return "DURATION"
	case VARIABLE_RULE:
		return "RULE"
	case VARIABLE_JSON:
		return "JSON"
	case VARIABLE_XML:
		return "XML"
	case VARIABLE_ENV:
		return "ENV"
	case VARIABLE_HIGHEST_SEVERITY:
		return "HIGHEST_SEVERITY"
	case VARIABLE_STATUS_LINE:
		return "STATUS_LINE"
	case VARIABLE_IP:
		return "IP"
	}
	return ""
}
