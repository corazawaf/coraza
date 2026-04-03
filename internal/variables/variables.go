// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run generator/main.go

// Package variables contains the representation of the variables used in the rules
// Variables are created as bytes, and they have a string representation
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
	// Description: Response content type. Available only starting with phase 3. The value
	// is extracted from the Content-Type response header, with parameters (e.g. charset) stripped.
	// It is equivalent to using RESPONSE_HEADERS:Content-Type, but without the parameter suffix.
	ResponseContentType
	// Description: This variable holds the unique id for the transaction.
	UniqueID
	// Description: Contains the combined size of all request parameters. Files are excluded
	// from the calculation. This variable can be useful, for example, to create a rule to
	// ensure that the total size of the argument data is below a certain threshold. The
	// following rule detects a request whose parameters are more than 2500 bytes long:
	// ---
	// ```seclang
	// SecRule ARGS_COMBINED_SIZE "@gt 2500" "id:12"
	// ````
	ArgsCombinedSize
	// Description: Contains the total size of the files transported in request body. Available
	// only on inspected multipart/form-data requests.
	// ---
	// ```seclang
	// SecRule FILES_COMBINED_SIZE "@gt 100000" "id:18"
	// ```
	FilesCombinedSize
	// Description: Represents the amount of bytes that FULL_REQUEST may use.
	// ---
	// ```seclang
	// SecRule FULL_REQUEST_LENGTH "@eq 205" "id:21"
	// ```
	FullRequestLength
	// Description: This variable will be set to 1 when the request body size is above the
	// setting configured by **SecRequestBodyLimit** directive. Your policies should always
	// contain a rule to check this variable. Depending on the rate of false positives and
	// your default policy you should decide whether to block or just warn when the rule is
	// triggered.
	//
	// The behavior depends on SecRequestBodyLimitAction:
	//   - ProcessPartial: the body is truncated at the limit, INBOUND_DATA_ERROR is set to 1,
	//     and Phase 2 rules run on the partial body. Rules can inspect this variable.
	//   - Reject (default): INBOUND_DATA_ERROR is set to 1 but the transaction is interrupted
	//     immediately before Phase 2 rules can run. The error is propagated as an interruption
	//     (status 413) to the connector; the variable is effectively inaccessible to rules.
	//
	// This variable is therefore only actionable in rules when SecRequestBodyLimitAction
	// is set to ProcessPartial.
	// ---
	// The best way to use this variable is as in the example below (requires ProcessPartial):
	//
	// ```seclang
	// SecRule INBOUND_DATA_ERROR "@eq 1" "phase:2,id:24,t:none,log,pass,msg:'Request Body Larger than SecRequestBodyLimit Setting'"
	// ```
	InboundDataError
	// Description: This variable holds the value of the most-recently matched variable. It is
	// similar to the TX:0, but it is automatically supported by all operators and there is no
	// need to specify the capture action.
	// ---
	// ```seclang
	// SecRule ARGS pattern chain,deny,id:25
	//   SecRule MATCHED_VAR "further scrutiny"
	// ```
	//
	// **Note :** Be aware that this variable holds data for the last operator match. This means that if there are more than one matches, only the last one will be populated. Use MATCHED_VARS variable if you want all matches.
	MatchedVar
	// Description: This variable holds the full name of the variable that was matched against.
	// ---
	// ```seclang
	// SecRule ARGS pattern "chain,deny,id:27"
	//   SecRule MATCHED_VAR_NAME "@eq ARGS:param"
	// ```
	//
	// **Note :** Be aware that this variable holds data for the last operator match. This means that if there are more than one matches, only the last one will be populated. Use MATCHED_VARS_NAMES variable if you want all matches.
	MatchedVarName
	// MultipartDataAfter is kept for compatibility
	MultipartDataAfter
	// Description: This variable will be set to 1 when the response body size exceeds the
	// limit configured by the SecResponseBodyLimit directive.
	//
	// The behavior depends on SecResponseBodyLimitAction:
	//   - ProcessPartial: the body is truncated at the limit, OUTBOUND_DATA_ERROR is set to 1,
	//     and Phase 4 rules run on the partial body. Rules can inspect this variable to log or
	//     block the truncated response.
	//   - Reject (default): OUTBOUND_DATA_ERROR is set to 1 but the transaction is interrupted
	//     immediately with a 500 error before Phase 4 rules can run. The error is propagated as
	//     an interruption to the connector; the variable is effectively inaccessible to rules.
	//
	// This variable is therefore only actionable in rules when SecResponseBodyLimitAction
	// is set to ProcessPartial.
	// ---
	// Example rule to deny when the response body exceeds the configured limit (requires ProcessPartial):
	//
	// ```seclang
	// SecRule OUTBOUND_DATA_ERROR "@eq 1" "phase:4,id:32,t:none,deny,status:413,msg:'Response Body Larger than SecResponseBodyLimit Setting'"
	// ```
	OutboundDataError
	// Description: Contains the query string part of a request URI. The value in QUERY_STRING
	// is always provided raw, without URL decoding taking place.
	// ---
	// ```seclang
	// SecRule QUERY_STRING "attack" "id:34"
	// ```
	QueryString
	// Description: This variable holds the IP address of the remote client.
	// ---
	// ```seclang
	// SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" "phase:1,id:35,log,pass,msg:'Request from a specific IP address'"
	// ```
	RemoteAddr
	// RemoteHost kept for compatibility
	RemoteHost
	// Description: This variable holds information on the source port that the client used when
	// initiating the connection.
	// ---
	// The example evaluates whether the REMOTE_PORT is less than 1024, which would indicate that the user is a privileged user:
	//
	// ```seclang
	// SecRule REMOTE_PORT "@lt 1024" "phase:1,id:37,log, pass,msg:'Request from a privileged User'"
	// ```
	RemotePort
	// Description: Contains the status of the request body processor used for request body
	// parsing. The values can be 0 (no error) or 1 (error). This variable will be set by
	// request body processors (typically the multipart/request-data parser, JSON or the XML
	// parser) when they fail to do their work.
	// ---
	// ```seclang
	// SecRule REQBODY_ERROR "@eq 1" "phase:2,id:39,deny,log,msg:'Request Body Processor Error Detected'"
	// ```
	//
	// **Note :** Your policies must have a rule to check for request body processor errors at the very beginning of phase 2. Failure to do so will leave the door open for impedance mismatch attacks. It is possible, for example, that a payload that cannot be parsed by Coraza can be successfully parsed by more tolerant parser operating in the application. If your policy dictates blocking, then you should reject the request if error is detected. When operating in detection-only mode, your rule should alert with high severity when request body processing fails.
	ReqbodyError
	// Description: If there's been an error during request body parsing, the variable will
	// contain the following error message:
	// ---
	// ```seclang
	// SecRule REQBODY_ERROR_MSG "failed to parse" "id:40"
	// ```
	ReqbodyErrorMsg
	// Description: Same as REQBODY_ERROR, set to 1 when the request body processor fails.
	// Unlike REQBODY_ERROR_MSG, the corresponding error message in REQBODY_PROCESSOR_ERROR_MSG
	// contains only the raw error string without the processor name prefix.
	ReqbodyProcessorError
	// Description: Same as REQBODY_ERROR_MSG, but contains only the raw error string from
	// the body processor, without the processor name prepended.
	ReqbodyProcessorErrorMsg
	// Description: Contains the name of the currently used request body processor. The default
	// possible values are URLENCODED, MULTIPART, XML, JSON, and RAW.
	// ---
	// ```seclang
	// SecRule REQBODY_PROCESSOR "^XML$" "chain,id:41"
	//   SecRule XML://* "something" "t:none"
	// ```
	ReqbodyProcessor
	// Description: Holds the filename part of REQUEST_FILENAME (e.g., index.php).
	// ---
	// Anti-evasion transformations are NOT applied to this variable by default. REQUEST_BASENAME will
	// recognize both / and \ as path separators. The value of this variable depends on what was provided
	// in request. It does not have to correspond to the resource (on disk) that will be used by the web server.
	// ```seclang
	// SecRule REQUEST_BASENAME "^login\.php$" "phase:2,id:42,pass,t:none,t:lowercase"
	// ```
	RequestBasename
	// Description: Holds the raw request body. It is populated only by the URLENCODED and RAW
	// body processors. MULTIPART, XML, and JSON processors parse the body into their own
	// collections and do not populate this variable.
	// ```ctl:forceRequestBodyVariable=on``` can be used in the REQUEST_HEADERS phase to force
	// the population of this variable by setting URLENCODED as the processor when no processor
	// would otherwise be selected.
	// ---
	// ```seclang
	// SecRule REQUEST_BODY "@contains foo" "id:1001,phase:2,deny,log"
	// ```
	//
	// **Note :** Requires request body buffering to be enabled.
	RequestBody
	// Description: Contains the number of bytes read from the request body. The calculation
	// is based on the actual body buffer size, not on the content-length header.
	RequestBodyLength
	// Description: Holds the relative request URL without the query string part
	// (e.g., /index.php).
	// ---
	// ```seclang
	// SecRule REQUEST_FILENAME "^/cgi-bin/login\.php$" phase:2,id:46,t:none,t:normalizePath
	// ```
	//
	// **Note :** Anti-evasion transformations are not used on REQUEST_FILENAME. You will have to specify them in the rules that use this variable.
	RequestFilename
	// Description: Holds the complete request line sent to the server (including
	// the request method and HTTP version information).
	// ---
	// ```seclang
	// # Allow only POST, GET and HEAD request methods, as well as only
	// # the valid protocol versions
	// SecRule REQUEST_LINE "!(^((?:(?:POS|GE)T|HEAD))|HTTP/(0\.9|1\.0|1\.1)$)" "phase:1,id:49,log,block,t:none"
	// ```
	RequestLine
	// Description: Holds the request method used in the transaction.
	// ---
	// ```seclang
	// SecRule REQUEST_METHOD "^(?:CONNECT|TRACE)$" "id:50,t:none,deny,log,msg:'Suspicious HTTP method used'"
	// ```
	RequestMethod
	// Description: Holds the request protocol version information.
	// ---
	// ```seclang
	// SecRule REQUEST_PROTOCOL "!^HTTP/(0\.9|1\.0|1\.1)$" "id:51,t:none,deny,log,msg:'Suspicious HTTP protocol version used'"
	// ```
	RequestProtocol
	// Description: Holds the full request URL including the query string data. It is the
	// parsed and normalized form of REQUEST_URI_RAW: fragments are stripped and the URL is
	// reconstructed from the parsed components. If parsing fails, the raw URI is used as-is.
	// ---
	// ```seclang
	// SecRule REQUEST_URI "attack" "phase:1,id:52,t:none,t:urlDecode,t:lowercase,t:normalizePath,deny"
	// ```
	//
	// **Note :** Anti-evasion transformations are not used on REQUEST_URI. You will have to specify them in the rules that use this variable.
	RequestURI
	// Description: Holds the raw request URI exactly as received on the request line, before
	// any parsing or normalization. This includes the domain name if the client sent an
	// absolute URI (e.g., http://www.example.com/index.php?p=X).
	// ---
	// ```seclang
	// SecRule REQUEST_URI_RAW "^http://" "phase:1,id:53,t:none,t:urlDecode,t:lowercase,t:normalizePath"
	// ```
	//
	// **Note :** Anti-evasion transformations are not used on REQUEST_URI_RAW. You will have to specify them in the rules that use this variable.
	RequestURIRaw
	// Description: Holds the data for the response body. Populated only when no response
	// body processor is active. When a processor (e.g. XML) is used, the body is parsed
	// into the processor's own collections instead.
	// By default, buffering only occurs for MIME types listed in SecResponseBodyMimeType.
	// ```ctl:forceResponseBodyVariable=on``` bypasses this MIME type check, forcing buffering
	// regardless of the Content-Type.
	// ---
	// ```seclang
	// SecRule RESPONSE_BODY "ODBC Error Code" "phase:4,id:54,t:none, deny"
	// ```
	//
	// **Note :** Requires response body buffering to be enabled.
	ResponseBody
	// Description: Response body length in bytes. Available starting from phase 4 only when
	// response body buffering is enabled and no response body processor is active. If a body
	// processor (e.g. XML) is used, this variable will not be populated.
	//
	// **Note :** Requires response body buffering to be enabled.
	ResponseContentLength
	// Description: Holds the HTTP response protocol information.
	// ---
	// ```seclang
	// SecRule RESPONSE_PROTOCOL "^HTTP\/0\.9" "phase:3,id:57,t:none"
	// ```
	ResponseProtocol
	// Description: Holds the HTTP response status code returned by the backend.
	// Available starting from phase 3.
	// ---
	// ```seclang
	// SecRule RESPONSE_STATUS "^[45]" "phase:3,id:58,t:none,pass,log,msg:'Response status matches 4xx or 5xx'"
	// ```
	ResponseStatus
	// Description: Contains the IP address of the server.
	// ---
	// ```seclang
	// SecRule SERVER_ADDR "@ipMatch 192.168.1.100" "phase:1,id:67,log,pass,msg:'Request to a specific IP address'"
	// ```
	ServerAddr
	// Description: Contains the server hostname or IP address. Since it originates from
	// the client-supplied Host header, it should NOT be implicitly trusted.
	// ---
	// ```seclang
	// SecRule SERVER_NAME "hostname\.com$" "phase:1,id:68,log,pass,msg:'Request to a specific hostname'"
	// ```
	ServerName
	// Description: Contains the target port of the request.
	// ---
	// ```seclang
	// SecRule SERVER_PORT "^80$" "phase:1,id:69,log,pass,msg:'Request to a specific port'"
	// ```
	ServerPort
	// Description: Holds the highest severity of any rules that have matched so
	// far. Severities are numeric values and thus can be used with comparison operators such as
	// @lt, and so on. A value of 255 indicates that no severity has been set.
	// ---
	// ```seclang
	// SecRule HIGHEST_SEVERITY "@le 2" "phase:2,id:23,deny,status:500,msg:'severity %{HIGHEST_SEVERITY}'"
	// ```
	//
	// **Note :** Higher severities have a lower numeric value.
	HighestSeverity
	// Description: Holds the full response status line sent by the backend server.
	// (e.g., `HTTP/1.1 200 OK`).
	// ---
	// ```seclang
	// # Generate an alert when the application returns 500 error.
	// SecRule STATUS_LINE "@contains 500" "phase:3,id:49,log,pass,logdata:'Application error detected!',t:none"
	//
	//
	// **Note:** This variable is currently NOT implemented by Coraza, but only kept for compatibility.
	StatusLine
	// Description: Contains the number of microseconds elapsed since the beginning of the
	// current transaction.
	//
	// **Note:** This variable is currently NOT implemented by Coraza, but only kept for compatibility.
	Duration
	// Description: Collection of the response header names.
	// ---
	// ```seclang
	// SecRule RESPONSE_HEADERS_NAMES "Set-Cookie" "phase:3,id:56,t:none,log,pass,msg:'Response contains Set-Cookie header'"
	// ```
	//
	// The same limitations apply as the ones discussed in RESPONSE_HEADERS.
	ResponseHeadersNames // CanBeSelected
	// Description: Collection of the names of all of the request headers.
	// ---
	// ```seclang
	// SecRule REQUEST_HEADERS_NAMES "^x-forwarded-for" "log,deny,id:48,status:403,t:lowercase,msg:'Proxy Server Used'"
	// ```
	RequestHeadersNames // CanBeSelected
	// Description: Collection of all request arguments, including both query string and
	// request body parameters. To inspect only query string or body arguments, see ARGS_GET
	// and ARGS_POST.
	// ---
	// Match all arguments:
	//
	// ```seclang
	// SecRule ARGS "dirty" "id:7"
	// ```
	//
	// Match only the argument named p:
	//
	// ```seclang
	// SecRule ARGS:p "dirty" "id:8"
	// ```
	//
	// Match all arguments except those named z:
	//
	// ```seclang
	// SecRule ARGS|!ARGS:z "dirty" "id:9"
	// ```
	//
	// Count the number of arguments (triggers if more than zero):
	//
	// ```seclang
	// SecRule &ARGS "!^0$" "id:10"
	// ```
	//
	// Match arguments whose names begin with id_:
	//
	// ```seclang
	// SecRule ARGS:/^id_/ "dirty" "id:11"
	// ```
	//
	// **Note :** Using ```ARGS:p``` will not result in any invocations against the operator if argument p does not exist.
	Args // CanBeSelected
	// Description: **ARGS_GET** is similar to ARGS, but contains only query string parameters.
	ArgsGet // CanBeSelected
	// Description: **ARGS_POST** is similar to **ARGS**, but only contains arguments from the
	// POST body.
	ArgsPost // CanBeSelected
	// Description: Contains the URL path components as individual items. Useful for matching
	// specific path segments without needing to parse the full URL.
	ArgsPath // CanBeSelected
	// Description: Contains a list of individual file sizes. Useful for implementing a size
	// limitation on individual uploaded files. Available only on inspected multipart/form-data
	// requests.
	// ---
	// ```seclang
	// SecRule FILES_SIZES "@gt 100" "id:20"
	// ```
	FilesSizes // CanBeSelected
	// Description: Contains a list of form fields that were used for file upload. Available only
	// on inspected multipart/form-data requests.
	// ---
	// ```seclang
	// SecRule FILES_NAMES "^upfile$" "id:19"
	// ```
	FilesNames // CanBeSelected
	// Description: Contains a key-value set where value is the content of the file which was
	// uploaded. Useful when used together with @fuzzyHash.
	// ---
	// ```seclang
	// SecRule FILES_TMP_CONTENT "@fuzzyHash $ENV{CONF_DIR}/ssdeep.txt 1" "id:192372,log,deny"
	// ```
	//
	// **Note :** SecUploadKeepFiles must be set to 'On' in order to have this collection filled.
	// **Note:** This variable is currently NOT implemented by Coraza
	FilesTmpContent // CanBeSelected
	// Description: This variable contains the multipart data from field FILENAME.
	//
	// **Note:** This variable is currently NOT implemented by Coraza
	MultipartFilename // CanBeSelected
	// Description: This variable contains the multipart data from field NAME.
	//
	// **Note:** This variable is currently NOT implemented by Coraza
	MultipartName // CanBeSelected
	// Description: Similar to MATCHED_VAR_NAME except that it is a collection of all variable
	// names that matched during the current operator check.
	// ---
	// ```seclang
	// SecRule ARGS "pattern" "chain,deny,id:28"
	//   SecRule MATCHED_VARS_NAMES "@eq ARGS:param" "t:none"
	// ```
	MatchedVarsNames // CanBeSelected
	// Description: Similar to MATCHED_VAR except that it is a collection of all values
	// that matched during the current operator check.
	// ---
	// ```seclang
	// SecRule ARGS "pattern" "chain,deny,id:26"
	//   SecRule MATCHED_VARS "@eq somevalue" "t:none"
	// ```
	MatchedVars // CanBeSelected
	// Description: Contains the original filenames as submitted by the client in the multipart
	// upload (the filename field of Content-Disposition). Available only on inspected multipart/form-data requests.
	// ---
	// ```seclang
	// SecRule FILES "@rx \.conf$" "id:17"
	// ```
	Files // CanBeSelected
	// Description: This variable is a collection of all of request cookies (values only).
	// ---
	// Example: the following example is using the Ampersand special operator to count how many variables are in the collection. In this rule, it would trigger if the request does not include any Cookie headers.
	//
	// ```seclang
	// SecRule &REQUEST_COOKIES "@eq 0" "id:44"
	// ```
	RequestCookies // CanBeSelected
	// Description: This variable can be used as either a collection of all of the request
	// headers or can be used to inspect selected headers (by using the
	// REQUEST_HEADERS:Header-Name syntax).
	// ---
	// ```seclang
	// SecRule REQUEST_HEADERS:Host "^[\d\.]+$" "deny,id:47,log,status:400,msg:'Host header is a numeric IP address'"
	// ```
	//
	// **Note:** Coraza will treat multiple headers that have identical names as a "list", processing each single value.
	RequestHeaders // CanBeSelected
	// Description: This variable refers to response headers, in the same way as
	// REQUEST_HEADERS does to request headers.
	// ---
	// ```seclang
	// SecRule RESPONSE_HEADERS:X-Cache "MISS" "id:55"
	// ```
	ResponseHeaders // CanBeSelected
	// Description: Contains the name of the currently used response body processor (e.g., XML).
	ResBodyProcessor
	// Description: Collection intended to be populated by the @geoLookup operator with
	// geographical data for a given IP address. Fields include COUNTRY_CODE, COUNTRY_NAME,
	// COUNTRY_CONTINENT, REGION, CITY, POSTAL_CODE, LATITUDE, LONGITUDE.
	// ---
	// ```seclang
	// SecRule REMOTE_ADDR "@geoLookup" "phase:1,id:22,nolog,pass"
	// SecRule GEO:COUNTRY_CODE "!@streq GB" "id:23,deny,log,msg:'Non-GB IP address'"
	// ```
	//
	// **Note:** Requires coraza-geoip plugin.
	Geo // CanBeSelected
	// Description: This variable is a collection of the names of all request cookies. For
	// example, the following rule will trigger if the JSESSIONID cookie is not present:
	// ---
	// ```seclang
	// SecRule &REQUEST_COOKIES_NAMES:JSESSIONID "@eq 0" "id:45"
	// ```
	RequestCookiesNames // CanBeSelected
	// Description: Contains a list of temporary files' names on the disk. Useful when used
	// together with @inspectFile. Available only on inspected multipart/form-data requests.
	// ---
	// ```seclang
	// SecRule FILES_TMPNAMES "@inspectFile /path/to/inspect_script.pl" "id:21"
	// ```
	FilesTmpNames // CanBeSelected
	// Description: Contains all request parameter names. You can search for specific parameter
	// names that you want to inspect. In a positive policy scenario, you can also allowlist
	// (using an inverted rule with the exclamation mark) only the authorized argument names.
	// This example rule allows only two argument names: p and a:
	// ---
	// ```seclang
	// SecRule ARGS_NAMES "!^(p|a)$" "id:13"
	// ```
	ArgsNames // CanBeSelected
	// Description: **ARGS_GET_NAMES** is similar to **ARGS_NAMES**, but contains only the
	// names of query string parameters.
	ArgsGetNames // CanBeSelected
	// Description: **ARGS_POST_NAMES** is similar to **ARGS_NAMES**, but contains only the
	// names of request body parameters.
	ArgsPostNames // CanBeSelected
	// Description: Transient transaction collection used to store arbitrary data for the
	// duration of the transaction, such as anomaly scores or state flags.
	// ---
	// ```seclang
	// # Increment transaction attack score on attack
	// SecRule ARGS "attack" "phase:2,id:82,nolog,pass,setvar:TX.score=+5"
	//
	// # Block the transactions whose scores are too high
	// SecRule TX:SCORE "@gt 20" "phase:2,id:83,log,deny"
	// ```
	//
	// Some variable names in the TX collection are reserved:
	//
	// - **TX:0:** the matching value when using the @rx or @pm operator with the capture action
	// - **TX:1-TX:9:** the captured subexpression values when using the @rx operator with capturing groups
	TX // CanBeSelected
	// Description: This is a special collection that provides access to the id, rev, severity,
	// logdata, and msg fields of the rule that triggered the action. It can be used to refer to
	// only the same rule in which it resides.
	// ---
	// ```seclang
	// SecRule &REQUEST_HEADERS:Host "@eq 0" "log,deny,id:59,setvar:tx.varname=%{RULE.id}"
	// ```
	Rule // CanBeSelected
	// JSON kept for compatibility, does not provide any data.
	JSON // CanBeSelected
	// Description: Collection that provides access to environment variables set via the
	// `setenv` action. Requires a single parameter to specify the name of the desired variable.
	// ---
	// ```seclang
	// # Set environment variable
	// SecRule REQUEST_FILENAME "printenv" \
	// "phase:2,id:15,pass,setenv:tag=suspicious"
	//
	// # Inspect environment variable
	// SecRule ENV:tag "suspicious" "id:16"
	// ```
	Env // CanBeSelected
	// Description: This variable is created when an invalid URL encoding is encountered during
	// the parsing of a query string (on every request) or during the parsing of an
	// application/x-www-form-urlencoded request body (only on the requests that use the
	// URLENCODED request body processor).
	UrlencodedError
	// ResponseArgs contains the response parsed arguments
	ResponseArgs // CanBeSelected
	// Description: Collection for interacting with the response XML body via XPath expressions.
	//
	// **Not Implemented yet**
	ResponseXML // CanBeSelected
	// RequestXML contains the request body parsed as XML. Populated by the XML body processor.
	RequestXML // CanBeSelected
	// Description: Special collection used to interact with the XML parser. It must contain a
	// valid XPath expression, which will then be evaluated against a previously parsed XML DOM
	// tree. Requires the XML body processor to be active.
	// ---
	// ```seclang
	// SecRule REQUEST_HEADERS:Content-Type "^text/xml$" "phase:1,id:87,t:lowercase,nolog,pass,ctl:requestBodyProcessor=XML"
	// SecRule XML:/employees/employee/name "Fred" "phase:2,id:88,deny,log"
	// ```
	//
	// It would match against payload such as this one:
	//
	// ```xml
	// <employees>
	//     <employee>
	//         <name>Fred Jones</name>
	//         <address location="home">
	//             <street>900 Aurora Ave.</street>
	//             <city>Seattle</city>
	//             <state>WA</state>
	//             <zip>98115</zip>
	//         </address>
	//         <address location="work">
	//             <street>2011 152nd Avenue NE</street>
	//             <city>Redmond</city>
	//             <state>WA</state>
	//             <zip>98052</zip>
	//         </address>
	//         <phone location="work">(425)555-5665</phone>
	//         <phone location="home">(206)555-5555</phone>
	//         <phone location="mobile">(206)555-4321</phone>
	//     </employee>
	// </employees>
	// ```
	XML // CanBeSelected
	// MultipartPartHeaders contains the multipart headers
	MultipartPartHeaders // CanBeSelected
	// ResBodyError is set to 1 when the response body processor fails.
	ResBodyError
	// ResBodyErrorMsg contains the response body processor error message, prefixed with the processor name.
	ResBodyErrorMsg
	// ResBodyProcessorError is set to 1 when the response body processor fails.
	// Unlike ResBodyError, the corresponding message in ResBodyProcessorErrorMsg contains only the raw error string.
	ResBodyProcessorError
	// ResBodyProcessorErrorMsg contains the raw error string from the response body processor, without the processor name prefix.
	ResBodyProcessorErrorMsg
	// Description: This variable holds a formatted string representing the time
	// (hour:minute:second).
	// ---
	// ```seclang
	// SecRule TIME "^(([1](8|9))|([2](0|1|2|3))):\d{2}:\d{2}$" "id:74"
	// ```
	Time
	// Description: This variable holds the current date (1–31). The following rule triggers on
	// a transaction that's happening anytime between the 10th and 20th in a month:
	// ---
	// ```seclang
	// SecRule TIME_DAY "^(([1](0|1|2|3|4|5|6|7|8|9))|20)$" "id:75"
	// ```
	TimeDay
	// Description: This variable holds the time in seconds since 1970.
	TimeEpoch
	// Description: This variable holds the current hour value (0–23). The following rule
	// triggers when a request is made "off hours":
	// ---
	// ```seclang
	// SecRule TIME_HOUR "^(0|1|2|3|4|5|6|[1](8|9)|[2](0|1|2|3))$" "id:76"
	// ```
	TimeHour
	// Description: This variable holds the current minute value (0–59). The following rule
	// triggers during the last half hour of every hour:
	// ---
	// ```seclang
	// SecRule TIME_MIN "^(3|4|5)" "id:77"
	// ```
	TimeMin
	// Description: This variable holds the current month value (0–11). The following rule
	// matches if the month is either November (value 10) or December (value 11):
	// ---
	// ```seclang
	// SecRule TIME_MON "^1" "id:78"
	// ```
	TimeMon
	// Description: This variable holds the current second value (0–59).
	// ---
	// ```seclang
	// SecRule TIME_SEC "@gt 30" "id:79"
	// ```
	TimeSec
	// Description: This variable holds the current weekday value (0–6). The following rule
	// triggers only on Saturday and Sunday:
	// ---
	// ```seclang
	// SecRule TIME_WDAY "^(0|6)$" "id:80"
	// ```
	TimeWday
	// Description: This variable holds the current four-digit year value.
	// ---
	// ```seclang
	// SecRule TIME_YEAR "^2006$" "id:81"
	// ```
	TimeYear

	// Unsupported variables. Variables comments are not starting with "Description" so that they are not
	// included in the documentation.

	// Holds the authentication method used to validate a user
	AuthType
	// Contains the full request including the request line, headers, and body.
	// The maximum size is determined by FULL_REQUEST_LENGTH.
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
	// Contains the extra request URI information, also known as path info. (For
	// example, in the URI /index.php/123, /123 is the path info.) Available only in embedded
	// deployments.
	PathInfo
	// Contains the value set with setsid. See SESSION for a
	// complete example.
	Sessionid
	// Contains the value set with setuid.
	// ---
	// ```seclang
	// # Initialize user tracking
	// SecAction "nolog,id:84,pass,setuid:%{REMOTE_USER}"
	//
	// # Is the current user the administrator?
	// SecRule USERID "admin" "id:85"
	// ```
	Userid
	// IP is kept for compatibility
	IP
)
