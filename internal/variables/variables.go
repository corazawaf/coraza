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
	// available in this variable is taken directly from the internal structures of Apache,
	// which means that it may contain the information that is not yet available in response
	// headers. In embedded deployments, you should always refer to this variable, rather than
	// to RESPONSE_HEADERS:Content-Type.
	ResponseContentType
	// Description: This variable holds the unique id for the transaction.
	UniqueID
	// Description: Contains the combined size of all request parameters. Files are excluded
	// from the calculation. This variable can be useful, for example, to create a rule to
	// ensure that the total size of the argument data is below a certain threshold. The
	// following rule detects a request whose parameters are more than 2500 bytes long:
	// ---
	// ```modsecurity
	// SecRule ARGS_COMBINED_SIZE "@gt 2500" "id:12"
	// ````
	ArgsCombinedSize
	// Description: Contains the total size of the files transported in request body. Available
	// only on inspected multipart/form-data requests.
	// ---
	// ```modsecurity
	// SecRule FILES_COMBINED_SIZE "@gt 100000" "id:18"
	// ```
	FilesCombinedSize
	// Description: Represents the amount of bytes that FULL_REQUEST may use.
	// ---
	// ```modsecurity
	// SecRule FULL_REQUEST_LENGTH "@eq 205" "id:21"
	// ```
	FullRequestLength
	// Description: This variable will be set to 1 when the request body size is above the
	// setting configured by **SecRequestBodyLimit** directive. Your policies should always
	// contain a rule to check this variable. Depending on the rate of false positives and
	// your default policy you should decide whether to block or just warn when the rule is
	// triggered.
	// ---
	// The best way to use this variable is as in the example below:
	//
	// ```modsecurity
	// SecRule INBOUND_DATA_ERROR "@eq 1" "phase:1,id:24,t:none,log,pass,msg:'Request Body Larger than SecRequestBodyLimit Setting'"
	// ```
	InboundDataError
	// Description: This variable holds the value of the most-recently matched variable. It is
	// similar to the TX:0, but it is automatically supported by all operators and there is no
	// need to specify the capture action.
	// ---
	// ```modsecurity
	// SecRule ARGS pattern chain,deny,id:25
	//   SecRule MATCHED_VAR "further scrutiny"
	// ```
	//
	// **Note :** Be aware that this variable holds data for the last operator match. This means that if there are more than one matches, only the last one will be populated. Use MATCHED_VARS variable if you want all matches.
	MatchedVar
	// Description: This variable holds the full name of the variable that was matched against.
	// ---
	// ```modsecurity
	// SecRule ARGS pattern "chain,deny,id:27"
	//   SecRule MATCHED_VAR_NAME "@eq ARGS:param"
	// ```
	//
	// **Note :** Be aware that this variable holds data for the last operator match. This means that if there are more than one matches, only the last one will be populated. Use MATCHED_VARS_NAMES variable if you want all matches.
	MatchedVarName
	// MultipartDataAfter kept for compatibility
	MultipartDataAfter
	// Description: This variable will be set to 1 when the response body size is above the
	// setting configured by SecResponseBodyLimit directive. Your policies should always contain
	// a rule to check this variable. Depending on the rate of false positives and your default
	// policy you should decide whether to block or just warn when the rule is triggered.
	// ---
	// The best way to use this variable is as in the example below:
	//
	// ```modsecurity
	// SecRule OUTBOUND_DATA_ERROR "@eq 1" "phase:1,id:32,t:none,log,pass,msg:'Response Body Larger than SecResponseBodyLimit Setting'"
	// ```
	OutboundDataError
	// Description: Contains the query string part of a request URI. The value in QUERY_STRING
	// is always provided raw, without URL decoding taking place.
	// ---
	// ```modsecurity
	// SecRule QUERY_STRING "attack" "id:34"
	// ```
	QueryString
	// Description: This variable holds the IP address of the remote client.
	// ---
	// ```modsecurity
	// SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" "id:35"
	// ```
	RemoteAddr
	// Description: If the Apache directive HostnameLookups is set to On, then this variable
	// will hold the remote hostname resolved through DNS. If the directive is set to Off,
	// this variable it will hold the remote IP address (same as REMOTE_ADDR). Possible uses
	// for this variable would be to deny known bad client hosts or network blocks, or
	// conversely, to allow in authorized hosts.
	// ---
	// ```modsecurity
	// SecRule REMOTE_HOST "\.evil\.network\org$" "id:36"
	// ```
	RemoteHost
	// Description: This variable holds information on the source port that the client used when
	// initiating the connection to our web server.
	// ---
	// In the following example, we are evaluating to see whether the REMOTE_PORT is less than 1024, which would indicate that the user is a privileged user:
	//
	// ```modsecurity
	// SecRule REMOTE_PORT "@lt 1024" "id:37"
	// ```
	RemotePort
	// Description: Contains the status of the request body processor used for request body
	// parsing. The values can be 0 (no error) or 1 (error). This variable will be set by
	// request body processors (typically the multipart/request-data parser, JSON or the XML
	// parser) when they fail to do their work.
	// ---
	// ```modsecurity
	// SecRule REQBODY_ERROR "@eq 1" deny,phase:2,id:39
	// ```
	//
	// **Note :** Your policies must have a rule to check for request body processor errors at the very beginning of phase 2. Failure to do so will leave the door open for impedance mismatch attacks. It is possible, for example, that a payload that cannot be parsed by Coraza can be successfully parsed by more tolerant parser operating in the application. If your policy dictates blocking, then you should reject the request if error is detected. When operating in detection-only mode, your rule should alert with high severity when request body processing fails.
	ReqbodyError
	// Description: If there's been an error during request body parsing, the variable will
	// contain the following error message:
	// ---
	// ```modsecurity
	// SecRule REQBODY_ERROR_MSG "failed to parse" "id:40"
	// ```
	ReqbodyErrorMsg
	// ReqbodyProcessorError is the same as ReqbodyError ?
	ReqbodyProcessorError
	// ReqbodyProcessorErrorMsg is the same as ReqbodyErrorMsg ?
	ReqbodyProcessorErrorMsg
	// Description: Contains the name of the currently used request body processor. The possible
	// values are URLENCODED, JSON, MULTIPART, and XML.
	// ---
	// ```modsecurity
	// SecRule REQBODY_PROCESSOR "^XML$ chain,id:41
	//   SecRule XML://* "something" "id:123"
	// ```
	ReqbodyProcessor
	// Description: This variable holds just the filename part of REQUEST_FILENAME (e.g.,
	// index.php).
	// ---
	// ```modsecurity
	// SecRule REQUEST_BASENAME "^login\.php$" phase:2,id:42,t:none,t:lowercase
	// ```
	//
	// **Note :** Please note that anti-evasion transformations are not applied to this variable by default. REQUEST_BASENAME will recognize both / and \ as path separators. You should understand that the value of this variable depends on what was provided in request, and that it does not have to correspond to the resource (on disk) that will be used by the web server.
	RequestBasename
	// Description: Holds the raw request body. This variable is available only if the
	// URLENCODED request body processor was used, which will occur by default when the
	// application/x-www-form-urlencoded content type is detected, or if the use of the
	// URLENCODED request body parser was forced.
	// ---
	// ```modsecurity
	// SecRule REQUEST_BODY "^username=\w{25,}\&password=\w{25,}\&Submit\=login$" "id:43"
	// ```
	//
	// It is possible to force the presence of the REQUEST_BODY variable, but only when there is no request body processor defined using the ```ctl:forceRequestBodyVariable``` option in the REQUEST_HEADERS phase.
	RequestBody
	// Description: Contains the number of bytes read from a request body.
	RequestBodyLength
	// Description: This variable holds the relative request URL without the query string part
	// (e.g., /index.php).
	// ---
	// ```modsecurity
	// SecRule REQUEST_FILENAME "^/cgi-bin/login\.php$" phase:2,id:46,t:none,t:normalizePath
	// ```
	//
	// **Note :** Please note that anti-evasion transformations are not used on REQUEST_FILENAME, which means that you will have to specify them in the rules that use this variable.
	RequestFilename
	// Description: This variable holds the complete request line sent to the server (including
	// the request method and HTTP version information).
	// ---
	// ```modsecurity
	// # Allow only POST, GET and HEAD request methods, as well as only
	// # the valid protocol versions
	// SecRule REQUEST_LINE "!(^((?:(?:POS|GE)T|HEAD))|HTTP/(0\.9|1\.0|1\.1)$)" "phase:1,id:49,log,block,t:none"
	// ```
	RequestLine
	// Description: This variable holds the request method used in the transaction.
	// ---
	// ```modsecurity
	// SecRule REQUEST_METHOD "^(?:CONNECT|TRACE)$" "id:50,t:none"
	// ```
	RequestMethod
	// Description: This variable holds the request protocol version information.
	// ---
	// ```modsecurity
	// SecRule REQUEST_PROTOCOL "!^HTTP/(0\.9|1\.0|1\.1)$" "id:51"
	// ```
	RequestProtocol
	// Description: This variable holds the full request URL including the query string data
	// (e.g., /index.php? p=X). However, it will never contain a domain name, even if it
	// was provided on the request line.
	// ---
	// ```modsecurity
	// SecRule REQUEST_URI "attack" "phase:1,id:52,t:none,t:urlDecode,t:lowercase,t:normalizePath"
	// ```
	//
	// **Note :** Please note that anti-evasion transformations are not used on REQUEST_URI, which means that you will have to specify them in the rules that use this variable.
	RequestURI
	// Description: Same as REQUEST_URI but will contain the domain name if it was provided on
	// the request line (e.g., http://www.example.com/index.php?p=X).
	// ---
	// ```modsecurity
	// SecRule REQUEST_URI_RAW "http:/" "phase:1,id:53,t:none,t:urlDecode,t:lowercase,t:normalizePath"
	// ```
	//
	// **Note :** Please note that anti-evasion transformations are not used on REQUEST_URI_RAW, which means that you will have to specify them in the rules that use this variable.
	RequestURIRaw
	// Description: This variable holds the data for the response body, but only when response
	// body buffering is enabled.
	// ---
	// ```modsecurity
	// SecRule RESPONSE_BODY "ODBC Error Code" "phase:4,id:54,t:none"
	// ```
	ResponseBody
	// Description: Response body length in bytes. Can be available starting with phase 3, but
	// it does not have to be (as the length of response body is not always known in advance).
	// If the size is not known, this variable will contain a zero. If RESPONSE_CONTENT_LENGTH
	// contains a zero in phase 5 that means the actual size of the response body was 0. The
	// value of this variable can change between phases if the body is modified. For example,
	// in embedded mode, mod_deflate can compress the response body between phases 4 and 5.
	ResponseContentLength
	// Description: This variable holds the HTTP response protocol information.
	// ---
	// ```modsecurity
	// SecRule RESPONSE_PROTOCOL "^HTTP\/0\.9" "phase:3,id:57,t:none"
	// ```
	ResponseProtocol
	// Description: This variable holds the HTTP response status code:
	// ---
	// ```modsecurity
	// SecRule RESPONSE_STATUS "^[45]" "phase:3,id:58,t:none"
	// ```
	//
	// This variable may not work as expected, as some implementations might change the status before releasing the output buffers.
	ResponseStatus
	// Description: This variable contains the IP address of the server.
	// ---
	// ```modsecurity
	// SecRule SERVER_ADDR "@ipMatch 192.168.1.100" "id:67"
	// ```
	ServerAddr
	// Description: This variable contains the transaction's hostname or IP address, taken from
	// the request itself (which means that, in principle, it should not be trusted).
	// ---
	// ```modsecurity
	// SecRule SERVER_NAME "hostname\.com$" "id:68"
	// ```
	ServerName
	// Description: This variable contains the local port that the web server (or reverse proxy)
	// is listening on.
	// ---
	// ```modsecurity
	// SecRule SERVER_PORT "^80$" "id:69"
	// ```
	ServerPort
	// Description: This variable holds the highest severity of any rules that have matched so
	// far. Severities are numeric values and thus can be used with comparison operators such as
	// @lt, and so on. A value of 255 indicates that no severity has been set.
	// ---
	// ```modsecurity
	// SecRule HIGHEST_SEVERITY "@le 2" "phase:2,id:23,deny,status:500,msg:'severity %{HIGHEST_SEVERITY}'"
	// ```
	//
	// **Note :** Higher severities have a lower numeric value.
	HighestSeverity
	// Description: This variable holds the full status line sent by the server (including the
	// request method and HTTP version information).
	// ---
	// ```modsecurity
	// # Generate an alert when the application generates 500 errors.
	// SecRule STATUS_LINE "@contains 500" "phase:3,id:49,log,pass,logdata:'Application error detected!,t:none"
	// ```
	//
	// **Supported on Coraza:** TBI
	StatusLine
	// Description: Contains the number of microseconds elapsed since the beginning of the
	// current transaction.
	//
	// **Not Implemented yet**
	Duration
	// Description: This variable is a collection of the response header names.
	// ---
	// ```modsecurity
	// SecRule RESPONSE_HEADERS_NAMES "Set-Cookie" "phase:3,id:56,t:none"
	// ```
	//
	// The same limitations apply as the ones discussed in RESPONSE_HEADERS.
	ResponseHeadersNames // CanBeSelected
	// Description: This variable is a collection of the names of all of the request headers.
	// ---
	// ```modsecurity
	// SecRule REQUEST_HEADERS_NAMES "^x-forwarded-for" "log,deny,id:48,status:403,t:lowercase,msg:'Proxy Server Used'"
	// ```
	RequestHeadersNames // CanBeSelected
	// Description: **ARGS** is a collection and can be used on its own (means all arguments
	// including the POST Payload), with a static parameter (matches arguments with that name),
	// or with a regular expression (matches all arguments with name that matches the regular
	// expression). To look at only the query string or body arguments, see the ARGS_GET and
	// ARGS_POST collections.
	// ---
	// Some variables are actually collections, which are expanded into more variables at runtime. The following example will examine all request arguments:
	//
	// ```modsecurity
	// SecRule ARGS dirty "id:7"
	// ```
	//
	// Sometimes, however, you will want to look only at parts of a collection. This can be achieved with the help of the selection operator(colon). The following example will only look at the arguments named p (do note that, in general, requests can contain multiple arguments with the same name):
	//
	// ```modsecurity
	// SecRule ARGS:p dirty "id:8"
	// ```
	//
	// It is also possible to specify exclusions. The following will examine all request arguments for the word dirty, except the ones named z (again, there can be zero or more arguments named z):
	//
	// ```modsecurity
	// SecRule ARGS|!ARGS:z dirty "id:9"
	// ```
	//
	// There is a special operator that allows you to count how many variables there are in a collection. The following rule will trigger if there is more than zero arguments in the request (ignore the second parameter for the time being):
	//
	// ```modsecurity
	// SecRule &ARGS !^0$ "id:10"
	// ```
	//
	// And sometimes you need to look at an array of parameters, each with a slightly different name. In this case you can specify a regular expression in the selection operator itself. The following rule will look into all arguments whose names begin with id_:
	//
	// ```modsecurity
	// SecRule ARGS:/^id_/ dirty "id:11"
	// ```
	//
	// **Note :** Using ```ARGS:p``` will not result in any invocations against the operator if argument p does not exist.
	Args // CanBeSelected
	// Description: **ARGS_GET** is similar to ARGS, but contains only query string parameters.
	ArgsGet // CanBeSelected
	// Description: **ARGS_POST** is similar to **ARGS**, but only contains arguments from the
	// POST body.
	ArgsPost // CanBeSelected
	// ArgsPath contains the url path parts
	ArgsPath // CanBeSelected
	// Description: Contains a list of individual file sizes. Useful for implementing a size
	// limitation on individual uploaded files. Available only on inspected multipart/form-data
	// requests.
	// ---
	// ```modsecurity
	// SecRule FILES_SIZES "@gt 100" "id:20"
	// ```
	FilesSizes // CanBeSelected
	// Description: Contains a list of form fields that were used for file upload. Available only
	// on inspected multipart/form-data requests.
	// ---
	// ```modsecurity
	// SecRule FILES_NAMES "^upfile$" "id:19"
	// ```
	FilesNames // CanBeSelected
	// Description: Contains a key-value set where value is the content of the file which was
	// uploaded. Useful when used together with @fuzzyHash.
	// ---
	// ```modsecurity
	// SecRule FILES_TMP_CONTENT "@fuzzyHash $ENV{CONF_DIR}/ssdeep.txt 1" "id:192372,log,deny"
	// ```
	//
	// **Note :** SecUploadKeepFiles should be set to 'On' in order to have this collection filled.
	FilesTmpContent // CanBeSelected
	// Description: This variable contains the multipart data from field FILENAME.
	MultipartFilename // CanBeSelected
	// Description: This variable contains the multipart data from field NAME.
	MultipartName // CanBeSelected
	// Description: Similar to MATCHED_VAR_NAME except that it is a collection of all matches
	// for the current operator check.
	// ---
	// ```modsecurity
	// SecRule ARGS pattern "chain,deny,id:28"
	//   SecRule MATCHED_VARS_NAMES "@eq ARGS:param"
	// ```
	MatchedVarsNames // CanBeSelected
	// Description: Similar to **MATCHED_VAR** except that it is a collection of all matches
	// for the current operator check.
	// ---
	// ```modsecurity
	// SecRule ARGS pattern "chain,deny,id:26"
	//   SecRule MATCHED_VARS "@eq ARGS:param"
	// ```
	MatchedVars // CanBeSelected
	// Description: Contains a collection of original file names (as they were called on the
	// remote user's filesystem). Available only on inspected multipart/form-data requests.
	// ---
	// ```modsecurity
	// SecRule FILES "@rx \.conf$" "id:17"
	// ```
	//
	// **Note :** Only available if files were extracted from the request body.
	Files // CanBeSelected
	// Description: This variable is a collection of all of request cookies (values only).
	// ---
	// Example: the following example is using the Ampersand special operator to count how many variables are in the collection. In this rule, it would trigger if the request does not include any Cookie headers.
	//
	// ```modsecurity
	// SecRule &REQUEST_COOKIES "@eq 0" "id:44"
	// ```
	RequestCookies // CanBeSelected
	// Description: This variable can be used as either a collection of all of the request
	// headers or can be used to inspect selected headers (by using the
	// REQUEST_HEADERS:Header-Name syntax).
	// ---
	// ```modsecurity
	// SecRule REQUEST_HEADERS:Host "^[\d\.]+$" "deny,id:47,log,status:400,msg:'Host header is a numeric IP address'"
	// ```
	//
	// **Note:** Coraza will treat multiple headers that have identical names as a "list", processing each single value.
	RequestHeaders // CanBeSelected
	// Description: This variable refers to response headers, in the same way as
	// REQUEST_HEADERS does to request headers.
	// ---
	// ```modsecurity
	// SecRule RESPONSE_HEADERS:X-Cache "MISS" "id:55"
	// ```
	//
	// This variable may not have access to some headers when running in embedded mode. Headers such as Server, Date, Connection, and Content-Type could be added just prior to sending the data to the client. This data should be available in phase 5 or when deployed in proxy mode.
	ResponseHeaders // CanBeSelected
	// ReseBodyProcessor contains the name of the response body processor used,
	// no default
	ResBodyProcessor
	// Description: GEO is a collection populated by the results of the last @geoLookup
	// operator. The collection can be used to match geographical fields looked from an IP
	// address or hostname.
	// ---
	// Fields:
	//
	// - **COUNTRY_CODE:** Two character country code. EX: US, CL, GB, etc.
	// - **COUNTRY_CODE3:** Up to three character country code.
	// - **COUNTRY_NAME:** The full country name.
	// - **COUNTRY_CONTINENT:** The two character continent that the country is located. EX: EU
	// - **REGION:** The two character region. For US, this is state. For Chile, region, etc.
	// - **CITY:** The city name if supported by the database.
	// - **POSTAL_CODE:** The postal code if supported by the database.
	// - **LATITUDE:** The latitude if supported by the database.
	// - **LONGITUDE:** The longitude if supported by the database.
	//
	// **Example:**
	//
	// ```modsecurity
	// SecGeoLookupDb maxminddb file=/usr/local/geo/data/GeoLiteCity.dat
	// ...
	// SecRule REMOTE_ADDR "@geoLookup" "chain,id:22,drop,msg:'Non-GB IP address'"
	// SecRule GEO:COUNTRY_CODE "!@streq GB"
	// ```
	Geo // CanBeSelected
	// Description: This variable is a collection of the names of all request cookies. For
	// example, the following rule will trigger if the JSESSIONID cookie is not present:
	// ---
	// ```modsecurity
	// SecRule &REQUEST_COOKIES_NAMES:JSESSIONID "@eq 0" "id:45"
	// ```
	RequestCookiesNames // CanBeSelected
	// Description: Contains a list of temporary files' names on the disk. Useful when used
	// together with @inspectFile. Available only on inspected multipart/form-data requests.
	// ---
	// ```modsecurity
	// SecRule FILES_TMPNAMES "@inspectFile /path/to/inspect_script.pl" "id:21"
	// ```
	FilesTmpNames // CanBeSelected
	// Description: Contains all request parameter names. You can search for specific parameter
	// names that you want to inspect. In a positive policy scenario, you can also allowlist
	// (using an inverted rule with the exclamation mark) only the authorized argument names.
	// This example rule allows only two argument names: p and a:
	// ---
	// ```modsecurity
	// SecRule ARGS_NAMES "!^(p|a)$" "id:13"
	// ```
	ArgsNames // CanBeSelected
	// Description: **ARGS_GET_NAMES** is similar to **ARGS_NAMES**, but contains only the
	// names of query string parameters.
	ArgsGetNames // CanBeSelected
	// Description: **ARGS_POST_NAMES** is similar to **ARGS_NAMES**, but contains only the
	// names of request body parameters.
	ArgsPostNames // CanBeSelected
	// Description: This is the transient transaction collection, which is used to store pieces
	// of data, create a transaction anomaly score, and so on. The variables placed into this
	// collection are available only until the transaction is complete.
	// ---
	// ```modsecurity
	// # Increment transaction attack score on attack
	// SecRule ARGS attack "phase:2,id:82,nolog,pass,setvar:TX.score=+5"
	//
	// # Block the transactions whose scores are too high
	// SecRule TX:SCORE "@gt 20" "phase:2,id:83,log,deny"
	// ```
	//
	// Some variable names in the TX collection are reserved and cannot be used:
	//
	// - **TX:0:** the matching value when using the @rx or @pm operator with the capture action
	// - **TX:1-TX:9:** the captured subexpression value when using the @rx operator with capturing parens and the capture action
	TX // CanBeSelected
	// Description: This is a special collection that provides access to the id, rev, severity,
	// logdata, and msg fields of the rule that triggered the action. It can be used to refer to
	// only the same rule in which it resides.
	// ---
	// ```modsecurity
	// SecRule &REQUEST_HEADERS:Host "@eq 0" "log,deny,id:59,setvar:tx.varname=%{RULE.id}"
	// ```
	Rule // CanBeSelected
	// JSON does not provide any data, might be removed
	JSON // CanBeSelected
	// Description: Collection that provides access to environment variables set by Coraza or
	// other server modules. Requires a single parameter to specify the name of the desired
	// variable.
	// ---
	// ```modsecurity
	// # Set environment variable
	// SecRule REQUEST_FILENAME "printenv" \
	// "phase:2,id:15,pass,setenv:tag=suspicious"
	//
	// # Inspect environment variable
	// SecRule ENV:tag "suspicious" "id:16"
	//
	// # Reading an environment variable from other Apache module (mod_ssl)
	// SecRule TX:ANOMALY_SCORE "@gt 0" "phase:5,id:16,msg:'%{env.ssl_cipher}'"
	// ```
	//
	// **Note :** Use setenv to set environment variables to be accessed by Apache.
	//
	// **Not Implemented yet**
	Env // CanBeSelected
	// Description: This variable is created when an invalid URL encoding is encountered during
	// the parsing of a query string (on every request) or during the parsing of an
	// application/x-www-form-urlencoded request body (only on the requests that use the
	// URLENCODED request body processor).
	UrlencodedError
	// ResponseArgs contains the response parsed arguments
	ResponseArgs // CanBeSelected
	// ResponseXML contains the response parsed XML
	ResponseXML // CanBeSelected
	// RequestXML contains the request parsed XML
	RequestXML // CanBeSelected
	// Description: Special collection used to interact with the XML parser. It must contain a
	// valid XPath expression, which will then be evaluated against a previously parsed XML DOM
	// tree.
	// ---
	// ```modsecurity
	// SecDefaultAction log,deny,status:403,phase:2,id:90
	// SecRule REQUEST_HEADERS:Content-Type ^text/xml$ "phase:1,id:87,t:lowercase,nolog,pass,ctl:requestBodyProcessor=XML"
	// SecRule REQBODY_PROCESSOR "!^XML$" skipAfter:12345,id:88
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

	// Unsupported variables

	// Description: This variable holds the authentication method used to validate a user, if
	// any of the methods built into HTTP are used. In a reverse-proxy deployment, this
	// information will not be available if the authentication is handled in the backend web
	// server.
	// ---
	// ```modsecurity
	// SecRule AUTH_TYPE "Basic" "id:14"
	// ```
	//
	// **Not Implemented yet**
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
	// Description: Contains the extra request URI information, also known as path info. (For
	// example, in the URI /index.php/123, /123 is the path info.) Available only in embedded
	// deployments.
	// ---
	// ```modsecurity
	// SecRule PATH_INFO "^/(bin|etc|sbin|opt|usr)" "id:33"
	// ```
	PathInfo
	// Description: This variable contains the value set with setsid. See SESSION for a
	// complete example.
	//
	// **Not Implemented yet**
	Sessionid
	// Description: This variable contains the value set with setuid.
	// ---
	// ```modsecurity
	// # Initialize user tracking
	// SecAction "nolog,id:84,pass,setuid:%{REMOTE_USER}"
	//
	// # Is the current user the administrator?
	// SecRule USERID "admin" "id:85"
	// ```
	//
	// **Supported:** TBI
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
	// Description: This variable holds a formatted string representing the time
	// (hour:minute:second).
	// ---
	// ```modsecurity
	// SecRule TIME "^(([1](8|9))|([2](0|1|2|3))):\d{2}:\d{2}$" "id:74"
	// ```
	Time
	// Description: This variable holds the current date (1–31). The following rule triggers on
	// a transaction that's happening anytime between the 10th and 20th in a month:
	// ---
	// ```modsecurity
	// SecRule TIME_DAY "^(([1](0|1|2|3|4|5|6|7|8|9))|20)$" "id:75"
	// ```
	TimeDay
	// Description: This variable holds the time in seconds since 1970.
	TimeEpoch
	// Description: This variable holds the current hour value (0–23). The following rule
	// triggers when a request is made "off hours":
	// ---
	// ```modsecurity
	// SecRule TIME_HOUR "^(0|1|2|3|4|5|6|[1](8|9)|[2](0|1|2|3))$" "id:76"
	// ```
	TimeHour
	// Description: This variable holds the current minute value (0–59). The following rule
	// triggers during the last half hour of every hour:
	// ---
	// ```modsecurity
	// SecRule TIME_MIN "^(3|4|5)" "id:77"
	// ```
	TimeMin
	// Description: This variable holds the current month value (0–11). The following rule
	// matches if the month is either November (value 10) or December (value 11):
	// ---
	// ```modsecurity
	// SecRule TIME_MON "^1" "id:78"
	// ```
	TimeMon
	// Description: This variable holds the current second value (0–59).
	// ---
	// **Supported:** TBI
	//
	// ```modsecurity
	// SecRule TIME_SEC "@gt 30" "id:79"
	// ```
	TimeSec
	// Description: This variable holds the current weekday value (0–6). The following rule
	// triggers only on Saturday and Sunday:
	// ---
	// **Supported:** TBI
	//
	// ```modsecurity
	// SecRule TIME_WDAY "^(0|6)$" "id:80"
	// ```
	TimeWday
	// Description: This variable holds the current four-digit year value.
	// ---
	// **Supported:** TBI
	//
	// ```modsecurity
	// SecRule TIME_YEAR "^2006$" "id:81"
	// ```
	TimeYear
)
