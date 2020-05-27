<img src="https://github.com/jptosso/coraza-waf/raw/master/docs/logo.png" width="50%">

[![Build Status](https://travis-ci.org/jptosso/Coraza.svg?branch=master)](https://travis-ci.org/jptosso/Coraza)
[![](https://raw.githubusercontent.com/ZenHubIO/support/master/zenhub-badge.png)](https://zenhub.com)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza&metric=bugs)](https://sonarcloud.io/dashboard?id=jptosso_coraza)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza&metric=ncloc)](https://sonarcloud.io/dashboard?id=jptosso_coraza)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza&metric=security_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=jptosso_coraza)

# Coraza Web Application Firewall

*This project is not intended for production yet*, APIs are going to change, it's not secure enough and it might crash.


### Table of Contents

- [Coraza Web Application Firewall](#coraza-web-application-firewall)
  * [What is the difference between this project and ModSecurity](#what-is-the-difference-between-this-project-and-modsecurity)
  * [Connector's status](#connector-s-status)
  * [To be Pre-Alpha](#to-be-pre-alpha)
  * [To be Alpha](#to-be-alpha)
  * [Low priority TO-DO](#low-priority-to-do)
  * [Rules reservation](#rules-reservation)
  * [Additional Operators](#additional-operators)
  * [Compile](#compile)
  * [Usage](#usage)
  * [Credits](#credits)
  * [License](#license)


### What is Coraza WAF

I've been working in this code since 2017, I believe it's almost production ready, most features are working, benchmarks are great and it's easy to extend.

### Connector's status

| Connector  | status |
|---|---|
| C API Wrapper | TBD |
| Nginx Connector | TBD |
| Apache Connector | TBD |
| PHP composer Module | TBD |
| NodeJS Package | TBD |
| Python Package | TBD |
| Ruby Gem | TBD |
| .NET Component | TBD |
| Wordpress Plugin | TBD |
| Kong Plugin | TBD |
| CPanel Application | TBD |
| TCPDump listener | TBD |


### TO-DO

- [ ] Normalize API
- [x] Libinjection integration
- [x] LibGeoIp2 integration
- [x] Implement PCRE to replicate modsecurity regex
- [x] Add more settings
- [ ] Create Documentation
- [ ] Audit Logging (syslog, ES and concurrent)
- [x] Logrotate support
- [x] Implement Aho-Corasick matching
- [x] API Swagger
- [x] Docker Package
- [x] Fix logger
- [x] Implement Modsecurity Level 1 Core Features
- [ ] Autoconf
- [x] Vendoring
- [ ] Optimize pcre compilation instructions
- [ ] Optimize multi-threading
- [x] Reorder file and code structure
- [x] Optimize rule parser
- [ ] OWASP CRS Full Support
- [x] Tests and Travis
- [ ] Benchmarking tools
- [ ] Plugin system


### Low priority TO-DO

- [ ] Cache geoip to enhance speed
- [ ] Create cloud playground
- [ ] Add lua scripting support
- [ ] Add clustering features
- [ ] Add support for plugins
- [ ] OpenAPI 3.0 Enforcement
- [ ] Implement coraza packages (rules and scripts)
- [ ] Implement custom data types
- [ ] Replace libinjection with something cooler
- [ ] Add custom operator to import files
- [ ] Add replace and masking capabilities to rules as "actions"

### Rules reservation

This project respects the original ModSecurity reserved rule IDs but removes those thar are not used anymore or not documented enough.

- 1–99,999: reserved for local (internal) use. Use as you see fit, but do not use this range for rules that are distributed to others
- 100,000–199,999: unused (available for reservation)*
- 200,000–299,999: reserved for rules published by Comodo
- 300,000–399,999: unused (available for reservation)*
- 400,000–419,999: unused (available for reservation)
- 420,000–429,999: unused (available for reservation)*
- 430,000–439,999: unused (available for reservation)*
- 440.000-599,999: unused (available for reservation)
- 600,000-699,999: reserved for use by Akamai http://www.akamai.com/html/solutions/waf.html
- 700,000–799,999: unused (available for reservation)*
- 900,000–999,999: reserved for the OWASP ModSecurity Core Rule Set http://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project project
- 1,000,000-1,009,999: reserved for rules published by Redhat Security Team
- 1,010,000-1,999,999: reserved for rules from Coraza Technologies Research team
- 2,000,000-2,999,999: reserved for rules from Trustwave's SpiderLabs Research team
- 3,000,000-3,999,999: reserved for use by Akamai http://www.akamai.com/html/solutions/waf.html
- 4,000,000-4,099,999 unused (available for reservation)*
- 4,100,000-4,199,999 reserved: in use by Fastly https://www.fastly.com/products/cloud-security/#products-cloud-security-web-application-firewall
- 4,200,000-4,299,999 unused (available for reservation)*
- 4,300,000-4,300,999 unused (available for reservation)*
- 4,301,000-19,999,999: unused (available for reservation)
- 20,000,000-21,999,999: reserved for rules from Trustwave's SpiderLabs Research team
- 22,000,000 and above: unused (available for reservation)

### Additional Operators

### Use with docker


`
docker build -t coraza-waf .
docker run -d -it -p 8080:8080 --name=coraza-waf coraza-waf --host=0.0.0.0
`

### Usage

### Credits

* The modsecurity team from the baseline for this project

# Compatibility

## Variables

[X] ARGS
[X] ARGS_COMBINED_SIZE
[X] ARGS_GET
[X] ARGS_GET_NAMES
[X] ARGS_NAMES
[X] ARGS_POST
[X] ARGS_POST_NAMES
[ ] AUTH_TYPE
[ ] DURATION
[ ] ENV
[X] FILES
[X] FILES_COMBINED_SIZE
[X] FILES_NAMES
[X] FULL_REQUEST
[X] FULL_REQUEST_LENGTH
[X] FILES_SIZES
[X] FILES_TMPNAMES
[X] FILES_TMP_CONTENT
[X] GEO
[ ] HIGHEST_SEVERITY
[ ] INBOUND_DATA_ERROR
[ ] MATCHED_VAR
[ ] MATCHED_VARS
[ ] MATCHED_VAR_NAME
[ ] MATCHED_VARS_NAMES
[ ] MODSEC_BUILD
[ ] MULTIPART_CRLF_LF_LINES
[X] MULTIPART_FILENAME
[X] MULTIPART_NAME
[ ] MULTIPART_STRICT_ERROR
[ ] MULTIPART_UNMATCHED_BOUNDARY
[ ] OUTBOUND_DATA_ERROR
[ ] PATH_INFO
[ ] PERF_ALL
[ ] PERF_COMBINED
[ ] PERF_GC
[ ] PERF_LOGGING
[ ] PERF_PHASE1
[ ] PERF_PHASE2
[ ] PERF_PHASE3
[ ] PERF_PHASE4
[ ] PERF_PHASE5
[ ] PERF_RULES
[ ] PERF_SREAD
[ ] PERF_SWRITE
[x] QUERY_STRING
[x] REMOTE_ADDR
[X] REMOTE_HOST
[X] REMOTE_PORT
[ ] REMOTE_USER
[ ] REQBODY_ERROR
[ ] REQBODY_ERROR_MSG
[ ] REQBODY_PROCESSOR
[X] REQUEST_BASENAME
[X] REQUEST_BODY
[X] REQUEST_BODY_LENGTH
[X] REQUEST_COOKIES
[X] REQUEST_COOKIES_NAMES
[X] REQUEST_FILENAME
[X] REQUEST_HEADERS
[X] REQUEST_HEADERS_NAMES
[X] REQUEST_LINE
[X] REQUEST_METHOD
[X] REQUEST_PROTOCOL
[X] REQUEST_URI
[ ] REQUEST_URI_RAW
[X] RESPONSE_BODY
[X] RESPONSE_CONTENT_LENGTH
[X] RESPONSE_CONTENT_TYPE
[X] RESPONSE_HEADERS
[X] RESPONSE_HEADERS_NAMES
[ ] RESPONSE_PROTOCOL
[ ] RESPONSE_STATUS
[ ] RULE
[ ] SCRIPT_BASENAME
[ ] SCRIPT_FILENAME
[ ] SCRIPT_GID
[ ] SCRIPT_GROUPNAME
[ ] SCRIPT_MODE
[ ] SCRIPT_UID
[ ] SCRIPT_USERNAME
[ ] SDBM_DELETE_ERROR
[ ] SERVER_ADDR
[ ] SERVER_NAME
[ ] SERVER_PORT
[ ] SESSION
[ ] SESSIONID
[ ] STATUS_LINE
[ ] STREAM_INPUT_BODY
[ ] STREAM_OUTPUT_BODY
[ ] TIME
[ ] TIME_DAY
[ ] TIME_EPOCH
[ ] TIME_HOUR
[ ] TIME_MIN
[ ] TIME_MON
[ ] TIME_SEC
[ ] TIME_WDAY
[ ] TIME_YEAR
[X] TX
[ ] UNIQUE_ID
[ ] URLENCODED_ERROR
[ ] USERID
[ ] USERAGENT_IP
[ ] WEBAPPID
[ ] WEBSERVER_ERROR_LOG
[ ] XML

## Operators

[x] beginsWith
[x] contains
[X] containsWord
[x] detectSQLi
[x] detectXSS
[x] endsWith
[ ] fuzzyHash
[x] eq
[x] ge
[X] geoLookup
[ ] gsbLookup
[x] gt
[ ] inspectFile
[X] ipMatch
[ ] ipMatchF
[ ] ipMatchFromFile
[x] le
[x] lt
[ ] noMatch
[x] pm
[X] pmf
[X] pmFromFile
[X] rbl
[X] rsub
[x] rx
[X] streq
[ ] strmatch
[x] unconditionalMatch
[ ] validateByteRange
[ ] validateDTD
[ ] validateHash
[ ] validateSchema
[ ] validateUrlEncoding
[ ] validateUtf8Encoding
[ ] verifyCC
[ ] verifyCPF
[ ] verifySSN
[X] within

## Phases

[x] Phase Request Headers
[x] Phase Request Body
[x] Phase Response Headers
[x] Phase Response Body
[x] Phase Logging

## Actions
[X] accuracy
[x] allow
[ ] append
[X] auditlog
[x] block
[X] capture
[x] chain
[X] ctl
[x] deny
[ ] deprecatevar
[X] drop
[ ] exec
[X] expirevar
[x] id
[X] initcol
[x] log
[X] logdata
[X] maturity
[x] msg
[X] multiMatch
[X] noauditlog
[X] nolog
[X] pass
[X] pause
[x] phase
[ ] prepend
[ ] proxy
[ ] redirect
[x] rev
[ ] sanitiseArg
[ ] sanitiseMatched
[ ] sanitiseMatchedBytes
[ ] sanitiseRequestHeader
[ ] sanitiseResponseHeader
[x] severity
[ ] setuid
[ ] setrsc
[ ] setsid
[ ] setenv
[X] setvar
[X] skip
[X] skipAfter
[X] status
[x] t
[X] tag
[X] ver
[ ] xmlns

## Transformations

[X] base64Decode
[X] sqlHexDecode
[X] base64DecodeExt
[X] base64Encode
[X] cmdLine
[X] compressWhitespace
[ ] cssDecode
[X] escapeSeqDecode
[X] hexDecode
[X] hexEncode
[X] htmlEntityDecode
[ ] jsDecode
[X] length
[X] lowercase
[X] md5
[X] none
[X] normalisePath
[X] normalizePath
[X] normalisePathWin
[X] normalizePathWin
[X] parityEven7bit
[X] parityOdd7bit
[X] parityZero7bit
[X] removeNulls
[X] removeWhitespace
[X] replaceComments
[X] removeCommentsChar
[X] removeComments
[X] replaceNulls
[X] urlDecode
[X] uppercase
[X] urlDecodeUni
[X] urlEncode
[X] utf8toUnicode
[X] sha1
[X] trimLeft
[X] trimRight
[X] trim


### License

To pay respect for the spirit of the ModSecurity project, Coraza also inherits the Apache 2 License, please check the LICENSE file for full details.