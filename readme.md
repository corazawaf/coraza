<img src="https://github.com/jptosso/coraza-waf/raw/master/docs/logo.png" width="50%">

[![Build Status](https://travis-ci.org/jptosso/Coraza-waf.svg?branch=master)](https://travis-ci.org/jptosso/Coraza-waf)
[![](https://raw.githubusercontent.com/ZenHubIO/support/master/zenhub-badge.png)](https://zenhub.com)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=bugs)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=ncloc)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=security_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![GoDoc](https://godoc.org/github.com/jptosso/coraza-waf?status.svg)](https://godoc.org/github.com/jptosso/coraza-waf)

# Coraza Web Application Firewall

Coraza WAF is a Golang implementation of Modsecurity built from scratch, it supports most of the features from ModSecurity but aims to be a completely different implementation with many new capabilities and extensibility.

*This project is not intended for production yet*, APIs are going to change, it's not secure enough and it might crash.


## Table of Contents

- [Coraza Web Application Firewall](#coraza-web-application-firewall)

## TO-DO

- [ ] Normalize API
- [x] Add more settings
- [ ] Replace libinjection for something awesome, maybe AI?
- [x] Create Documentation
- [ ] Audit Logging (syslog, ES and concurrent)
- [x] Logrotate support
- [ ] Autoconf
- [ ] Optimize pcre compilation instructions
- [ ] OWASP CRS Full Support (almost there)
- [ ] Benchmarking tools
- [ ] Plugin system
- [ ] Add settings reload feature
- [ ] Cache geoip to enhance speed
- [ ] Add clustering features
- [ ] Add support for plugins
- [ ] OpenAPI 3.0 Enforcement


## Docker


```
docker build -t coraza-waf .
docker run -d -it -p 8080:8080 --name=coraza-waf coraza-waf --host=0.0.0.0
```

If you want to use your own settings, you must set the volume of /etc/coraza/ to your custom virtual path.

## Usage

Using Skipper filter sample:
```
-> corazaWAF("/path/to/rules.conf", "/path/to/datafiles")
```

Sample:
```
baidu:
        Path("/baidu")
        -> corazaWAF("/path/to/rules.conf", "/path/to/datafiles")
        -> setRequestHeader("Host", "www.baidu.com")
        -> setPath("/s")
        -> setQuery("wd", "godoc skipper")
        -> "http://www.baidu.com";
```

## Compile from source

Compilation prerequisites: golang 1.11>, C compiler, libpcre++-dev, libinjection compiled (use `make libinjection`)

You can compile each package individually running: `go build cmd/skipper/main.go` or using the make scripts.

```
make
sudo make install
```

## Compile as a skipper plugin

Change package name of pkg/skipper/filters.go from skipper to main and then:
```
GO111MODULE=on go build -buildmode=plugin -o coraza.so pkg/skipper/filters.go
skipper -filter-plugin coraza
```

## Non implemented features

### Variables

- [ ] AUTH_TYPE
- [ ] DURATION
- [ ] ENV
- [ ] HIGHEST_SEVERITY
- [ ] INBOUND_DATA_ERROR
- [ ] MATCHED_VAR
- [ ] MATCHED_VARS
- [ ] MATCHED_VAR_NAME
- [ ] MATCHED_VARS_NAMES
- [ ] MULTIPART_CRLF_LF_LINES
- [ ] MULTIPART_STRICT_ERROR
- [ ] MULTIPART_UNMATCHED_BOUNDARY
- [ ] OUTBOUND_DATA_ERROR
- [ ] PATH_INFO
- [ ] PERF_ALL
- [ ] PERF_COMBINED
- [ ] PERF_GC
- [ ] PERF_LOGGING
- [ ] PERF_PHASE1
- [ ] PERF_PHASE2
- [ ] PERF_PHASE3
- [ ] PERF_PHASE4
- [ ] PERF_PHASE5
- [ ] PERF_RULES
- [ ] PERF_SREAD
- [ ] PERF_SWRITE
- [ ] REMOTE_USER
- [ ] REQBODY_ERROR
- [ ] REQBODY_ERROR_MSG
- [ ] RESPONSE_PROTOCOL
- [ ] RESPONSE_STATUS
- [ ] RULE
- [ ] SERVER_ADDR
- [ ] SERVER_NAME
- [ ] SERVER_PORT
- [ ] SESSION
- [ ] SESSIONID
- [ ] STATUS_LINE
- [ ] STREAM_INPUT_BODY
- [ ] STREAM_OUTPUT_BODY
- [ ] TIME
- [ ] TIME_DAY
- [ ] TIME_EPOCH
- [ ] TIME_HOUR
- [ ] TIME_MIN
- [ ] TIME_MON
- [ ] TIME_SEC
- [ ] TIME_WDAY
- [ ] TIME_YEAR
- [ ] UNIQUE_ID
- [ ] URLENCODED_ERROR
- [ ] USERID
- [ ] USERAGENT_IP
- [ ] WEBAPPID
- [ ] WEBSERVER_ERROR_LOG
- [ ] XML

### Operators

- [ ] fuzzyHash
- [ ] gsbLookup
- [ ] inspectFile
- [ ] noMatch
- [ ] validateDTD
- [ ] validateHash
- [ ] validateSchema
- [ ] verifyCC

### Actions

- [ ] append
- [ ] deprecatevar
- [ ] prepend
- [ ] proxy
- [ ] redirect
- [ ] sanitiseArg
- [ ] sanitiseMatched
- [ ] sanitiseMatchedBytes
- [ ] sanitiseRequestHeader
- [ ] sanitiseResponseHeader
- [ ] setuid
- [ ] setrsc
- [ ] setsid
- [ ] setenv
- [ ] xmlns

### Transformations

- [ ] cssDecode
- [ ] jsDecode


## License

Apache 2 License, please check the LICENSE file for full details.