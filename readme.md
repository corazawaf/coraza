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
- [ ] Plugin system
- [ ] Add settings reload feature
- [ ] Add clustering features
- [ ] Add support for plugins
- [ ] OpenAPI 3.0 Enforcement


## Compile from source

Compilation prerequisites: 
* golang 1.11+
* C compiler
* libpcre++-dev
* libinjection compiled and linked (use `make libinjection`)

You can compile each package individually running: `go build cmd/skipper/main.go` or using the make scripts.

```
make
sudo make install
```


## Compile as a skipper plugin

```
GO111MODULE=on go build -buildmode=plugin -o coraza.so cmd/skipper/main.go
skipper -filter-plugin coraza
```

## Test

Standard Golang tests:
```
git clone https://github.com/jptosso/coraza-waf
cd coraza-waf/
go test ./...
```

Rule core test:
```
git clone https://github.com/jptosso/coraza-waf
cd coraza-waf/
go run cmd/testsuite/main.go -path test/ -rules test/data/test-rules.conf
```

Test against OWASP CRS
```
git clone https://github.com/jptosso/coraza-waf
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs
# Create your OWASP CRS package owasp-crs.conf
cd coraza-waf/
go run cmd/testsuite/main.go -path ../owasp-modsecurity-crs -rules ../owasp-modsecurity-crs/owasp-crs.conf
```

## Using Reverse Proxy WAF

**Routes:**
* */etc/coraza-waf/skipper.yaml*: Contains the options that will be imported by Skipper by default.
* */etc/coraza-waf/routes.eskip*:  Contains the routes that will be used by Skipper.
* */etc/coraza-waf/profiles/default/rules.conf*: Placeholder file with default options.
* */opt/coraza/var/log/coraza-waf/access.log*: Access log for Skipper.
* */opt/coraza/var/log/coraza-waf/skiper-error.log*: Error log for Skipper
* */opt/coraza/var/log/coraza-waf/audit.log*: Audit log, contains references for each audit log, [more information here](#).
* */opt/coraza/var/log/coraza-waf/audit/*: This directory contains the concurrent logs created by the audit engine.
* */opt/coraza/var/log/coraza-waf/error.log*: Default path for Coraza WAF errors log.
* */opt/coraza/var/log/coraza-waf/debug.log*:  Default path for Coraza WAF debug logs.
* */tmp/coraza-waf.sock*:  
* */tmp/coraza-waf.pid*:  
* */usr/local/bin/coraza-waf*: Coraza WAF binary location.

Sample:
```
samplesite:
        Path("/")
        -> corazaWAF("/etc/coraza-waf/profiles/default/rules.conf")
        -> setRequestHeader("Host", "www.samplesite.com")
        -> "https://www.samplesite.com";
```

For more configuration options and SSL check [Skipper Documentation](#).

## Using as a library

```
samplesite:
        Path("/")
        -> corazaWAF("/etc/coraza-waf/profiles/default/rules.conf")
        -> setRequestHeader("Host", "www.samplesite.com")
        -> "https://www.samplesite.com";
```

## Deployment options

* [Load Balancer -> Coraza WAF -> Application](#) (Recommended)
* [Nginx + Coraza WAF -> Application](#)
* [Coraza WAF -> Application](#)
* [Kubern8 Ingress Controller](#)

## Missing features and known bugs

* Persistent collections, Lua and remote logging are a experimental feature
* cssdecode andjsdecode transformations are not implemented	


## License

Apache 2 License, please check the LICENSE file for full details.