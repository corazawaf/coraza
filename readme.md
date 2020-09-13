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


## About current version (0.1.0-alpha1)

Most features are available for testing, APIs are unstable but close to the final product. 

## What is not working

- [ ] Normalized API
- [ ] Optimized pcre compilation instructions
- [ ] OWASP CRS Full Support (almost there)
- [ ] cssdecode and jsdecode transformation
- [ ] some disruptive actions
- [ ] some lua features


## Compile from source

Compilation prerequisites: 
* golang 1.13+
* C compiler (gcc)
* Libpcre++-dev

You can compile each package individually running: `go build cmd/coraza-waf/*.go` or using the make scripts.

```
# Get dependencies
go get ./...
# make libinjection is required
sudo make libinjection
make
sudo make install

```


## Compile as a skipper plugin

```
GO111MODULE=on go build -buildmode=plugin -o coraza.so cmd/skipper/skipper.go
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

## Run with Docker

```
$ docker run --name my-waf -v /some/config/routes.eskip:/etc/coraza-waf/routes.eskip:ro -d -p 9090:9090 jptosso/coraza-waf
```

Alternatively, a simple Dockerfile can be used to generate a new image that includes the necessary content (which is a much cleaner solution than the bind mount above):

```
FROM jptosso/coraza-waf
COPY static-settings-directory /etc/coraza-waf
```

Place this file in the same directory as your directory of content ("static-settings-directory"), ``run docker build -t my-waf .``, then start your container:

```
$ docker run --name my-waf -d -p 9090:9090 some-waf-server
```
Then you can hit http://localhost:9090 or http://host-ip:9090 in your browser.

## Using Reverse Proxy WAF

**Files and directories:**
* */etc/coraza-waf/skipper.yaml*: Contains the options that will be imported by Skipper by default.
* */etc/coraza-waf/routes.eskip*:  Contains the routes that will be used by Skipper.
* */etc/coraza-waf/profiles/default/rules.conf*: Placeholder file with default options.
* */opt/coraza/var/log/coraza-waf/access.log*: Access log for Skipper.
* */opt/coraza/var/log/coraza-waf/system.log*: Skipper + Coraza system logs
* */opt/coraza/var/log/coraza-waf/audit.log*: Audit log, contains references for each audit log, [more information here](#).
* */opt/coraza/var/log/coraza-waf/audit/*: This directory contains the concurrent logs created by the audit engine.
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
package main

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"fmt"
)

func main(){
	// Create waf instance
	waf := &engine.Waf{}
	waf.Init()

	// Parse some rules
	p := parser.Parser{}
	p.Init(waf)
	p.FromString(`SecRule REQUEST_HEADERS:test "TestValue" "id:1, drop, log"`)

	// Create Transaction
	tx := waf.NewTransaction()
	tx.AddRequestHeader("Test", "TestValue")
	tx.ExecutePhase(1)
	if tx.Disrupted{
		fmt.Println("Transaction disrupted")
	}
}
```

## Deployment options

* [Load Balancer -> Coraza WAF -> Application](#) (Recommended)
* [Nginx + Coraza WAF -> Application](#)
* [Coraza WAF -> Application](#)
* [Kubern8 Ingress Controller](#)

## Missing features and known bugs

* cssdecode andjsdecode transformations are not implemented	


## License

Apache 2 License, please check the LICENSE file for full details.