<img src="https://github.com/jptosso/coraza-waf/raw/master/docs/logo.png" width="50%">

[![Build Status](https://travis-ci.org/jptosso/Coraza-waf.svg?branch=master)](https://travis-ci.org/jptosso/Coraza-waf)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=bugs)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=ncloc)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=coverage)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
![CodeQL](https://github.com/jptosso/coraza-waf/workflows/CodeQL/badge.svg)
[![GoDoc](https://godoc.org/github.com/jptosso/coraza-waf?status.svg)](https://godoc.org/github.com/jptosso/coraza-waf)

# Coraza Web Application Firewall

Coraza WAF is a Golang implementation of Modsecurity built from scratch, it supports most of the features from ModSecurity but aims to be a completely different implementation with many new capabilities and extensibility.

*This project is not intended for production yet*, APIs are going to change, it's not secure enough and it might crash.


## Table of Contents

- [Coraza Web Application Firewall](#coraza-web-application-firewall)


## Compile from source

Compilation prerequisites: 
* golang 1.13+
* C compiler (gcc)
* Libpcre++-dev


## Compile as a skipper plugin

```
GO111MODULE=on go build -buildmode=plugin -o coraza.so cmd/coraza-waf/skipper.go
skipper -filter-plugin coraza.so
```

## Test

Golang test suite:
```
git clone --recursive https://github.com/jptosso/coraza-waf
cd coraza-waf/
go test ./... -v
```

Test against OWASP CRS
```
git clone --recursive https://github.com/jptosso/coraza-waf
# Create your OWASP CRS package owasp-crs.conf
cd coraza-waf/
go run cmd/testsuite/main.go -path docs/rs -rules crs/some-rules.conf
```

## Using Coraza WAF

```
package main

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/seclang"
	"fmt"
)

func main(){
	// Create waf instance
	waf := engine.NewWaf()

	// Parse some rules
	p, _ := parser.NewParser(waf)
	p.FromString(`SecRule REQUEST_HEADERS:test "TestValue" "id:1, drop, log"`)

	// Create Transaction
	tx := waf.NewTransaction()
	tx.AddRequestHeader("Test", "TestValue")
	tx.ExecutePhase(2)
	if tx.Disrupted{
		fmt.Println("Transaction disrupted")
	}
}
```


## Using the CRS engine

Coraza WAF can be configured with OWASP CRS without the need to download and setup the packages. The ``pkg.crs`` package contains tools to automatically import and setup CRS.


## License

Apache 2 License, please check the LICENSE file for full details.