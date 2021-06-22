<img src="https://github.com/jptosso/coraza-waf/raw/master/docs/logo.png" width="50%">

[![Build Status](https://travis-ci.org/jptosso/Coraza-waf.svg?branch=master)](https://travis-ci.org/jptosso/Coraza-waf)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=bugs)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=ncloc)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=coverage)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
![CodeQL](https://github.com/jptosso/coraza-waf/workflows/CodeQL/badge.svg)
[![GoDoc](https://godoc.org/github.com/jptosso/coraza-waf?status.svg)](https://godoc.org/github.com/jptosso/coraza-waf)
[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)


# Coraza Web Application Firewall


Welcome to Coraza Web Application Firewall, this project is a Golang port of ModSecurity with the goal to become the first enterprise-grade Open Source Web Application Firewall, extensible enough to serve as the baseline for many projects. 

Please note Coraza is still a WIP.

## Prerequisites

* Linux distribution (Debian and Centos are recommended, Windows is not supported)
* Golang compiler v1.13+ (Note some wrappers like Caddy requires v1.16+)
* libpcre-dev (``apt install libpcre++-dev`` for Ubuntu)
* **CGO_ENABLED** environmental variable must be set to 1
* libinjection must be installed and linked

You may install libinjection with the following command:

```
# Must be run as root
sudo make deps
```

Note this command will compile and install libinjection to your **LIBRARY_PATH** and **LD_LIBRARY_PATH**.

## Running the test suite

Run the go tests:
```
go test ./...
go test -race ./...
```

Run the test suite against OWASP CRS:
```
git clone https://github.com/jptosso/coraza-waf
git clone https://github.com/coreruleset/coreruleset
# Create your OWASP CRS package owasp-crs.conf
cat <<EOF >> custom-crs.conf
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400"
EOF
cat coreruleset/crs-setup.conf.example coreruleset/rules/*.conf >> custom-crs.conf
cd coraza-waf/
go run cmd/testsuite/main.go -path ../coreruleset/tests/regression/tests/ -rules ../custom-crs.conf
```


## Your first Coraza WAF project

Make sure ``CGO_ENABLED=1`` env is set before compiling and all dependencies are met.

```
package main
import(
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/seclang"
)

func main() {
	// First we initialize our waf and our seclang parser
	waf := engine.NewWaf()
	parser := seclang.NewParser(waf)

	// Now we parse our rules
	parser.FromString(`SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,drop"`)

	// Then we create a transaction and assign some variables
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 12345)

	tx.ProcessRequestHeaders()

	// Finally we check the transaction status
	if tx.Interrupted() {
		fmt.Println("Transaction was interrupted")
	}
}
```

For more examples check the examples pages in the left menu.

## Using the embedded sandbox

Coraza WAF repository contains a Sandbox package that can be used to test rules and the Core Ruleset.

You may use the sandbox with the following command:

```
CGO_ENABLED=1 go run cmd/sandbox/main.go -port 8000 -crs ../coreruleset/rules
```

It will start the sandobox at [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

Please note that Coraza Sandbox is not intended to face the public internet, if you do so you may get hacked. Future versions will contain settings to avoid unsafe operations like remote resources, command execution and lua.

## Compatibility status

We have currently achieved a 91% compatibility with OWASP CRS, some features are under development, like:

* Persistent Collections
* Audit Log engine
* Some transformations: removeCommentsChar
* Some operators: fuzzyHash
* Lua is still being tested

## Coraza WAF implementations

* [Caddy Plugin (Reverse Proxy and Web Server)](https://github.com/jptosso/coraza-caddy)

## Differences with ModSecurity

### Custom Operators

**@validateNid:** Validates national ID for many countries, replaces validateSSN.

## Troubleshooting


## Useful links

