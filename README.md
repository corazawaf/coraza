# OWASP Coraza Web Application Firewall v2

[![Regression Tests](https://github.com/corazawaf/coraza/actions/workflows/regression.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/regression.yml)
[![Coreruleset Compatibility](https://github.com/corazawaf/coraza/actions/workflows/go-ftw.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/go-ftw.yml)
[![CodeQL](https://github.com/corazawaf/coraza/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/codeql-analysis.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=coverage)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![OWASP Lab Project](https://img.shields.io/badge/owasp-lab%20project-brightgreen)](https://owasp.org/www-project-coraza-web-application-firewall)
[![GoDoc](https://godoc.org/github.com/corazawaf/coraza?status.svg)](https://godoc.org/github.com/corazawaf/coraza/v2)

<div align="center">
	<img src="https://coraza.io/images/logo.png" width="50%">
</div>
Welcome to OWASP Coraza Web Application Firewall, OWASP Coraza is a golang enterprise-grade Web Application Firewall framework that supports Modsecurity's seclang language and is 100% compatible with OWASP Core Ruleset.

## Prerequisites

* Linux distribution (Debian and Centos are recommended, Windows is not supported yet)
* Golang compiler v1.16+


## Migrate from v1

* Rollback SecAuditLog to the legacy syntax (serial/concurrent)
* Attach an error log handler using ```waf.SetErrorLogCb(cb)``` (optional)
* the function Transaction.Clean() must be used to clear transaction data, files and take them back to the sync pool.
* If you are using @rx with libpcre (CRS) install the plugin [github.com/jptosso/coraza-pcre](https://github.com/jptosso/coraza-pcre)
* If you are using low level APIs check the complete changelog as most of them were removed.


## Running the tests

Run the go tests:

```sh
go test ./...
go test -race ./...
```

Using pre-commit 

```sh
pip install pre-commit
pre-commit run --all-files
```

You can also install the pre-commit git hook by running
```sh
pre-commit install
```

## Coraza v2 differences with v1

* Full internal API refactor, public API has not changed
* Full audit engine refactor with plugins support
* New enhanced plugins interface for transformations, actions, body processors, and operators
* We are fully compliant with Seclang from modsecurity v2
* Many features removed and transformed into plugins: XML (Mostly), GeoIP and PCRE regex
* Better debug logging
* New error logging (like modsecurity)
* Better performance

## Your first Coraza WAF project

```go
package main
import(
	"fmt"
	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/seclang"
)

func main() {
	// First we initialize our waf and our seclang parser
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)

	// Now we parse our rules
	if err := parser.FromString(`SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"`); err != nil {
		fmt.Println(err)
	}

	// Then we create a transaction and assign some variables
	tx := waf.NewTransaction()
	defer func(){
		tx.ProcessLogging()
		tx.Clean()
	}()
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 12345)

	// Finally we process the request headers phase, which may return an interruption
	if it := tx.ProcessRequestHeaders(); it != nil {
		fmt.Printf("Transaction was interrupted with status %d\n", it.Status)
	}
}
```

## Why Coraza WAF?

### Philosophy

* **Simplicity:** Anyone should be able to understand and modify Coraza WAF's source code
* **Extensibility:** It should be easy to extend Coraza WAF with new functionalities
* **Innovation:** Coraza WAF isn't just a ModSecurity port. It must include awesome new functions (in the meantime, it's just a port :sweat_smile:)
* **Community:** Coraza WAF is a community project, and all ideas will be considered


### Roadmap

* New rule language
* GraphQL body processor
* C exports
* WASM scripts support

## Coraza WAF implementations

* [Caddy Plugin (Reverse Proxy and Web Server)](https://github.com/jptosso/coraza-caddy) (Stable)
* [Traefik Plugin (Reverse Proxy and Web Server)](https://github.com/jptosso/coraza-traefik) (preview)
* [Gin Middleware (Web Framework)](https://github.com/jptosso/coraza-gin) (Preview)
* [Buffalo Plugin (Web Framework)](#) (soon)
* [Coraza Server (HAPROXY, REST and GRPC)](https://github.com/jptosso/coraza-server) (experimental)
* [Apache httpd](https://github.com/jptosso/coraza-server) (experimental)
* [Nginx](https://github.com/jptosso/coraza-server) (soon)
* [Coraza C Exports](https://github.com/jptosso/coraza-cexport) (experimental)

## Some useful tools

* [Go FTW](https://github.com/fzipi/go-ftw): rule testing engine
* [Coraza Playground](https://playground.coraza.io/): rule testing sandbox with web interface
* [OWASP Core Ruleset](https://github.com/coreruleset/coreruleset/): Awesome rule set, compatible with Coraza

## Troubleshooting

**Dependency issues**: 
```
go get: github.com/jptosso/coraza-waf/v2@v2.0.0-rc.3: parsing go.mod:
	module declares its path as: github.com/corazawaf/coraza/v2
	        but was required as: github.com/jptosso/coraza-waf/v2
```
Coraza was migrated from github.com/jptosso/coraza-waf to github.com/corazawaf/coraza. Most dependencies has already been updated to use the new repo, but you must make sure they all use v2.0.0-rc.3+. You may use the following command to fix the error:
```sh
go get -u github.com/corazawaf/coraza@v2.0.0-rc.3
```

## How to contribute

Contributions are welcome. There are many TODOs, functionalities, fixes, bug reports, and any help you can provide. Just send your PR.

```sh
cd /path/to/coraza
egrep -Rin "TODO|FIXME" -R --exclude-dir=vendor *
```

## Special thanks

* Modsecurity team for creating ModSecurity
* OWASP Coreruleset team for the CRS and their help

### Companies using Coraza

* [Babiel](https://babiel.com) (supporter)

### Author on Twitter 

- [@jptosso](https://twitter.com/jptosso)

## Donations

For donations, see [Donations site](https://owasp.org/donate/?reponame=www-project-coraza-web-application-firewall&title=OWASP+Coraza+Web+Application+Firewall)
