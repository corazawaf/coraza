# Coraza Web Application Firewall v2

![Build Status](https://github.com/jptosso/coraza-waf/actions/workflows/regression.yml/badge.svg)
![CodeQL](https://github.com/jptosso/coraza-waf/workflows/CodeQL/badge.svg)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jptosso_coraza-waf&metric=coverage)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![GoDoc](https://godoc.org/github.com/jptosso/coraza-waf?status.svg)](https://godoc.org/github.com/jptosso/coraza-waf)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Coreruleset Compatibility](https://github.com/jptosso/coraza-waf/actions/workflows/go-ftw.yml/badge.svg)](https://github.com/jptosso/coraza-waf/actions/workflows/go-ftw.yml)

<div align="center">
	<img src="https://coraza.io/images/logo.png" width="50%">
</div>
Welcome to Coraza Web Application Firewall, this project is an enterprise grade, Golang port of ModSecurity, flexible and powerful enough to serve as the baseline for many projects.

## Prerequisites

* Linux distribution (Debian and Centos are recommended, Windows is not supported yet)
* Golang compiler v1.16+


## Migrate from v1

* Rollback SecAuditLog to the legacy syntax (serial/concurrent)
* Attach an error log handler using ```waf.SetErrorLogCb(cb)``` (optional)
* If you are using @detectXSS and @detectSQLi (CRS) install the plugin [github.com/jptosso/coraza-libinjection](https://github.com/jptosso/coraza-libinjection)
* If you are using @rx with libpcre (CRS) install the plugin [github.com/jptosso/coraza-pcre](https://github.com/jptosso/coraza-pcre)
* If you are using low level APIs check the complete changelog as most of them were removed


## Running the tests

Run the go tests:

```sh
go test ./...
go test -race ./...
```

## Coraza v2 differences with v1

* Full internal API refactor, public API has not changed
* Full audit engine refactor with plugins support
* New enhanced plugins interface for transformations, actions, body processors and operators
* Now we are fully compliant with Seclang from modsecurity v2
* Many features removed and transformed into plugins: XML processing, GeoIP, PCRE regex, Libinjection (@detectXSS and @detectSQLi)
* Better debug logging
* New error logging (like modsecurity)

## Your first Coraza WAF project

```go
package main
import(
	"fmt"
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/seclang"
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
* **Innovation:** Coraza WAF isn't just a ModSecurity port, it must include awesome new functions (in the meantime it's just a port :sweat_smile:)
* **Community:** Coraza WAF is a community project and everyone's idea will be heard

### Plugins roadmap

* WASM scripts support
* Lua script support
* Integrated DDOS protection and directives with iptables(Or others) integration
* Integrated bot detection with captcha
* Open Policy Agent package (OPA)
* Enhanced data signing features (cookies, forms, etc)
* OpenAPI enforcement
* JWT enforcement
* XML request body processor
* Libinjection integration (done)
* Lib PCRE integration (done)
* Bluemonday policies (maybe)

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

## Troubleshooting

## How to contribute

Contributions are welcome, there are so many TODOs, also functionalities, fixes, bug reports and any help you can provide. Just send your PR.

```sh
cd /path/to/coraza
egrep -Rin "TODO|FIXME" -R --exclude-dir=vendor *
```

## Useful links

## Special thanks

* Modsecurity team for creating ModSecurity
* OWASP Coreruleset team for the CRS and their help
* @fzipi for his support and help
* @dune73 for the Modsecurity Handbook (The bible for this project) and all of his support

### Companies using Coraza

* [Babiel](https://babiel.com) (supporter)

## About

The name **Coraza** is trademarked, **Coraza** is a registered trademark of Juan Pablo Tosso.

* Author on Twitter [@jptosso](https://twitter.com/jptosso)

## Donations

For donations, see [Donations site](https://www.tosso.io/donate)