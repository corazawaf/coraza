<h1>
  <img src="https://coraza.io/images/logo_shield.png" align="left" height="46px" alt=""/>
  <span>Coraza - Web Application Firewall Engine</span>
</h1>

[![Regression Tests](https://github.com/corazawaf/coraza/actions/workflows/regression.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/regression.yml)
[![Coreruleset Compatibility](https://github.com/corazawaf/coraza/actions/workflows/go-ftw.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/go-ftw.yml)
[![CodeQL](https://github.com/corazawaf/coraza/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/codeql-analysis.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=coraza&metric=coverage)](https://sonarcloud.io/dashboard?id=jptosso_coraza-waf)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![OWASP Lab Project](https://img.shields.io/badge/owasp-lab%20project-brightgreen)](https://owasp.org/www-project-coraza-web-application-firewall)
[![GoDoc](https://godoc.org/github.com/corazawaf/coraza?status.svg)](https://godoc.org/github.com/corazawaf/coraza/v2)

* Website: https://coraza.io
* OWASP Slack Community (#coraza): https://owasp.org/slack/invite
* Issue Tracker: https://github.com/corazawaf/coraza/issues
* Coraza Playground: https://playground.coraza.io
* Project Planning: https://github.com/orgs/corazawaf/projects?type=beta

Coraza is an open source, enterprise-grade, high performance Web Application
Firewall (WAF) ready to protect your beloved applications. It written in Go,
supports ModSecurity SecLang rulesets and is 100% compatible with the OWASP
Core Rule Set.

* **Firewall Engine** Coraza is an implementation of the SecLang engine in the
    memory-safe Go language. Coraza runs the [OWASP Core Rule Set
    (CRS)](https://coreruleset.org/) to stop attacks and generate important audit
    information.

* **Security** - Coraza runs the [OWASP Core Rule Set (CRS)](https://coreruleset.org)
		which protects web applications from a wide range of attacks, including the
		OWASP Top Ten, with a minimum of false alerts. CRS protects from many
		common attack categories including: SQL Injection (SQLi), Cross Site
		Scripting (XSS), Local File Inclusion (LFI), Remote File Inclusion (RFI),
		PHP Code Injection, Java Code Injection, HTTPoxy, Shellshock, Unix/Windows
		Shell Injection, Session Fixation, Scripting/Scanner/Bot Detection,
		Metadata & Error Leakages.

* **Performance** - From huge websites to small blogs, Coraza can handle that load
    with minimal performance impacts. Check our [Benchmarks](https://coraza.io/docs/reference/benchmarks)

* **Integrated** - Coraza is a library at its core, but we support many
    integrations to deploy a WAF as an application server, reverse proxy,
    container, and more.

* **Extensible** - Audit Loggers, persistence engines, operators, actions,
    create your own functionalities to extend Coraza as much as you want.


## Implementations

The Coraza Project maintains implementations and plugins for the following servers: 

* [Caddy Reverse Proxy and Webserver Plugin](https://github.com/corazawaf/coraza-caddy) (stable, needs a maintainer)
* [HAProxy SPOE Plugin](https://github.com/jptosso/coraza-spoa) (preview)
* [Traefik Proxy Plugin](https://github.com/jptosso/coraza-traefik) (preview, needs maintainer)
* [Gin Web Framework Middleware](https://github.com/jptosso/coraza-gin) (preview, needs maintainer)
* [Apache HTTP Server](https://github.com/jptosso/coraza-server) (experimental)
* [Nginx](https://github.com/jptosso/coraza-server) (experimental)
* [Coraza C Library](https://github.com/corazawaf/libcoraza) (experimental)
* Buffalo Web Framework Middleware (planned)

## Plugins

* [Coraza GeoIP](https://github.com/corazawaf/coraza-geoip) (preview)

## Philosophy

* **Simplicity:** Anyone is able to understand and modify the Coraza source code.
* **Extensibility:** It is easy to extend Coraza with new functionality.
* **Innovation:** Coraza is not just a ModSecurity port, it includes awesome new functions (in the meantime, it's just a port :sweat_smile:)
* **Community:** Coraza is a community project, and all ideas will be considered.

## Roadmap

* New rule language
* GraphQL body processor
* C exports
* WASM scripts support

## Prerequisites

* Linux distribution (Debian and Centos are recommended, Windows is not supported yet)
* Golang compiler v1.16+

## Using Coraza

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

## Tools

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
go get -u github.com/corazawaf/coraza/v2@v2.0.0-rc.3
```

## Contribute

Contributions are welcome! Please refer to [CONTRIBUTING.md](https://github.com/corazawaf/coraza/blob/v2/master/CONTRIBUTING.md) for guidance.

## Thanks

* Modsecurity team for creating ModSecurity
* OWASP Coreruleset team for the CRS and their help

### Companies using Coraza

* [Babiel](https://babiel.com) (supporter)

### Author on Twitter 

- [@jptosso](https://twitter.com/jptosso)

## Donations

For donations, see [Donations site](https://owasp.org/donate/?reponame=www-project-coraza-web-application-firewall&title=OWASP+Coraza+Web+Application+Firewall)
