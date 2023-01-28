<h1>
  <img src="https://coraza.io/images/logo_shield_only.png" align="left" height="46px" alt=""/>&nbsp;
  <span>Coraza - Web Application Firewall</span>
</h1>

[![Regression Tests](https://github.com/corazawaf/coraza/actions/workflows/regression.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/regression.yml)
[![Coreruleset Compatibility](https://img.shields.io/badge/Coreruleset%20Compatibility-100%25-brightgreen)](#)
[![CodeQL](https://github.com/corazawaf/coraza/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/corazawaf/coraza/actions/workflows/codeql-analysis.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=coraza&metric=coverage)](https://sonarcloud.io/project/overview?id=coraza)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![OWASP Lab Project](https://img.shields.io/badge/owasp-lab%20project-brightgreen)](https://owasp.org/www-project-coraza-web-application-firewall)
[![GoDoc](https://godoc.org/github.com/corazawaf/coraza?status.svg)](https://godoc.org/github.com/corazawaf/coraza/v3)

## Notice: Coraza v3 is on pre-alpha stage and APIs might change ! :warning:

Coraza is an open source, enterprise-grade, high performance Web Application Firewall (WAF) ready to protect your beloved applications. It written in Go, supports ModSecurity SecLang rulesets and is 100% compatible with the OWASP Core Rule Set.

* Website: https://coraza.io
* Forum: [Github Discussions](https://github.com/corazawaf/coraza/discussions)
* OWASP Slack Community (#coraza): https://owasp.org/slack/invite
* Rule testing: [Coraza Playground](https://playground.coraza.io)
* Planning: [Github Projects](https://github.com/orgs/corazawaf/projects?type=beta)

<br/>

Key Features:

* ⇲ **Drop-in** - Coraza is a drop-in alternative to replace the soon to be abandoned Trustwave ModSecurity Engine and supports industry standard SecLang rule sets.

* 🔥 **Security** -  Coraza runs the [OWASP Core Rule Set (CRS)](https://coreruleset.org) to protect your web applications from a wide range of attacks, including the OWASP Top Ten, with a minimum of false alerts. CRS protects from many common attack categories including: SQL Injection (SQLi), Cross Site Scripting (XSS), PHP & Java Code Injection, HTTPoxy, Shellshock, Scripting/Scanner/Bot Detection & Metadata & Error Leakages.

* 🔌 **Extensible** - Coraza is a library at its core, with many integrations to deploy on-premise Web Application Firewall instances. Audit Loggers, persistence engines, operators, actions, create your own functionalities to extend Coraza as much as you want.

* 🚀 **Performance** - From huge websites to small blogs, Coraza can handle the load with minimal performance impact. Check our [Benchmarks](https://coraza.io/docs/reference/benchmarks)

* ﹡ **Simplicity** - Anyone is able to understand and modify the Coraza source code. It is easy to extend Coraza with new functionality.

* 💬 **Community** - Coraza is a community project, contributions are accepted and all ideas will be considered. Find contributor guidance in the [CONTRIBUTION](https://github.com/corazawaf/coraza/blob/v2/master/CONTRIBUTING.md) document.

<br/>

## Integrations

The Coraza Project maintains implementations and plugins for the following servers: 

* [Caddy Reverse Proxy and Webserver Plugin](https://github.com/corazawaf/coraza-caddy) - stable, needs a maintainer
* [Proxy WASM extension](https://github.com/corazawaf/coraza-proxy-wasm) for proxies with proxy-wasm support (e.g. Envoy) - stable, still under development
* [HAProxy SPOE Plugin](https://github.com/corazawaf/coraza-spoa) - preview
* [Traefik Proxy Plugin](https://github.com/jptosso/coraza-traefik) - preview, needs maintainer
* [Gin Web Framework Middleware](https://github.com/jptosso/coraza-gin) - preview, needs maintainer
* [Apache HTTP Server](https://github.com/corazawaf/coraza-server) - experimental
* [Nginx](https://github.com/corazawaf/coraza-server) - experimental
* [Coraza C Library](https://github.com/corazawaf/libcoraza) - experimental

## Plugins

* [Coraza GeoIP](https://github.com/corazawaf/coraza-geoip) (preview)

## Roadmap

* WASM scripts support
* New rule language
* GraphQL body processor
* TinyGo support
* libcoraza C exports

## Prerequisites

* Golang compiler v1.18+
* Linux distribution (Debian or Centos recommended) or Mac. Windows not supported yet.


## Coraza Core Usage

Coraza can be used as a library for your Go program to implement a security middleware or integrate it with existing application & webservers.

```go
package main

import (
	"fmt"
	"github.com/corazawaf/coraza/v3"
)

func main() {
	// First we initialize our waf and our seclang parser
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"`))
	// Now we parse our rules
	if err != nil {
		fmt.Println(err)
	}

	// Then we create a transaction and assign some variables
    tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 12345)

	// Finally we process the request headers phase, which may return an interruption
	if it := tx.ProcessRequestHeaders(); it != nil {
		fmt.Printf("Transaction was interrupted with status %d\n", it.Status)
	}
}
```
[Examples/http-server](./examples/http-server/) provides an example to practice with Coraza.

### Build tags

Go build tags can tweak certain functionality at compile-time. These are for advanced use cases only and do not
have compatibility guarantees across minor versions - use with care.

- coraza.disabled_operators.* - excludes the specified operator from compilation. Particularly useful if overriding
the operator with `operators.Register` to reduce binary size / startup overhead.
- `coraza.rule.multiphase_valuation` - enables evaluation of rule variables in the phases that they are ready, not
only the phase the rule is defined for.

## Tools

* [Go FTW](https://github.com/coreruleset/go-ftw): Rule testing engine
* [Coraza Playground](https://playground.coraza.io/): Sandbox rule testing web interface
* [OWASP Core Ruleset](https://github.com/coreruleset/coreruleset/): Awesome rule set, compatible with Coraza

## Development

Coraza only requires Go for development. You can run `mage.go` to issue development commands.

See the list of commands

```shell
go run mage.go -l
```

For example, to format your code before submission, run

```shell
go run mage.go format
```

## Contribute

Contributions are welcome! Please refer to [CONTRIBUTING.md](./CONTRIBUTING.md) for guidance.

## Thanks

* Modsecurity team for creating ModSecurity
* OWASP Coreruleset team for the CRS and their help

### Companies using Coraza

* [Babiel](https://babiel.com) (supporter)

### Author on Twitter 

- [@jptosso](https://twitter.com/jptosso)

## Donations

For donations, see [Donations site](https://owasp.org/donate/?reponame=www-project-coraza-web-application-firewall&title=OWASP+Coraza+Web+Application+Firewall)

## Thanks to all the people who have contributed

We could not have done this without you!

<a href="https://github.com/corazawaf/coraza/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=corazawaf/coraza" />
</a>

Made with [contrib.rocks](https://contrib.rocks).
