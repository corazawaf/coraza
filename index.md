---
title: "Getting started"
keywords: coraza waf
sidebar: mydoc_sidebar
permalink: index.html
---


<img src="https://github.com/jptosso/coraza-waf/raw/master/docs/logo.png" style="width:400px;height:auto;">


## Coraza Web Application Firewall

Coraza WAF is a Golang implementation of Modsecurity built from scratch, it supports most of the features from ModSecurity but aims to be a completely different implementation with many new capabilities and extensibility.

*This project is not intended for production yet*, APIs are going to change, it's not secure enough and it might crash.


## About current version (0.1.0-alpha2)

Most features are available for testing, APIs are unstable but close to the final product. 

## What is not working

- Normalized API
- Optimized pcre compilation instructions
- some disruptive actions
- some lua features


## Compile from source

Compilation prerequisites: 
* golang 1.13+
* C compiler (gcc)
* Libpcre++-dev

You can compile each package individually running: `go build cmd/coraza-waf/*.go` or using the make scripts.

```
# Get dependencies
$ go get ./...
# make libinjection is required
$ sudo make libinjection
$ make
$ sudo make install

```


## Compile as a skipper plugin

```
$ GO111MODULE=on go build -buildmode=plugin -o coraza.so cmd/coraza-waf/skipper.go
$ skipper -filter-plugin coraza.so
```

## Build installers

### Debian (.deb)

Keep in mind that this script requires the project dependencies plus dpkg tools.

Go to the project directory and run the following:
```
$ git clone https://github.com/jptosso/coraza-waf
$ cd coraza-waf/
$ ./scripts/debian/package.sh
```
As a result, you will get a /tmp/coraza-waf-build/corazawaf-version.deb file ready to be installed with ``dpkg -i corazawaf-version.deb``

### Centos/RHEL (.rpm)

There is no rpm package but you can create your own build using the `alien` command over a .deb package:
```
$ alien -r coraza-waf0.1-alpha1_amd64.deb
coraza-waf0.1.amd64.rpm generated
```

## Test

Standard Golang tests:
```
$ git clone https://github.com/jptosso/coraza-waf
$ cd coraza-waf/
$ go test ./...
```

Rule core test:
```
$ git clone https://github.com/jptosso/coraza-waf
$ cd coraza-waf/
$ go run cmd/testsuite/main.go -path test/ -rules test/data/test-rules.conf
```

Test against OWASP CRS
```
$ git clone https://github.com/jptosso/coraza-waf
$ git clone https://github.com/SpiderLabs/owasp-modsecurity-crs
# Create your OWASP CRS package owasp-crs.conf
$ cd coraza-waf/
$ go run cmd/testsuite/main.go -path ../owasp-modsecurity-crs -rules ../owasp-modsecurity-crs/owasp-crs.conf
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

<pre class="hljs" style="display: block; overflow-x: auto; padding: 0.5em; background: rgb(255, 255, 255); color: rgb(0, 0, 0);"><span class="hljs-keyword" style="color: rgb(0, 0, 136);">package</span> main

<span class="hljs-keyword" style="color: rgb(0, 0, 136);">import</span>(
	<span class="hljs-string" style="color: rgb(0, 136, 0);">"github.com/jptosso/coraza-waf/pkg/engine"</span>
	<span class="hljs-string" style="color: rgb(0, 136, 0);">"github.com/jptosso/coraza-waf/pkg/parser"</span>
	<span class="hljs-string" style="color: rgb(0, 136, 0);">"fmt"</span>
)

<span class="hljs-function"><span class="hljs-keyword" style="color: rgb(0, 0, 136);">func</span> <span class="hljs-title" style="color: rgb(102, 0, 102);">main</span><span class="hljs-params" style="color: rgb(102, 0, 102);">()</span></span>{
	<span class="hljs-comment" style="color: rgb(136, 0, 0);">// Create waf instance</span>
	waf := engine.NewWaf()

	<span class="hljs-comment" style="color: rgb(136, 0, 0);">// Parse some rules</span>
	p := parser.Parser{}
	p.Init(waf)
	p.FromString(<span class="hljs-string" style="color: rgb(0, 136, 0);">`SecRule REQUEST_HEADERS:test "TestValue" "id:1, drop, log"`</span>)

	<span class="hljs-comment" style="color: rgb(136, 0, 0);">// Create Transaction</span>
	tx := waf.NewTransaction()
	tx.AddRequestHeader(<span class="hljs-string" style="color: rgb(0, 136, 0);">"Test"</span>, <span class="hljs-string" style="color: rgb(0, 136, 0);">"TestValue"</span>)
	tx.ExecutePhase(<span class="hljs-number" style="color: rgb(0, 102, 102);">1</span>)
	<span class="hljs-keyword" style="color: rgb(0, 0, 136);">if</span> tx.Disrupted{
		fmt.Println(<span class="hljs-string" style="color: rgb(0, 136, 0);">"Transaction disrupted"</span>)
	}
}</pre>

## Deployment options

* [Docker -> Application](#)
* [Nginx + Coraza WAF -> Application](#)
* [Coraza WAF -> Application](#)
* [Kubern8 Ingress Controller](#)


## License

Apache 2 License, please check the LICENSE file for full details.

## Useful links

- [ModSecurity references](#)
- [Skipper Settings](#)
- [Skipper Routes (eskip)](#)
