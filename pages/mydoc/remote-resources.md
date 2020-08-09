---
title: Remote Resources
keywords: remote resources, modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: remote-resources.html
folder: mydoc
---

Remote resources can be loaded using HTTPS, some actions and operators are supported.

Each HTTPS request must be sent to a valid HTTPS site with a trusted certificate, TLSv1.2 and decent loading speed, a few special headers are included with each request:

**X-CW-Version:** Current Coraza WAF version.

**X-CW-Key:** API credentials, can be set with the [SecRemoteApiKey](#) directive.

All remote resources are loaded on startup, a reload will redownload everything.

If a connection fails, it will fail or warn after N seconds with the [SecRemoteTimeout](#) directive.

You can change the fail or skip behaviour with the [SecRemoteRulesFailAction](#) directive.

You can create a reload marker path that is checked every 15 seconds with the [SecReloadMark](#).

You can use a proxy server using the [SecRemoteProxy](#) directive with URI syntaxis.


## Reverse Proxy Filter

**Important**: Connection rules to this server are different:
* Timeout is 30 seconds and will abort if failed, 
* TLS security is enforced
* Reloads can be performed by touching the file ``/opt/coraza-waf/tmp/coraza-rp-reload.lock`` 
* **X-CW-Key** and **X-CW-Version** headers will be sent

```
	-> corazaWafRemote("https://www.example.com/sample.conf", "API-KEY")
```

## Directives

* SecRemoteRules

## Rule Actions
Each action that supports reading a file also supports loading remote files.



## Rule Operators

* pmFromFile
* fuzzyHash
* inspectFile
* ipMatchF
* ipMatchFromFile
* pmf
* pmFromFile
* validateDTD