---
title: What is Coraza WAF
keywords: modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: coraza-waf.html
folder: mydoc
---

## Why another WAF

There are hundreds of open source WAF projects, but the only one really used by companies around the world is ModSecurity.

ModSecurity is a great project, it's robust, well designed and there is a strong community of administrators, but not a strong community willing to improve it and build new stuff around it.

Coraza WAF is focused on both communities, development and administrators, the idea is to create an open source enterprise grade WAF capable of performing great from startup blogs to huge banking applications.

## Why keep SecRule format

We are keeping SecRule format because it's easy to understand, already used by the ModSecurity community, compatible with OWASP CRS and we could keep building new functionalities around it.

We could create our own format in the future but I believe SecRule should be ok for many years to come.

## Main principles

### Extensibility

Coraza WAF must be easy to extend, developers should be able to easily build new directives, actions, transformations, directives, persistence engines and more.

To achieve this, Coraza APIs will give access to each core functionality and provide a plugins engine.

### Long term support



### Constant evolution



### Integration

### Simplicity

### Community Focus

## SQL Injection and XSS filters evasion

There are a lot of payloads used to bypass Modsecurity SQL injection and XSS 