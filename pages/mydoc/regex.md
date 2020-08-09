---
title: Regex Support
keywords: regex, scripting, modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: regex.html
folder: mydoc
---

Many Coraza features like the @rx operator or the Variables engine supports regular expressions.

Coraza is built in Golang, and it supports each feature from the [re2](https://github.com/google/re2/wiki/Syntax) standard except by ``\C``, making it compatible with Perl, PCRE and Python expressions.

Most regex in Coraza must be enclosed between slashes, like ``SecRule ARGS:/(.*?)/ "" "id:1"``

## Performance

Performance is important as regex must be supported but DOS must be prevented.