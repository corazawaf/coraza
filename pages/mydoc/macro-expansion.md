---
title: Macro Expansion
keywords: macro expansion, modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: macro-expansion.html
folder: mydoc
---

Macros allow for using place holders in rules that will be expanded out to their values at runtime. Currently only variable expansion is supported, however more options may be added in future versions of Coraza WAF.

Format:
```
%{VARIABLE}
%{COLLECTION.VARIABLE}
```

Macro expansion can be used in actions such as initcol, setsid, setuid, setvar, setenv, logdata. Operators that are evaluated at runtime support expansion and are noted above. 

You can use macro expansion for operators that are "compiled" such @rx, etc. however you will have some impact in efficiency.
Some values you may want to expand include: TX, REMOTE_ADDR, USERID, HIGHEST_SEVERITY, MATCHED_VAR, MATCHED_VAR_NAME, MULTIPART_STRICT_ERROR, RULE, SESSION, USERID, among others.

For more information about the supported collections and custom collections, check the [Collections article](#).

For more information about the supported variables, check the [Variables article](#).

## Operators supporting Macro Expansion

* @beginsWith
* @endsWith
* @contains
* @within 
* @streq

## Actions supporting Macro Expansion

* tag
* logdata

