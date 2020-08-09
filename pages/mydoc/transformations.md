---
title: transformations
keywords: transformations, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: transformations.html
folder: mydoc
summary: This document contains details about transformations. Most of the data was copied from the ModSecurity WIKI
---

Transformation functions are used to alter input data before it is used in matching (i.e., operator execution). The input data is never modified, actually—whenever you request a transformation function to be used, ModSecurity will create a copy of the data, transform it, and then run the operator against the result.

Note : There are no default transformation functions.
In the following example, the request parameter values are converted to lowercase before matching:

```
SecRule ARGS "xp_cmdshell" "t:lowercase,id:91"
```

Multiple transformation actions can be used in the same rule, forming a transformation pipeline. The transformations will be performed in the order in which they appear in the rule.

In most cases, the order in which transformations are performed is very important. In the following example, a series of transformation functions is performed to counter evasion. Performing the transformations in any other order would allow a skillful attacker to evade detection:

```
SecRule ARGS "(asfunction|javascript|vbscript|data|mocha|livescript):" "id:92,t:none,t:htmlEntityDecode,t:lowercase,t:removeNulls,t:removeWhitespace"
```
**Warning:** It is currently possible to use SecDefaultAction to specify a default list of transformation functions, which will be applied to all rules that follow the SecDefaultAction directive. However, this practice is not recommended, because it means that mistakes are very easy to make. It is recommended that you always specify the transformation functions that are needed by a particular rule, starting the list with t:none (which clears the possibly inherited transformation functions).
The remainder of this section documents the transformation functions currently available in ModSecurity.

{% for tra in site.data.transformations %}
{% assign t = tra[1] %}
## {{ t.name }}

{{ t.description }}
{% endfor %}