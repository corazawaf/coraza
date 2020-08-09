---
title: Variables
keywords: variables, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: variables.html
folder: mydoc
summary: This document contains details about variables. Most of the data was copied from the ModSecurity WIKI
---

## Special Modifiers
There are some special variable modifiers that might help with specific cases:


### Get specific key from collection
If you have the url ``index.php?id=123&name=test&pass=456`` you can get the value from the argument "pass" with the following syntaxis:
```
SecRule ARGS:pass 456 "id:9"
```

### Get from multiple collections
You can use the character pipe "|" to select multiple variables, for example:
```
SecRule REQUEST_HEADERS|ARGS "test123" "id:9"
```

### Ignore key from collection

If you have a url ``index.php?id=123&name=test&pass=456`` you can get each argument except pass by using the following syntaxis:
```
SecRule ARGS|!ARGS:pass 456 "id:9"
```

### Count collection elements
Following the previous example, if you have th url ``index.php?id=123&name=test&pass=456`` you may count the number of parameters using the following syntaxis:
```
SecRule &ARGS_GET 3 "id:4"
```

### Regular expressions
You may use regular expressions to select elements from a collection by enclosing them between slashes ``ARGS:/(.*?)/``. For example, you have a url ``index.php?param_1=test&param_2=test2&param_3=test3``, you can get each argument that begins with params_ with the following rule:

```
SecRule ARGS_GET:/^param_(.*?)$/ "test3" "id:5"
```

## Variables

{% for var in site.data.variables %}
{% assign v = var[1] %}
### {{ v.name }}

{{ v.description }}
{% endfor %}