---
title: General Syntaxis
keywords: general syntaxis, scripting, modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: general-syntaxis.html
folder: mydoc
---

## General

### Base syntaxis

``DIRECTIVE DATA``

### Multi-line rules

```
SecRule ARGS:pass 456 "id:9, \
	pass, \
	t:none, \
	log"
```

### Comments

```
# This is a comment
# The following rule will match anything and trigger a disruptive drop action
SecRule UNCONDITIONAL_MATCH "" "id:9, drop"
```


## Rules
``SecRule VARIABLES OPERATORS "ACTIONS"`` 

* Operator parameters are case sensitive
* Default operator is @rx

### Variables


#### Get specific key from collection
If you have the url ``index.php?id=123&name=test&pass=456`` you can get the value from the argument "pass" with the following syntaxis:
```
SecRule ARGS:pass 456 "id:9"
```

#### Get from multiple collections
You can use the character pipe "|" to select multiple variables, for example:
```
SecRule REQUEST_HEADERS|ARGS "test123" "id:9"
```

#### Ignore key from collection

If you have a url ``index.php?id=123&name=test&pass=456`` you can get each argument except pass by using the following syntaxis:
```
SecRule ARGS|!ARGS:pass 456 "id:9"
```

#### Count collection elements
Following the previous example, if you have th url ``index.php?id=123&name=test&pass=456`` you may count the number of parameters using the following syntaxis:
```
SecRule &ARGS_GET 3 "id:4"
```

#### Regular expressions
You may use regular expressions to select elements from a collection by enclosing them between slashes ``ARGS:/(.*?)/``. For example, you have a url ``index.php?param_1=test&param_2=test2&param_3=test3``, you can get each argument that begins with params_ with the following rule:

```
SecRule ARGS_GET:/^param_(.*?)$/ "test3" "id:5"
```


### Operators

* Operator names are contains a leading "@", for example the "eq" operator must be used as "@eq 1".

### Actions

* Actions are key value objects defined like: ``"action1:value, action2:value2"``
* Value is not required, it will execute the action without parameters
* Actions are comma (,) separated
* You can wrap the value between single quotes (') for complex string, they can be escaped with backslash ``\'``.
* Actions must be enclosed between double quotes like: ``"action1, action2, action3"``.

### Chains

Chains allows you to trigger disruptive actions by following chain triggered rules. A chain is created by using the "chain" action.

* Chained rules cannot contain an metadata actions like id or phase
* Disruptive actions must be used in the first rule from the chain
* If you use a chain action, the next rule will be part of the chain, you can nest unlimited rules as a chain
* The next rule will only be evaluated if the current rules conditions are met

```
# Refuse to accept POST requests that do not contain Content-Length header. 
# (Do note that this rule should be preceded by a rule 
# that verifies only valid request methods are used.) 
SecRule REQUEST_METHOD "^POST$" phase:1,chain,t:none,id:105
  SecRule &REQUEST_HEADERS:Content-Length "@eq 0" t:none
```
