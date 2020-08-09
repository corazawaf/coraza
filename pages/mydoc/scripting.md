---
title: Scripting
keywords: lua, scripting, modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: scripting.html
folder: mydoc
---

**Important:** You cannot update a persistent collection as it might cause a race condition but you can read them. In the future it will be possible to update them.

## Accessing Collections and variables

The phase where you run this script will directly affect the result, for example, if you update the request body in phase 3, the change won't be applied as the body was already sent. For more information see [phase's documentation](#)
### tx:read_collection(name, key)

### tx:update_collection(name, key, values)


## Disruptive actions

### tx:drop()

### tx:pass()

### tx:redirect(url)

### tx:proxy(proxyurl)

### tx:block()

## Using operators

```
local op = operator:new("eq", "test")
if op:evaluate(tx, "test")
```
## Using external libraries

## Performance
