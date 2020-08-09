---
title: Collections
keywords: collections, modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: collections.html
folder: mydoc
---


## Collections explanation

Coraza WAF considers each variable as a collection and always returns arrays, each element of the array is evaluated. The following example provides an idea of the internal structure:
```
{
	"request_headers": {
		"host": [
			"test-site.com"
		]
	},
	"request_headers_names": {
		"": [
			"host"
		]
	}
}
```

If you want to read the Host header you might use the following snippet and you would obtain an array with the value [test-site.com]:

```
SecRule tx.request_headers:host "@eq test-site.com" "id:1"
```

Keyless collections like request_headers_names are stored inside ``request_headers_names[""]`` with an empty key, for example:
```
{
	"request_headers_names": {
		"": [
			"host",
			"user-agent",
			"cookies"
		]
	}
}
```

If no collection key is specified, the system will scan all keys and return each result.

Note: Collections keys are case insensitive.

Note: There are reserved names for persistent collections, these are: GLOBAL, RESOURCE, IP, SESSION and USER.

## Persistent Collections

Persistent collections are an abstract type of collection that is managed by the PersistentCollection engine. The system will catch them and attempt to get them from Redis.

Persistent collections suport multi tenancy and can handle race conditions by locking fields.

At this time it is only possible to have five collections in which data is stored persistently (i.e. data available to multiple requests). These are: GLOBAL, RESOURCE, IP, SESSION and USER.

Every collection contains several built-in variables that are available and are read-only unless otherwise specified:

1. **CREATE_TIME -** date/time of the creation of the collection.
2. **IS_NEW -** set to 1 if the collection is new (not yet persisted) otherwise set to 0.
3. **KEY -** the value of the initcol variable (the client's IP address in the example).
4. **LAST_UPDATE_TIME -** date/time of the last update to the collection.
5. **TIMEOUT -** date/time in seconds when the collection will be updated on disk from memory (if no other updates occur). This variable may be set if you wish to specifiy an explicit expiration time (default is 3600 seconds). The TIMEOUT is updated every time that the values of an entry is changed.
6. **UPDATE_COUNTER -** how many times the collection has been updated since creation.
7. **UPDATE_RATE -** is the average rate updates per minute since creation.

To create a collection to hold session variables (SESSION) use action setsid. To create a collection to hold user variables (USER) use action setuid. To create a collection to hold client address variables (IP), global data or resource-specific data, use action initcol.


**Currently supported persistance engines**

* Redis

**Key names**

Collection names are structured as following:
```
redis> GET col-{collection-name}-{key}
{
	"create_time": "",
	"is_new": "",
	"key": "",
	"last_update_time": "",
	"timeout": "",
	"update_counter": "",
	"update_rate": "",
	"some_custom_field": ""
}
```

Collection locks
```
redis> GET col-lock-{collection-name}-{key}
{timestamp}

```
