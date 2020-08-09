---
title: Execution Phases
keywords: phases, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: phases.html
folder: mydoc
---

Coraza's execution phases are based on ModSecurity's integration with Apache, where 5 phases are create based on the following execution flow:

![Apache execution cycle](/images/phases-apache.jpg)

The cycle above provides a path for 5 primary phases of execution, these are:

* Request headers (REQUEST_HEADERS)
* Request body (REQUEST_BODY)
* Response headers (RESPONSE_HEADERS)
* Response body (RESPONSE_BODY)
* Logging (LOGGING)

{% include callout.html content="**Note**: Many Coraza implementations handle phases 1-2 and 3-4 as one, depending on the data handlers capabilities, meaning they can't block loading an attachment if there is an insecure header, the connection will still be blocked after loading the file." type="primary" %} 

{% include callout.html content="**Note**: Keep in mind that rules are executed according to phases, so even if two rules are adjacent in a configuration file, but are set to execute in different phases, they would not happen one after the other. The order of rules in the configuration file is important only within the rules of each phase. This is especially important when using the skip and skipAfter actions." type="primary" %} 

{% include callout.html content="**Note**: Each phase can be represented by it's numeric value from 1 to 5." type="primary" %} 

{% include callout.html content="**Note**: The data available in each phase is cumulative. This means that as you move onto later phases, you have access to more and more data from the transaction.
" type="primary" %} 

{% include callout.html content="**Note**: The LOGGING phase is special. It is executed at the end of each transaction no matter what happened in the previous phases. This means it will be processed even if the request was intercepted or the allow action was used to pass the transaction through." type="primary" %} 

## Phase Request Headers

Rules in this phase are processed immediately after Apache completes reading the request headers (post-read-request phase). At this point the request body has not been read yet, meaning not all request arguments are available. Rules should be placed in this phase if you need to have them run early (before Apache does something with the request), to do something before the request body has been read, determine whether or not the request body should be buffered, or decide how you want the request body to be processed (e.g. whether to parse it as XML or not).


## Phase Request Body

This is the general-purpose input analysis phase. Most of the application-oriented rules should go here. In this phase you are guaranteed to have received the request arguments (provided the request body has been read). ModSecurity supports three encoding types for the request body phase:

* application/x-www-form-urlencoded - used to transfer form data
* multipart/form-data - used for file transfers
* text/xml - used for passing XML data

Other encodings are not used by most web applications.

{% include callout.html content="**Note**: In order to access the Request Body phase data, you must have SecRequestBodyAccess set to On." type="primary" %} 

## Phase Response Headers

This phase takes place just before response headers are sent back to the client. Run here if you want to observe the response before that happens, and if you want to use the response headers to determine if you want to buffer the response body. Note that some response status codes (such as 404) are handled earlier in the request cycle by Apache and my not be able to be triggered as expected. Additionally, there are some response headers that are added by Apache at a later hook (such as Date, Server and Connection) that we would not be able to trigger on or sanitize. This should work appropriately in a proxy setup or within phase:5 (logging).

## Phase Response Body

This is the general-purpose output analysis phase. At this point you can run rules against the response body (provided it was buffered, of course). This is the phase where you would want to inspect the outbound HTML for information disclosure, error messages or failed authentication text.

{% include callout.html content="**Note**: In order to access the Response Body phase data, you must have SecResponseBodyAccess set to On." type="primary" %} 

## Phase Logging

This phase is run just before logging takes place. The rules placed into this phase can only affect how the logging is performed. This phase can be used to inspect the error messages logged by Apache. You cannot deny/block connections in this phase as it is too late. This phase also allows for inspection of other response headers that weren't available during phase:3 or phase:4. Note that you must be careful not to inherit a disruptive action into a rule in this phase as this is a configuration error in ModSecurity 2.5.0 and later versions