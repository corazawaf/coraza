---
title: Operators
keywords: operators, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: operators.html
folder: mydoc
summary: This document contains the detailed configurations for each operators. Most of the data was copied from the ModSecurity WIKI
---


{% for op in site.data.operators %}
{% assign o = op[1] %}
## {{ o.name }}
{% if o.deprecated == true %}
{% include callout.html content="**Deprecated**: This Operator is deprecated and won't work anymore." type="danger" %} 
{% endif %}
{% if o.experimental == true %}
{% include callout.html content="**Experimental**: Might change or disappear in future releases." type="warning" %} 
{% endif %}
**Description:** {{ o.description }}

**Version:** {{ o.version }}

**Example:** 
```
{{ o.example }}
```

{{ o.data }}
{% endfor %}