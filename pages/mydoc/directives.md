---
title: Directives
keywords: directives, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: directives.html
folder: mydoc
summary: This document contains the detailed configurations for each directive. Most of the data was copied from the ModSecurity WIKI
---


{% for dir in site.data.directives %}
{% assign d = dir[1] %}
## {{ d.name }}
{% if d.supported == false and d.deprecated != true %}
{% include callout.html content="**Important information**: This Directive is currently not supported but might be added in the future." type="danger" %} 
{% endif %}
{% if d.deprecated == true %}
{% include callout.html content="**Deprecated**: This Directive is deprecated and won't work anymore." type="danger" %} 
{% endif %}
**Description:** {{ d.description }}

**Syntax:** ``{{ d.syntaxis }}``

{% if d.default != null and d.default != "" %}
**Default:** {{ d.default }}
{% endif %}

{% if d.example != null and d.example != "" %}
**Example Usage:** ``{{ d.example }}``
{% endif %}

{% if d.version != null and d.version != "" %}
**Version:** {{ d.version }}
{% endif %}

{{ d.data }}
{% endfor %}