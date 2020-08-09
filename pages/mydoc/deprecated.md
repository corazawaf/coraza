---
title: Deprecated Features
keywords: modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: deprecated-features.html
folder: mydoc
---

## Deprecated Directives

{% for dir in site.data.directives %}
{% assign d = dir[1] %}
  {% if d.deprecated == nil or d.deprecated == false %}
    {% continue %}
  {% endif %}
### {{ d.name }}

**Description:** {{ d.description }}

**Last version:** {{ d.version }}

**Deprecated Since:** {{ d.deprecated_version }}

{{ d.deprecated_reason }}
{% endfor %}

## Deprecated Actions

## Deprecated Variables