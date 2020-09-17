---
title: Actions
keywords: actions, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: actions.html
folder: mydoc
---

Each action belongs to one of five groups:

* **Disruptive actions -** Cause Coraza to do something. In many cases something means block transaction, but not in all. For example, the allow action is classified as a disruptive action, but it does the opposite of blocking. There can only be one disruptive action per rule (if there are multiple disruptive actions present, or inherited, only the last one will take effect), or rule chain (in a chain, a disruptive action can only appear in the first rule).

Note : Disruptive actions will NOT be executed if the SecRuleEngine is set to DetectionOnly. If you are creating exception/whitelisting rules that use the allow action, you should also add the ctl:ruleEngine=On action to execute the action.

* **Non-disruptive actions -** Do something, but that something does not and cannot affect the rule processing flow. Setting a variable, or changing its value is an example of a non-disruptive action. Non-disruptive action can appear in any rule, including each rule belonging to a chain.
* **Flow actions -** These actions affect the rule flow (for example skip or skipAfter).
* **Meta-data actions -** Meta-data actions are used to provide more information about rules. Examples include id, rev, severity and msg.
* **Data actions** - Not really actions, these are mere containers that hold data used by other actions. For example, the status action holds the status that will be used for blocking (if it takes place).

{% for act in site.data.actions %}
{% assign a = act[1] %}
## {{ a.name }}
{% if a.deprecated == true %}
{% include callout.html content="**Deprecated**: This Action is deprecated and won't work anymore." type="danger" %} 
{% endif %}
**Description:** {{ a.description }}

**Version:** {{ a.version }}

**Example:** 
```
{{ a.example }}
```

{{ a.data }}
{% endfor %}