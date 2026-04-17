# ADR-0029: JSON schema audit log improvements

- **Status:** accepted
- **Date:** 2025-08-11
- **Version:** v3.4.0
- **PR:** [#1384](https://github.com/corazawaf/coraza/pull/1384) (rework of [#1343](https://github.com/corazawaf/coraza/pull/1343))
- **Issue(s):** No linked issue
- **Deciders:** @jcchavezs, @M4tteoP, @airween, @fzipi, @cognitivegears
- **Category:** Feature

## Context and Problem

The original JSON-schema work ([#1343](https://github.com/corazawaf/coraza/pull/1343))
added JSON-schema-validation scaffolding to Coraza's audit logging layer, but
left open questions: what's the right SecLang directive, and does Coraza need
to distinguish XML vs. JSON external-entity handling explicitly? This PR
picked up the rework and shipped the improvements.

## Decision Drivers

- Keep naming sensible for non-XML (JSON) contexts.
- Stay compatible with the future ModSecurity direction for JSON-schema
  validation.
- Preserve the audit log contract — additional recorded variables must not
  break existing consumers.

## Considered Options

- Reuse `SecXmlExternalEntity` as an umbrella directive for schema-enable
  toggles.
- Introduce `SecJsonExternalEntity` mirroring the XML directive name.
- Introduce `@validateSchema` operator that works on both JSON and XML
  targets, plus a matching directive.

## Decision Outcome

Chosen: **merge the rework and settle naming in a follow-up thread.** The
operator name and directive ambiguity are acknowledged as unresolved at
merge time.

> "I will merge this and we can settle the extra flag in another thread."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1384#issuecomment-3096079652))

## Technical Discussion

**Naming collaboration with upstream ModSecurity.** @airween volunteered the
intended ModSecurity direction:

> "if you want to follow the XMl's validation method, then I suggest to use
> this keyword. There is a plan to add this feature (JSON schema validation)
> to ModSecurity, and I think it will be used there."
> — @airween ([comment](https://github.com/corazawaf/coraza/pull/1384#issuecomment-3065045886))

@jcchavezs asked for the name clarification:

> "You mean to use `SecJsonExternalEntity` or `SecXmlExternalEntity`?"
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1384#issuecomment-3066672310))

**Unified operator proposal.** @M4tteoP sketched a shared operator shape:

> "```
> SecXmlExternalEntity On
> SecRule XML \"@validateSchema /path/to/xml.xsd\"
> ```
> So, in the context of JSON it could become:
> ```
> SecJsonExternalEntity On
> SecRule JSON \"@validateSchema /path/to/schema.json\"
> ```
> The operator `@validateSchema` can be flexible enough to deal with both
> json and XML based on the variable or/and the extension of the provided
> schema."
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1384#issuecomment-3067129756))

## Participants

- @jcchavezs — author of rework
- @M4tteoP — review (proposed unified operator)
- @airween — review (ModSecurity-roadmap input)
- @fzipi — review
- @cognitivegears — original work in #1343

## Consequences

- **Positive:** JSON-schema-related audit improvements ship in v3.4.0,
  closing the long-running #1343 workstream.
- **Negative / follow-up:** Naming (`SecJsonExternalEntity` vs reused XML
  directive) remains to be settled; `@validateSchema` unified-operator
  proposal is captured for follow-up.

## References

- PR: https://github.com/corazawaf/coraza/pull/1384
- Original: https://github.com/corazawaf/coraza/pull/1343
- ModSecurity XML reference: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#SecXmlExternalEntity
