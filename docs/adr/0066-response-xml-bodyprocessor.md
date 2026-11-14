# ADR-0066: `RESPONSE_XML` body processor

- **Status:** proposed
- **Date:** 2026-10-15
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1769](https://github.com/corazawaf/coraza/pull/1769)
- **Issue(s):** [#1714](https://github.com/corazawaf/coraza/issues/1714)
- **Deciders:** @fzipi
- **Category:** Feature

## Context and Problem

ModSecurity historically supported XML body processing only for inbound request bodies:
ModSecurity v2 registered the `XML` variable during the request-body phase (`re_variables.c`),
and ModSecurity v3 provided `ctl:requestBodyProcessor=XML` without any corresponding mechanism
for response bodies. Neither engine offers `RESPONSE_XML` or response-phase XML inspection.

Coraza introduced the `RESPONSE_XML` target variable in its public interface (`ResponseXML()`),
intended to allow inspection of XML responses in phase 4 (e.g. following `ctl:responseBodyProcessor=XML`
in phase 3). However, `xmlBodyProcessor.ProcessResponse` was left as an unimplemented stub that
returned `nil` without parsing the response body. Consequently, rules referencing `RESPONSE_XML:/*`
or `RESPONSE_XML://@*` never matched any response payload.

Furthermore, the SecLang variable parser disambiguated XPath queries from regular expressions by
checking for exact `"XML"` or `"JSON"` prefixes, causing `REQUEST_XML:/*` and `RESPONSE_XML:/*`
to be misclassified as regular expressions rather than XPath selectors.

## Decision Drivers

- Provide full XML response inspection via `ctl:responseBodyProcessor=XML` and `RESPONSE_XML`
  to match the functionality available for `RESPONSE_ARGS` / JSON responses.
- Explicitly document `RESPONSE_XML` as a Coraza-only extension beyond ModSecurity parity.
- Enforce the same resource bounds on response parsing as request parsing, bounding collected
  XML attributes and contents by `SecArgumentsLimit` and setting `ARGUMENTS_LIMIT_REACHED=1`
  when truncated (analogous to response-side JSON bounds in ADR-0059).
- Fix SecLang variable parsing so `REQUEST_XML` and `RESPONSE_XML` (as well as case-folded
  `xml` and `json`) correctly identify XPath and JSONPath selectors.

## Considered Options

1. **Rely solely on raw `RESPONSE_BODY` with regexes:**
   Leave `RESPONSE_XML` unimplemented and require users to inspect raw response text.
   - *Drawback:* Regexes on XML are brittle, prone to evasion, and cannot cleanly select
     specific attributes (`//@*`) or text nodes (`/*`).
2. **Unbounded XML response parsing:**
   Parse all XML elements and attributes without applying argument limits.
   - *Drawback:* Malicious or oversized XML payloads could cause memory exhaustion by
     collecting unbounded numbers of attribute and text strings.
3. **Bounded `RESPONSE_XML` processing with `SecArgumentsLimit` (Chosen):**
   Implement `ProcessResponse` to populate `v.ResponseXML()` with attributes (`//@*`) and
   text contents (`/*`), bounded by `options.ArgumentLimit`. Set `ARGUMENTS_LIMIT_REACHED=1`
   when the limit is reached, matching the behavior of `jsonBodyProcessor.ProcessResponse`.

## Decision Outcome

Chosen: **Option 3**.

- `xmlBodyProcessor.ProcessResponse` parses the response stream using `encoding/xml` and
  populates `v.ResponseXML()` with attribute values (`//@*`) and text contents (`/*`).
- Both `ProcessRequest` and `ProcessResponse` respect `options.ArgumentLimit` (`SecArgumentsLimit`).
  When the combined total of attributes and text contents reaches the configured limit and additional
  items are encountered, collection stops and `ARGUMENTS_LIMIT_REACHED` is set to `1`.
- The SecLang variable parser recognizes `REQUEST_XML` and `RESPONSE_XML` (case-insensitively via
  `strings.EqualFold`) as path-based collections so leading slashes are parsed as XPath queries.

## Technical Discussion

No substantive technical discussion recorded on the issue thread.

## Participants

- @fzipi — reviewer

## Consequences

- **Positive:** WAF rules can now inspect XML responses using XPath selectors (`RESPONSE_XML:/*`
  and `RESPONSE_XML://@*`).
- **Positive:** Resource consumption is capped by `SecArgumentsLimit`, preventing memory exhaustion
  from expansive XML response documents.
- **Negative:** `RESPONSE_XML` and `ctl:responseBodyProcessor=XML` are Coraza-specific extensions
  not portable to upstream ModSecurity v2/v3 rule sets without conditional guards.

## References

- Issue: https://github.com/corazawaf/coraza/issues/1714
- PR: https://github.com/corazawaf/coraza/pull/1769
- Related ADRs: ADR-0001 (`RESPONSE_ARGS`), ADR-0002 (`SecArgumentsLimit`), ADR-0059 (`SecResponseBodyJsonDepthLimit`)
