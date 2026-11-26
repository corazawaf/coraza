# ADR-0063: sanitise* actions for audit log redaction

- **Status:** proposed
- **Date:** 2026-11-21 (expected)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1878](https://github.com/corazawaf/coraza/pull/1878)
- **Issue(s):** [#765](https://github.com/corazawaf/coraza/issues/765)
- **Deciders:** @ayushsinha322
- **Category:** Parity (ModSecurity v2 parity)

## Context and Problem

Audit logs can carry secrets: passwords in query strings and form bodies, bearer
tokens in `Authorization`, session cookies in `Set-Cookie`. ModSecurity v2 lets
rule writers keep them out of the audit log with the `sanitiseArg`,
`sanitiseRequestHeader`, `sanitiseResponseHeader` and `sanitiseMatched` actions,
which replace each byte of the value with an asterisk. Coraza rejected these
actions at parse time, so rulesets that use them could not be loaded and there was
no way to redact the audit log.

Issue #765 first proposed a new `SecAuditRedact` directive, then settled on reusing
ModSecurity's actions, with redaction applied before any formatter sees the data.

## Decision Drivers

- ModSecurity v2 compatibility: existing rulesets use these actions.
- Redaction must hold for every formatter (native, JSON, legacy JSON, OCSF) and
  for writer or formatter plugins, without each one reimplementing it.
- Rules must keep inspecting the original values.
- No cost for transactions that do not use the actions.

## Considered Options

- A new `SecAuditRedact` directive with static selectors, as first proposed in the
  issue.
- Reuse ModSecurity's actions and mark collection elements as redacted, so the
  collections carry the information.
- Reuse ModSecurity's actions, record the names to mask on the transaction, and
  mask copies of the data while `Transaction.AuditLog()` builds the record.

## Decision Outcome

Chosen: **reuse ModSecurity's actions and mask copies in
`Transaction.AuditLog()`**, because it is the design agreed in the issue, it keeps
collections and inspection untouched, it covers every formatter at once since they
all read the same record, and it adds no work when no sanitise action ran (the
redactor is `nil` and the record is built as before).

The actions record lowercased names on the transaction. `sanitiseMatched` reads the
variable and key of the last match, which `Transaction.matchVariable` now keeps.
When the record is built, the redactor masks:

- the query string of the request URI and of the `[uri]` field of error messages,
  by position, keeping every other pair as it was. Pairs are split on `&`, the
  separator the argument parsers use;
- the path of the same URIs, for sanitised `ARGS_PATH` arguments. Only the
  integration knows where a path argument sits, so the redactor looks for its
  value: a segment that decodes to the value is masked whole, however it is
  encoded, and elsewhere the value is masked where it appears literally;
- a copy of `ARGS`, which the OCSF formatter serialises;
- request and response headers, in the copies returned by `Data()`;
- an `application/x-www-form-urlencoded` request body by position;
- a JSON request body by position on its raw text, so a value is masked however
  it is escaped. The keys are built as the JSON body processor builds them
  (`bodyprocessors.MaskJSONValues`), and the walk works under the same depth
  limit and byte budget. A body it cannot walk to the end, because it goes past
  one of those or is not valid JSON, is masked whole;
- other body formats by masking each occurrence of a sanitised value;
- matched values, rule messages and log data, through a masked copy of each
  matched rule, which also produces the masked error message. The values looked
  for include the form a matched rule saw after its transformations, since that
  is what `%{MATCHED_VAR}` puts in its log data.

Behaviour that follows ModSecurity v2:

- Argument names are compared case-insensitively, also when Coraza is built with
  `coraza.rule.case_sensitive_args_keys`; redacting more is the safe direction.
- The error log and the debug log are not sanitised.
- `sanitiseMatched` ignores variables that are not arguments or headers. Coraza
  also accepts the `ARGS_GET`, `ARGS_POST` and `ARGS_PATH` variants, which v2 does
  not recognise but which always refer to an argument.

## Technical Discussion

Representative quotes from the issue thread:

> "Maybe instead of implementing a new directive, the same actions provided in ModSecurity could be reused: […]"
> — @funkluk ([comment](https://github.com/corazawaf/coraza/issues/765#issuecomment-3106368685))

> "I vote for reusing existing directives."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/issues/765#issuecomment-3151978904))

> "Triage: keep, retitled to the agreed design: reuse ModSecurity's `sanitise*` actions rather than a new directive. Redaction must happen before data reaches any formatter. This needs an ADR (new actions); help wanted."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/issues/765#issuecomment-6090475474))

## Participants

- @ayushsinha322 — author
- @funkluk — issue thread
- @jcchavezs — issue thread
- @fzipi — issue triage

## Consequences

- **Positive:** rulesets using the four actions load and behave as in ModSecurity
  v2. Redaction happens once, on the record, so every built-in audit log format
  and every formatter plugin gets the same masked data.
- **Negative / follow-up:** `sanitiseMatchedBytes` is not implemented.
- **Known limits.** A sanitised value still reaches the audit log when:
  - it is a path argument that is percent-encoded and is only part of a path
    segment, such as `/files/report-p%40ss.pdf`;
  - it sits in a body that is neither url-encoded nor JSON in a spelling other
    than the parsed value;
  - a rule wrote it into another variable in a changed form and a later rule
    logs that variable. Transformed forms are only known for the matches the
    record carries;
  - the request has more sanitised arguments than `SecArgumentsLimit` and a
    rule logs the raw URI or body in its message. Every one of them is masked
    by position in the URI and the body, but only `SecArgumentsLimit` raw
    spellings are looked for in free text, so that a request cannot make the
    record arbitrarily expensive to build.
- **Over-masking.** Free-text fields, paths and bodies that are neither
  url-encoded nor JSON are masked by value occurrence, so a short value is
  masked wherever the same text appears. A masked JSON number or boolean is no
  longer valid JSON.
- The request body is read once for the record, so the body that is logged is
  the one that was masked.
- The engine harness gained `AuditLogContains` and `NoAuditLogContains`
  assertions, which test the record across formatters, and a `PathArgs` input.

## References

- Issue: https://github.com/corazawaf/coraza/issues/765
- ModSecurity v2 reference manual, actions: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Actions
- Related ADRs: ADR-0005, ADR-0016, ADR-0018, ADR-0051
