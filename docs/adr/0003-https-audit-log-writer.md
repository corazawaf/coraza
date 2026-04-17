# ADR-0003: HTTPS audit log writer

- **Status:** accepted
- **Date:** 2023-07-11
- **Version:** v3.0.3
- **PR:** [#826](https://github.com/corazawaf/coraza/pull/826)
- **Issue(s):** Discussion [#813](https://github.com/corazawaf/coraza/issues/813)
- **Deciders:** @jptosso, @jcchavezs, @anuraaga
- **Category:** Feature

## Context and Problem

Prior to v3.0.3 Coraza could write audit logs to disk but had no pluggable way
to ship them over HTTP(S) to a remote collector. ModSecurity had a similar
feature via MLOGC; modern deployments want TLS-capable remote audit streaming
without MLOGC-era constraints.

## Decision Drivers

- Enable cloud-native audit shipping (TLS, HTTP-based SIEM ingestion).
- Intentionally drop MLOGC compatibility — it is a v2-era protocol.
- Honour the formatter's MIME type so remote collectors can decode correctly.

## Considered Options

- Batched remote writes (accumulate N records, flush on timer).
- Per-record HTTP writes, no batching, accept the loss of efficiency for v3.
- Ship a full pluggable exporter subsystem now.

## Decision Outcome

Chosen: **per-record HTTP writes now; defer batching to v4** because Coraza
v3 has no `WAF.Close()` method, so buffered records cannot be safely flushed
on shutdown.

> "Unfortunatelly we can't do bathing as we can't close the exporter (WAF does
> not support close method and hence when terminating the APP the batched
> requests will be lost). I think it is a good idea to add a Close method now
> but not to force people to use it and maybe the exporter can listen to
> termination signal"
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/826#issuecomment-1607190436))

MIME-type awareness was introduced alongside this PR via the formatter
interface refactor in [ADR-0005](0005-auditlogformatter-interface.md).

## Technical Discussion

Substantive review focused on lifecycle, transport hygiene, and future-proofing.

**Lifecycle / Close:** the missing `WAF.Close()` blocked batching and shaped
the whole design. The v3 compromise was "send one request per audit record,
revisit in v4". That revisit eventually landed in v3.5.0 as
[ADR-0043](0043-waf-close-per-owner-memoize.md).

**Transport hygiene.** @jcchavezs flagged two concrete HTTP-client issues:

> "I think any 2xx should be accepted. Restricting to OK feels mistaken as 201
> and 204 are also valid status codes."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/826#discussion_r1241901929))

> "Please drain the body before closing it using something like
> `io.Copy(io.Discard, res.Body)` to be able to reuse the connection."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/826#discussion_r1241902417))

Both were applied.

**Content type.** @jcchavezs noted the missing Content-Type plumbing, which
led directly to the formatter-interface refactor:

> "One thing missing here is the content type support. We could add it to
> formatters (yet not to the interface) and do interface assertion ok init and
> record the value to be added to the requests."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/826#issuecomment-1630021852))

Out-of-band decision-making is called out explicitly on the PR:

> "Decisions we made during meeting
> https://owasp.slack.com/archives/C02BXH135AT/p1687955362171029"
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/826#issuecomment-1612492704))

The Slack thread itself is not visible to outside readers.

## Participants

- @jptosso — author
- @jcchavezs — review (lifecycle, transport, content-type)
- @anuraaga — review

## Consequences

- **Positive:** First-party HTTPS audit forwarding; MIME-aware so JSON,
  native, and OCSF formatters can share the writer.
- **Negative / follow-up:** No batching, no retry, no backoff — a record per
  HTTP request. Higher-level reliability is left to the operator (SIEM-side
  buffering). Batching awaits `WAF.Close()` (shipped in v3.5.0 —
  [ADR-0043](0043-waf-close-per-owner-memoize.md)).
- Drops MLOGC compatibility by design.

## References

- PR: https://github.com/corazawaf/coraza/pull/826
- Related ADRs: ADR-0005 (AuditLogFormatter interface), ADR-0028 (syslog
  audit writer), ADR-0043 (`WAF.Close()`)
