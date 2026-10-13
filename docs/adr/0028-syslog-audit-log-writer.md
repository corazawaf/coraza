# ADR-0028: Syslog audit log writer

- **Status:** accepted
- **Date:** 2025-07-21
- **Version:** v3.4.0
- **PR:** [#1383](https://github.com/corazawaf/coraza/pull/1383)
- **Issue(s):** No linked issue
- **Deciders:** @Serjick, @jcchavezs
- **Category:** Feature

## Context and Problem

Coraza had HTTPS audit forwarding ([ADR-0003](0003-https-audit-log-writer.md))
and file-based writers, but many environments route through syslog —
rsyslog, journald, or a remote aggregator. Shipping without syslog was a
gap for traditional infra.

## Decision Drivers

- No new dependencies — the Go stdlib `log/syslog` suffices.
- Fit the existing `plugintypes.AuditLogWriter` shape so no formatter
  changes are needed.
- Reasonable defaults: facility `local0`, `LOG_INFO` for normal audit
  entries, `LOG_ERR` for interrupted transactions.
- Flexible destination string so operators can target any network/raddr
  supported by `log/syslog`.

## Considered Options

- Third-party syslog client with structured-data support.
- `log/syslog` stdlib.

## Decision Outcome

Chosen: **stdlib `log/syslog`**, with directive integration:

- `SecAuditLogType syslog`
- `SecAuditLog network://raddr` (e.g. `udp://127.0.0.1:514`,
  `unixgram:///var/run/syslog`); empty lets `log/syslog` choose.

Two explicit platform limitations are called out in the PR body:

> "Not available for tinygo because of not verified `log/syslog` support.
> Not available for windows and plan9 operating systems because of
> `log/syslog` limitations."
> — @Serjick (PR body)

## Technical Discussion

No substantive technical debate took place on the PR thread. Review
activity was limited to a coverage-bump round:

> "I've taken steps to increase test coverage of `syslog_writer.go`, please
> rerun pipeline."
> — @Serjick ([comment](https://github.com/corazawaf/coraza/pull/1383#issuecomment-3077277446))

The author had clearly thought through the mapping of severity and
destination; reviewers approved on that basis with no architectural
counter-proposal.

## Participants

- @Serjick — author
- @jcchavezs — review

## Consequences

- **Positive:** Coraza slots into traditional syslog-based logging pipelines
  without an external collector; interrupted transactions get higher
  severity automatically.
- **Negative:** Windows, Plan 9 and TinyGo builds cannot use the writer.

## References

- PR: https://github.com/corazawaf/coraza/pull/1383
- Related ADRs: ADR-0003 (HTTPS audit log writer), ADR-0005 (formatter
  interface)
