# ADR-0018: OCSF (v1.2.0) audit log format

- **Status:** accepted
- **Date:** 2024-09-17
- **Version:** v3.3.0
- **PR:** [#1089](https://github.com/corazawaf/coraza/pull/1089)
- **Issue(s):** No linked issue (adopts OCSF schema)
- **Deciders:** @durg78, @jcchavezs, @fzipi, @M4tteoP, @jptosso
- **Category:** Feature

## Context and Problem

Modern SIEM tooling converges on OCSF (Open Cybersecurity Schema Framework).
Coraza shipped with a native text format and a JSON format, neither of which
maps cleanly into OCSF-aligned pipelines. Downstream consumers had to rebuild
the OCSF record themselves.

## Decision Drivers

- Fit cleanly into OCSF-based observability stacks (SIEMs, XDRs).
- Reuse an upstream schema library (`github.com/valllabh/ocsf-schema-golang`)
  rather than hand-roll field mappings.
- Keep the native/JSON formats as the default — OCSF is opt-in.

## Considered Options

- Add an OCSF wrapper around the existing JSON formatter.
- Adopt OCSF v1.2.0 directly as a new formatter plugin.
- Defer until OCSF adoption stabilises.

## Decision Outcome

Chosen: **OCSF v1.2.0 as a new formatter plugin**, opt-in. Native and JSON
formatters stay the defaults.

> "I think this is great. Being a existing format honestly feels this is
> better than our JSON format or the modsec one which I am not 100% sure fits
> in modern tooling. My only request here is that we should avoid changing
> the transaction to support a format. Audit log formats are pluggable and
> we should be able to either do everything with what we have or extend what
> we have to support new use cases but that does not include changing the
> internal API."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1089#issuecomment-2189072268))

> "I don't think we want to recommend this by default as this feels like a
> breaking change."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1089#discussion_r1652872889))

> "Audit log is pluggable hence users might define their own, I don't think
> we can support a strict type for this."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1089#discussion_r1652879947))

> "Agreed. We should keep the native as default for now."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1089#discussion_r1652910194))

## Technical Discussion

Two cross-cutting issues surfaced during review.

**1. Go version bump.** OCSF dependency forced Go 1.22, and
`reflect.StringHeader` got deprecated in 1.21 along the way:

> "reflect.StringHeader was deprecated in go 1.21, this was causing the lint
> check to fail. I wasn't sure how best to handle that other than adding an
> exception for now."
> — @durg78 ([review](https://github.com/corazawaf/coraza/pull/1089#discussion_r1652986174))

> "We can also use inline linter nochecks"
> — @jptosso ([review](https://github.com/corazawaf/coraza/pull/1089#discussion_r1653127458))

The real fix landed separately as PR #1162 — see
[ADR-0019](0019-unsafe-stringdata-refactor.md).

**2. Respect the plugin boundary.** @jcchavezs specifically rejected any
change to the internal `Transaction` type to accommodate OCSF-specific
fields:

> "I doubt the internal transaction has to know about all these fields. I
> wonder if this could happen in the internal/auditlog#Transaction type."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1089#discussion_r1652885811))

The implementation was restructured to stay within the formatter package.

**3. Rebase + TinyGo.** @M4tteoP asked for a rebase to pick up TinyGo
updates (PR #1148). After the rebase:

> "Checks are passing now! 🎉"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1089#issuecomment-2342227609))

## Participants

- @durg78 — author
- @jcchavezs — review (drove plugin-boundary discipline, Go-version policy)
- @fzipi — review (merge sign-off, default-format guidance)
- @M4tteoP — review (TinyGo rebase)
- @jptosso — review (linter-exception suggestion)

## Consequences

- **Positive:** Modern SIEM ingestion without downstream re-mapping; a clean
  validation that the formatter plugin boundary holds for non-trivial
  schemas.
- **Negative / follow-up:** Coraza's Go minimum version moved forward;
  `reflect.StringHeader` deprecation surfaced (fixed in ADR-0019).

## References

- PR: https://github.com/corazawaf/coraza/pull/1089
- OCSF schema lib: https://github.com/valllabh/ocsf-schema-golang
- Related ADRs: ADR-0005 (formatter interface), ADR-0019 (unsafe.StringData),
  ADR-0028 (syslog writer)
