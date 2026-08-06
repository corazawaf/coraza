# ADR-0032: `ctl:auditLogParts` `+`/`-` modification syntax

- **Status:** accepted
- **Date:** 2026-01-13
- **Version:** v3.4.0
- **PR:** [#1467](https://github.com/corazawaf/coraza/pull/1467)
- **Issue(s):** No linked issue (ModSecurity compatibility)
- **Deciders:** @fzipi, @jcchavezs, @Copilot (reviewer)
- **Category:** Parity (ModSecurity parity — `ctl` grammar extension)

## Context and Problem

ModSecurity's `ctl:auditLogParts=+X` and `ctl:auditLogParts=-X` lets a rule
*add* or *remove* specific audit-log parts on the fly without listing every
part again. Coraza only accepted absolute replacement (`ctl:auditLogParts=ABCDEFZ`),
which forces rule authors to know every current part.

## Decision Drivers

- ModSecurity parity for a commonly-used `ctl` form.
- Preserve audit-log part ordering when modifying.
- Fail fast on malformed modifications (`++`, `--`).

## Considered Options

- Map-based de-duplication for parts.
- Slice + `slices.Contains` for ordered iteration.
- Accept both `+`/`-` and absolute forms in one function.

## Decision Outcome

Chosen: **one function `ApplyAuditLogParts` handling both forms**, backed
by an ordered slice of valid parts (not a map) because part ordering
matters for the audit log layout.

> "either we use ordered in all or we use validHere because otherwise we
> are reordering the parts."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1467#discussion_r2680503702))

> "let's get rid of this and use `slice.Contains` with orderedAuditLogParts.
> While map is supposed to be O(1) for small sets, iteration performs
> better so I'd rather to that."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1467#discussion_r2688076857))

Malformed inputs are rejected by the existing `validOpts` check:

> "None, as this is checked by `validOpts`. It will be rejected with
> `invalid audit log parts +`."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1467#discussion_r2681944724))

## Technical Discussion

**`map` vs `slice` debate.** @jcchavezs initially proposed
`map[AuditLogPart]struct{}` for set semantics; reverted to
`slices.Contains` for ordering + better small-N performance.

**Pathological modifications.** @jcchavezs explicitly asked about `++`:

> "What if moditication is `++` or `--`?"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1467#discussion_r2680505932))

…answered by @fzipi above: rejected with a clear error.

**Copilot-reviewer hot-path concern** (deferred):

> "The orderedParts slice is recreated on every call to
> `ApplyAuditLogParts`. Consider moving this to a package-level variable
> to avoid repeated allocations, especially since this is in a critical
> path"
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1467#discussion_r2678672834))

Reviewers merged on the trade-off between readability and micro-alloc cost;
a package-level variable is an easy follow-up if profiling surfaces it.

## Participants

- @fzipi — author
- @jcchavezs — review (drove slice-vs-map decision)
- @Copilot — PR reviewer bot (hot-path concern)

## Consequences

- **Positive:** ModSecurity-style additive/subtractive audit-log-part
  tuning works in Coraza; rules no longer need to restate every part.
- **Negative / follow-up:** `orderedParts` slice re-allocated per call;
  small, but worth profiling if noticed on the hot path.

## References

- PR: https://github.com/corazawaf/coraza/pull/1467
- Follow-up (Copilot-driven): https://github.com/corazawaf/coraza/pull/1468
