# ADR-0015: Case-sensitive map types

- **Status:** accepted
- **Date:** 2024-05-01
- **Version:** v3.2.0
- **PR:** [#1055](https://github.com/corazawaf/coraza/pull/1055)
- **Issue(s):** No linked issue (foundation for [#1042](https://github.com/corazawaf/coraza/issues/1042))
- **Deciders:** @fzipi, @M4tteoP, @jcchavezs, @jptosso
- **Category:** Feature (foundation API)

## Context and Problem

All Coraza map-backed collections normalised keys to lowercase. That is the
wrong default for most HTTP semantics — argument names, JSON keys, and XML
element names are case-sensitive per RFC. Making the whole engine
case-sensitive in a minor release would silently break rules that assumed the
old lowercasing.

## Decision Drivers

- Move toward RFC-correct case-sensitivity without a hard v3 break.
- Keep the existing case-insensitive maps working for backwards
  compatibility.
- Make the case-sensitive type available so follow-up work
  ([ADR-0016](0016-case-sensitive-args.md)) can enable it per-collection.

## Considered Options

- Flip all maps to case-sensitive now (breaking change in v3.x).
- Add a parallel `NamedCollection` / map type with case-sensitive keys; keep
  the case-insensitive one as the default.
- Defer all changes until v4.

## Decision Outcome

Chosen: **add parallel case-sensitive map type as a new type alongside the
existing one.** The switch-the-default change is deferred to v4.

> "LGTM, what is the plan here? Merge this in Coraza 3.x and then hold #1042
> (The breaking change) as part of v4 milestones"
> — @M4tteoP (implied by author confirmation in PR thread; captured in
> [case-sensitive args follow-up](https://github.com/corazawaf/coraza/pull/1059))

> "I'll be pushing smaller changes until we figure it out. I don't think this
> will break the api for a major release though."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1055#issuecomment-2088587799))

## Technical Discussion

Minor style / docs nits only. @jptosso referenced RFC 2616 on header-field
combining rules, confirming which fields legitimately keep multi-value
behaviour:

> "RFC 2616 — Multiple message-header fields with the same field-name MAY be
> present in a message if and only if the entire field-value for that header
> field is defined as a comma-separated list …"
> — @jptosso ([review](https://github.com/corazawaf/coraza/pull/1055#discussion_r1582694847))

No architectural debate on the shape of the new type itself.

## Participants

- @fzipi — author
- @M4tteoP — review (v4 plan)
- @jcchavezs — review (doc nit)
- @jptosso — review (RFC reference)

## Consequences

- **Positive:** A case-sensitive map type exists and can be adopted per
  collection (see ADR-0016).
- **Negative / follow-up:** Two map types coexist; the full switch to
  case-sensitive by default is a v4 task.

## References

- PR: https://github.com/corazawaf/coraza/pull/1055
- Related ADRs: ADR-0016 (case-sensitive args)
