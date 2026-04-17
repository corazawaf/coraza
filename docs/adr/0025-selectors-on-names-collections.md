# ADR-0025: Selectors on `*_NAMES` collections

- **Status:** accepted
- **Date:** 2025-05-30
- **Version:** v3.4.0
- **PR:** [#1143](https://github.com/corazawaf/coraza/pull/1143)
- **Issue(s):** No linked issue (docs-referenced crash)
- **Deciders:** @blotus, @LaurenceJJones, @fzipi, @jcchavezs, @jptosso
- **Category:** Parity (ModSecurity parity + remove runtime `panic`s)

## Context and Problem

The canonical selector-on-names rule
`SecRule &REQUEST_COOKIES_NAMES:JSESSIONID "@eq 0" "id:45"`
is supported by ModSecurity and appears in Coraza's own docs, but in Coraza
it triggered an explicit `panic`. The fix extends the engine in three
coordinated ways so (a) this rule works, (b) the error is caught at parse
time, and (c) the engine never `panic`s at runtime.

## Decision Drivers

- Make docs-example rules actually work.
- Coraza is embedded — `panic` is not a graceful failure mode.
- Catch invalid selectors at parse time, before traffic flows.

## Considered Options

- Leave the `panic`, document the limitation.
- Hard-code which collections are selectable.
- Tag selectability in metadata comments on the variable definition and
  derive `CanBeSelected` from that.

## Decision Outcome

Chosen: **metadata-comment-driven selectability + `NamedCollectionNames`
implements `collection.Keyed` + runtime `panic`s replaced by parser errors
or error logs**. The author acknowledged the comment-as-metadata trick is
not ideal:

> "I don't know if I'm really happy with embedding information in comments,
> but it was the least intrusive way I found to handle this."
> — @blotus (PR body)

The complexity concern was surfaced by @jptosso for a future refactor:

> "Interesting, thank you very much for your contribution. Im a bit worried
> about how the complexity of variables is growing. Maybe not for this PR,
> but we need to improve generation of code, even for this 'selectable'
> feature"
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/1143#issuecomment-2329129961))

## Technical Discussion

Three areas changed together:

- **Parser check.** `CanBeSelected` is consulted during rule parsing so
  un-selectable collections fail fast rather than at runtime.
- **`NamedCollectionNames` implements `Keyed`.** `Get`, `FindString`,
  `FindRegex` all return the same value for key and value because
  `*_NAMES` collections return names, not values.
- **No more `panic`.** Four `panic` sites were replaced with parse-time
  errors or error-log calls; the remaining defensive logs only trigger
  if a collection is marked selectable but does not implement `Keyed`.

## Participants

- @blotus — author
- @LaurenceJJones — review
- @fzipi — review
- @jcchavezs — review
- @jptosso — review (flagged complexity growth)

## Consequences

- **Positive:** Docs-example rules run; configuration errors surface at
  parse time; Coraza no longer crashes a host process from inside the WAF.
- **Negative / follow-up:** Variable metadata is carried as comments (a
  minor maintenance hazard); full code-gen of the variables table is
  captured as a follow-up concern.

## References

- PR: https://github.com/corazawaf/coraza/pull/1143
