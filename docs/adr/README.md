# Architecture Decision Records

An ADR records a structural decision — what was decided, what the alternatives were,
and why one was chosen — at the time it was made. It is not a changelog entry and not
a design document: `CHANGELOG.md` says what changed, an ADR says why that shape and
not another.

## When to write one

Write an ADR when a change alters the shape of Coraza:

- a new directive, operator, action, transformation, variable or collection
- a new subsystem, or a new plugin / experimental surface
- a breaking change to a public API
- an algorithmic or allocation change that shifts performance characteristics
- an internal refactor that changes how a subsystem is structured

Skip it for bugfixes, documentation, CI, chores and dependency bumps. If a reviewer
has to ask "why this way?", that is the signal.

The ADR belongs in the PR that makes the change, so the reasoning is captured while
the alternatives are still live. Reconstructing one months later recovers only what
happened to reach GitHub.

## How to write one

1. Copy [`0000-template.md`](0000-template.md) to `NNNN-short-slug.md`, taking the
   next free number.
2. Fill in every header field — `Status`, `Date`, `Version`, `PR`, `Issue(s)`,
   `Deciders`, `Category`. Use "No linked issue" rather than dropping `Issue(s)`.
   `Category` must be exactly one of **Feature**, **Parity**, **Perf** or
   **Refactor**, optionally followed by a single parenthetical qualifier and
   nothing else (`Parity (ModSecurity parity)`). One record counts under one
   category — if a change feels like two, name the one that drove it.
   `Performance` is not a spelling of `Perf`.
3. Write the body. Keep `Considered Options` honest: if there was only ever one
   option, say so rather than inventing rivals for it.
4. Quote the discussion **inside** `## Technical Discussion`, following the quoting
   rules in the template — verbatim, one comment per blockquote, `[…]` for every
   omission. A quote elsewhere in the document does not count: that section is where
   a reader looks for the evidence. If there was no substantive discussion, use the
   marker sentence. That is a normal outcome, not a gap to paper over.
5. Add a row to the index below.

Run `go run mage.go adr` to check the format before pushing. CI runs the same check
on any PR touching `docs/adr/`.

## What the check does and does not cover

`mage adr` validates structure offline: filenames, the header block (all seven fields,
read only from above the first section so a stray line further down cannot stand in for
a missing one), the `Status` and `Category` vocabularies, that the `## Technical
Discussion` section itself carries either a permalinked quote or the marker, that quote
permalinks point at this repository, and that the index below matches the files on disk.

It cannot verify that a quote matches what the person actually wrote. That is a
reviewer's job — open the permalink and read it. A quote is the one part of an ADR
that puts words in someone else's mouth, so it is the part worth checking by hand.

## Status values

`proposed` · `accepted` · `superseded by ADR-NNNN` · `deprecated`

Superseding does not delete the old record. Set its status and let the history stand.

## Index

| ADR | PR | Merged | Version | Cat. | Title |
|-----|----|--------|---------|------|-------|
| [0001](0001-response-args-collection.md) | [#811](https://github.com/corazawaf/coraza/pull/811) | 2023-06-12 | v3.0.1 | P | RESPONSE_ARGS collection |
| [0002](0002-secargumentslimit-directive.md) | [#812](https://github.com/corazawaf/coraza/pull/812) | 2023-06-14 | v3.0.2 | P | SecArgumentsLimit directive |
| [0003](0003-https-audit-log-writer.md) | [#826](https://github.com/corazawaf/coraza/pull/826) | 2023-07-11 | v3.0.3 | F | HTTPS audit log writer |
| [0004](0004-matchedrule-log-method.md) | [#848](https://github.com/corazawaf/coraza/pull/848) | 2023-07-25 | v3.0.3 | F | `MatchedRule.Log()` method |
| [0005](0005-auditlogformatter-interface.md) | [#850](https://github.com/corazawaf/coraza/pull/850) | 2023-08-06 | v3.0.3 | R | `AuditLogFormatter` interface |
| [0006](0006-regex-ahocorasick-memoize.md) | [#836](https://github.com/corazawaf/coraza/pull/836) | 2023-08-06 | v3.0.3 | ⚡ | Regex & Aho-Corasick memoize cache |

Categories: **F**eature · **P**arity · **⚡** Perf · **R**efactor
