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
| [0007](0007-uppercase-transformation.md) | [#935](https://github.com/corazawaf/coraza/pull/935) | 2023-12-18 | v3.1.0 | P | `uppercase` transformation |
| [0008](0008-transaction-context.md) | [#963](https://github.com/corazawaf/coraza/pull/963) | 2024-01-31 | v3.1.0 | F | Transaction `context.Context` plumbing |
| [0009](0009-structured-logging.md) | [#971](https://github.com/corazawaf/coraza/pull/971) | 2024-02-01 | v3.1.0 | R | Structured `debuglog` facade |
| [0010](0010-raw-body-processor.md) | [#983](https://github.com/corazawaf/coraza/pull/983) | 2024-02-06 | v3.1.0 | F | `raw` request body processor |
| [0011](0011-expose-expected-directives.md) | [#1012](https://github.com/corazawaf/coraza/pull/1012) | 2024-03-08 | v3.2.0 | F | Expose expected directives for e2e |
| [0012](0012-secruleupdatetargetbytag.md) | [#1020](https://github.com/corazawaf/coraza/pull/1020) | 2024-03-28 | v3.2.0 | P | `SecRuleUpdateTargetByTag` + ID ranges |
| [0013](0013-tinygo-formatter-registration.md) | [#1027](https://github.com/corazawaf/coraza/pull/1027) | 2024-04-02 | v3.2.0 | P | TinyGo formatter registration |
| [0014](0014-base64decodeext-transformation.md) | [#1046](https://github.com/corazawaf/coraza/pull/1046) | 2024-04-24 | v3.2.0 | P | `base64DecodeExt` transformation |
| [0015](0015-case-sensitive-maps.md) | [#1055](https://github.com/corazawaf/coraza/pull/1055) | 2024-05-01 | v3.2.0 | F | Case-sensitive maps |
| [0016](0016-case-sensitive-args.md) | [#1059](https://github.com/corazawaf/coraza/pull/1059) | 2024-05-28 | v3.2.0 | P | Case-sensitive args support |
| [0017](0017-multipart-strict-error.md) | [#1098](https://github.com/corazawaf/coraza/pull/1098) | 2024-07-18 | v3.3.0 | P | `MULTIPART_STRICT_ERROR` variable |
| [0018](0018-ocsf-audit-log.md) | [#1089](https://github.com/corazawaf/coraza/pull/1089) | 2024-09-17 | v3.3.0 | F | OCSF audit log format |
| [0019](0019-unsafe-stringdata-refactor.md) | [#1162](https://github.com/corazawaf/coraza/pull/1162) | 2024-10-04 | v3.3.0 | R | `reflect.StringHeader` → `unsafe.StringData` |
| [0020](0020-secruleupdateactionbyid.md) | [#1071](https://github.com/corazawaf/coraza/pull/1071) | 2024-10-31 | v3.3.0 | P | `SecRuleUpdateActionById` directive |
| [0021](0021-square-brackets-in-variables.md) | [#1226](https://github.com/corazawaf/coraza/pull/1226) | 2024-11-21 | v3.3.0 | P | Square brackets in macro variables |
| [0022](0022-time-variables.md) | [#1223](https://github.com/corazawaf/coraza/pull/1223) | 2024-12-09 | v3.3.0 | P | `TIME_*` variables |
| [0023](0023-base64encode-transformation.md) | [#1257](https://github.com/corazawaf/coraza/pull/1257) | 2024-12-29 | v3.3.0 | P | `base64Encode` transformation |
| [0024](0024-hexdecode-transformation.md) | [#1275](https://github.com/corazawaf/coraza/pull/1275) | 2025-01-24 | v3.3.2 | P | `hexDecode` transformation |

Categories: **F**eature · **P**arity · **⚡** Perf · **R**efactor
