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

Listed in order of merge.

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
| [0025](0025-selectors-on-names-collections.md) | [#1143](https://github.com/corazawaf/coraza/pull/1143) | 2025-05-30 | v3.4.0 | P | Selectors on `*_NAMES` collections |
| [0026](0026-pmf-short-alias.md) | [#1356](https://github.com/corazawaf/coraza/pull/1356) | 2025-05-12 | v3.4.0 | P | `@pmf` short alias |
| [0027](0027-ipmatchf-short-alias.md) | [#1357](https://github.com/corazawaf/coraza/pull/1357) | 2025-05-13 | v3.4.0 | P | `@ipMatchF` short alias |
| [0028](0028-syslog-audit-log-writer.md) | [#1383](https://github.com/corazawaf/coraza/pull/1383) | 2025-07-21 | v3.4.0 | F | Syslog audit log writer |
| [0029](0029-json-schema-improvements.md) | [#1384](https://github.com/corazawaf/coraza/pull/1384) | 2025-08-11 | v3.4.0 | F | JSON schema audit log improvements |
| [0030](0030-secrequestbodyjsondepthlimit.md) | [#1110](https://github.com/corazawaf/coraza/pull/1110) | 2026-03-06 | v3.4.0 | F | `SecRequestBodyJsonDepthLimit` directive |
| [0031](0031-multipart-unexpected-eof.md) | [#1453](https://github.com/corazawaf/coraza/pull/1453) | 2026-03-06 | v3.4.0 | P | Ignore unexpected EOF in multipart |
| [0032](0032-ctl-auditlogparts-plus-minus.md) | [#1467](https://github.com/corazawaf/coraza/pull/1467) | 2026-01-13 | v3.4.0 | P | `ctl:auditLogParts` `+`/`-` syntax |
| [0033](0033-strmatch-operator.md) | [#1473](https://github.com/corazawaf/coraza/pull/1473) | 2026-01-15 | v3.4.0 | P | `@strmatch` operator |
| [0034](0034-rule-observer-callback.md) | [#1478](https://github.com/corazawaf/coraza/pull/1478) | 2026-02-24 | v3.4.0 | F | Optional rule observer callback |
| [0035](0035-wafwithrules-interface.md) | [#1492](https://github.com/corazawaf/coraza/pull/1492) | 2026-02-27 | v3.4.0 | F | `WAFWithRules` interface |
| [0036](0036-remove-root-experimental-dep.md) | [#1494](https://github.com/corazawaf/coraza/pull/1494) | 2026-02-24 | v3.4.0 | R | Remove root package dependency on `experimental` |
| [0037](0037-ctl-whole-collection-exclusion.md) | [#1495](https://github.com/corazawaf/coraza/pull/1495) | 2026-03-05 | v3.4.0 | P | `ctl:ruleRemoveTargetById` whole-collection exclusion |
| [0038](0038-map-for-ruleremovebyid.md) | [#1524](https://github.com/corazawaf/coraza/pull/1524) | 2026-03-06 | v3.4.0 | ⚡ | `map` for `ruleRemoveByID` O(1) lookup |
| [0039](0039-bulk-allocate-matchdata.md) | [#1530](https://github.com/corazawaf/coraza/pull/1530) | 2026-03-11 | v3.4.0 | ⚡ | Bulk-allocate `MatchData` in `collection.Find*` |
| [0040](0040-crslang-antlr4-buildtag.md) | [#1536](https://github.com/corazawaf/coraza/pull/1536) | 2026-03-08 | v3.4.0 | F | `crslang` ANTLR4 parser behind build tag |
| [0041](0041-ruleremovebyid-range-storage.md) | [#1538](https://github.com/corazawaf/coraza/pull/1538) | 2026-03-09 | v3.4.0 | ⚡ | `ruleRemoveById` range storage |
| [0042](0042-regex-memoize-default-on.md) | [#1540](https://github.com/corazawaf/coraza/pull/1540) | 2026-03-18 | v3.5.0 | ⚡ | Regex memoize enabled by default |
| [0043](0043-waf-close-per-owner-memoize.md) | [#1541](https://github.com/corazawaf/coraza/pull/1541) | 2026-03-11 | v3.5.0 | F | `WAF.Close()` + per-owner memoize tracking |
| [0044](0044-prefix-transformation-cache.md) | [#1544](https://github.com/corazawaf/coraza/pull/1544) | 2026-03-11 | v3.5.0 | ⚡ | Prefix-based transformation cache |
| [0045](0045-findstringsubmatchindex-noalloc.md) | [#1547](https://github.com/corazawaf/coraza/pull/1547) | 2026-03-11 | v3.5.0 | ⚡ | `FindStringSubmatchIndex` no-alloc path |
| [0046](0046-secuploadkeepfiles-directive.md) | [#1557](https://github.com/corazawaf/coraza/pull/1557) | 2026-03-19 | v3.5.0 | P | `SecUploadKeepFiles` directive |
| [0047](0047-regex-in-ctl-ruleremovetarget.md) | [#1561](https://github.com/corazawaf/coraza/pull/1561) | 2026-03-21 | v3.5.0 | F | Regex in `ctl:ruleRemoveTarget*` |
| [0048](0048-ndjson-body-processor.md) | [#1563](https://github.com/corazawaf/coraza/pull/1563) | 2026-03-21 | v3.5.0 | F | NDJSON (JSON Stream) body processor |
| [0049](0049-rx-literal-prefilter.md) | [#1534](https://github.com/corazawaf/coraza/pull/1534) | 2026-03-31 | v3.6.0 | ⚡ | `@rx` literal pre-filter |
| [0050](0050-secrxprefilter-directive.md) | [#1589](https://github.com/corazawaf/coraza/pull/1589) | 2026-04-05 | v3.7.0 | F | `SecRxPreFilter` directive |
| [0051](0051-audit-log-part-j.md) | [#1591](https://github.com/corazawaf/coraza/pull/1591) | 2026-04-03 | v3.7.0 | P | Audit log Part J (uploaded files) |
| [0052](0052-ahocorasick-to-bitmap.md) | [#1597](https://github.com/corazawaf/coraza/pull/1597) | 2026-04-09 | unreleased | ⚡ | Aho-Corasick → indexed-bitmap matcher |
| [0053](0053-pm-minlen-prefilter.md) | [#1601](https://github.com/corazawaf/coraza/pull/1601) | 2026-04-13 | unreleased | ⚡ | `@pm` `minLen` prefilter |
| [0054](0054-xml-unexpected-eof.md) | [#1452](https://github.com/corazawaf/coraza/pull/1452) | 2025-12-18 | v3.4.0 | P | Ignore unexpected EOF in XML body processor |

Categories: **F**eature · **P**arity · **⚡** Perf · **R**efactor

## Totals

**54 structural ADRs** across v3.0.0 → v3.7.0 (plus two unreleased
post-v3.7.0 changes on `main`):

| Category | Count | Share |
|---|---:|---:|
| Feature | 17 | 31 % |
| Parity | 23 | 43 % |
| Perf | 10 | 19 % |
| Refactor | 4 | 7 % |

**≈ 1 in 3 structural changes is a Feature; the other 2 are upkeep**
(Parity + Perf + Refactor). Bugfixes are excluded from the denominator.

**14 / 54 ADRs (26 %)** ship with no substantive on-GitHub technical
discussion — see the `## Technical Discussion` section of each ADR for
its own reviewer dialogue or the "No substantive technical discussion
