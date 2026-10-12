# ADR-0057: `filename*` (RFC 5987) precedence and new multipart filename variables

- **Status:** proposed
- **Date:** 2026-09-05 (expected; update before merge)
- **Version:** unreleased (targeted for v3.8.0)
- **PR:** [#1](https://github.com/corazawaf/coraza-ghsa-3wr7-993q-jrff/pull/1) (private advisory fork; update to the public PR once GHSA-3wr7-993q-jrff is published)
- **Issue(s):** No linked issue (security advisory [GHSA-3wr7-993q-jrff](https://github.com/corazawaf/coraza/security/advisories/GHSA-3wr7-993q-jrff))
- **Deciders:** @fzipi, @jptosso
- **Category:** Parity (ModSecurity parity + security fix)

## Context and Problem

> "Coraza extracts a multipart file upload's filename using Go's
> standard-library `mime.ParseMediaType`, which only decodes the RFC 5987/6266
> extended `filename*` `Content-Disposition` parameter when its declared
> charset is exactly `us-ascii` or `utf-8`. Any other charset — including
> `iso-8859-1`, which RFC 5987 explicitly permits — is silently dropped by the
> stdlib, with no error and no fallback signal. This lets an attacker present
> one filename to Coraza and a different one to the backend application in
> the same request."
> — [GHSA-3wr7-993q-jrff](https://github.com/corazawaf/coraza/security/advisories/GHSA-3wr7-993q-jrff)

`MULTIPART_FILENAME` and `MULTIPART_NAME` were already declared in
`internal/variables/variables.go` for ModSecurity name parity, but no code
path populated either of them before this fix.

## Decision Drivers

- Close the bypass: a rule inspecting `FILES` must see the filename a
  RFC-5987-compliant, non-`utf-8`/`us-ascii` backend actually resolves.
- `filename*` takes precedence over plain `filename` per RFC 7578 §4.2 when
  both are present and parse; Coraza's own parsing must not silently prefer
  the wrong one under a charset the stdlib doesn't special-case.
- A part carrying only `filename*` must still be routed and counted as a file
  upload (`FILES`, `FILES_COMBINED_SIZE`), not silently fall through to
  `ARGS_POST`.
- Match ModSecurity's own fix for the equivalent class of bug
  ([GHSA-5pww-8rfg-9crf](https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-5pww-8rfg-9crf)):
  same `MULTIPART_DUPLICATE_PART_HEADER`/`MULTIPART_INVALID_QUOTING` variable
  names and audit-log codes (`DH`, `IQ`), and multi-valued filename
  collections per part rather than last-write-wins per name.
- Do not have Coraza pick a "safe" charset allowlist on the operator's
  behalf; expose what was declared (`MULTIPART_FILENAME_CHARSET`,
  `MULTIPART_FILENAME_LANGUAGE`) so operators enforce their own policy.

## Considered Options

- Leave `filename` authoritative (status quo) — this is the vulnerable
  behavior; rejected.
- Make `filename*` authoritative over `filename` whenever `filename*` parses,
  per RFC 7578 §4.2, and expose its declared charset/language as separate
  collections for operator-written allowlists.
- Reject the part (fail closed) whenever `filename` and `filename*` disagree,
  rather than choosing one.
- Add both `filename` and `filename*` values to `FILES` when they differ, so
  a rule matches either backend's interpretation without the engine
  deciding — raised in review (see Technical Discussion).

## Decision Outcome

Chosen: **`filename*` primary per RFC 7578 §4.2, with the plain `filename`
kept alongside it in `FILES`/`MULTIPART_FILENAME` whenever a well-formed
`filename*` picked a different value, plus its charset and language exposed
as their own rule-matchable collections.** `filename*` is now located and
decoded independently of `mime.ParseMediaType`'s `us-ascii`/`utf-8` charset
restriction (a quoted-string-aware scanner over the raw header), so an
unrecognized-but-legal charset such as `iso-8859-1` no longer defeats the
parse. `MULTIPART_FILENAME`/`MULTIPART_NAME` are populated for the first
time. `MULTIPART_FILENAME_CHARSET` and `MULTIPART_FILENAME_LANGUAGE` are new,
Coraza-specific collections (no ModSecurity equivalent) so an operator can
enforce their own charset allowlist instead of Coraza silently trusting or
rejecting one on their behalf. Two further anomaly signals,
`MULTIPART_DUPLICATE_PART_HEADER` and `MULTIPART_INVALID_QUOTING`, were added
to mirror ModSecurity's GHSA-5pww-8rfg-9crf fix and both contribute to the
existing `MULTIPART_STRICT_ERROR` (ADR-0017).

The "expose both values" option **was** adopted, after review (see Technical
Discussion): the plain `filename` is parsed independently of
`mime.ParseMediaType`'s own `dispositionParams["filename"]` (which the stdlib
already overwrites with its own `filename*` decoding for `utf-8`/`us-ascii`,
so it cannot be trusted to recover the original plain value once `filename*`
is present) using the same quoted-string-aware scanner already written for
`filename*`. When it differs from the `filename*` reading, both are added to
`FILES`/`FILES_SIZES`/`MULTIPART_FILENAME` for the same part -- one temp file,
one byte count, two names a rule can match against. `filename*` still decides
which reading populates `MULTIPART_FILENAME_CHARSET`/`_LANGUAGE`, since a
plain `filename` has no charset/language of its own to expose.

## Technical Discussion

@jptosso reviewed the initial implementation and raised a direct objection to
making `filename*` unconditionally authoritative:

> "Tested this branch end to end and I think the precedence decision has a
> problem. Making `filename*` authoritative under any charset doesn't close
> the differential, it moves it. […] So payload 1 gets closed and payload 2
> gets opened. Whether that's a win depends entirely on which backend you are
> protecting, and I don't think we know that yet. […] My suggestion is to not
> pick a side at all. When there are two plausible readings a WAF should
> inspect both, so I'd add both values to FILES when they differ. An
> extension or name blocklist then catches either interpretation, there is no
> decoy in any direction, and we don't need to win the argument about which
> backends are out there."
> — @jptosso ([comment](https://github.com/corazawaf/coraza-ghsa-3wr7-993q-jrff/pull/1#issuecomment-5376317758))

Adopted: both `fields.filename` (the `filename*` reading, when present and
well-formed) and `fields.altFilename` (the plain `filename` reading, when it
differs) are now added to `FILES`/`FILES_SIZES`/`MULTIPART_FILENAME` for the
same part. Verified against @jptosso's own repro
(`filename="shell.php"; filename*=iso-8859-1''safe.jpg`, where Go's
`multipart.Part.FileName()` resolves `shell.php`): `FILES` now contains
`[safe.jpg shell.php]`, so a rule scoped to `FILES` catches the payload
regardless of which reading a given backend's parser prefers. Test coverage
for the original PoC direction only ever exercised one payload order (decoy
in `filename`, real name in `filename*`); the swapped order is now a
dedicated case in both `TestMultipartFilenameStar` and the
`multipart_filename_star.yaml` engine profile (CRS rule 933110), so the gap
that let this ship once cannot silently reopen.

@M4tteoP reviewed the dual-reading fix and found three ways the "pick
whichever reading is well-formed" logic still lost or misresolved a
filename:

> "**Blocking: an empty `filename*` turns a file upload into a normal
> field.** With `Content-Disposition: form-data; name="f";
> filename="shell.php"; filename*=utf-8''`, `filename*` decodes to `""`, so
> `fields.filename` is empty and the part takes the field branch. […] PHP, Go
> `mime/multipart`, python-multipart and formidable ignore that `filename*`
> and store `shell.php` as a file, so FILES-based rules (e.g. CRS 933110),
> FILES_NAMES/FILES_SIZES and the upload size limits never see it."
> — @M4tteoP ([review comment](https://github.com/corazawaf/coraza-ghsa-3wr7-993q-jrff/pull/1#discussion_r4138921078))

> "**Blocking: RFC 2231 continuations (`filename*0*=` / `filename*0=`) get
> around this fix.** `findParam` only matches the exact key `filename*`, so
> for continuations the filename still comes from `mime.ParseMediaType`
> […] the stdlib drops a non-UTF-8 first piece but still writes
> `params["filename"] = ""`, which wipes out the plain filename. […] the
> continuation overrides the plain filename, and since `findFilenameStar`
> returns not-found, the `altFilename` path never runs."
> — @M4tteoP ([review comment](https://github.com/corazawaf/coraza-ghsa-3wr7-993q-jrff/pull/1#discussion_r4138921083))

> "`MULTIPART_INVALID_QUOTING` should be set to `"0"` here too, like
> `MULTIPART_DUPLICATE_PART_HEADER` […] Otherwise the new `logdata` on rule
> 200003 in `coraza.conf-recommended` prints an empty
> `MULTIPART_INVALID_QUOTING=` rather than `0`, and the two flags behave
> differently for rules that check them."
> — @M4tteoP ([review comment](https://github.com/corazawaf/coraza-ghsa-3wr7-993q-jrff/pull/1#discussion_r4138921092))

Adopted for all three: (1) the part is now recognized as a file when either
reading is non-empty, falling back to `fields.altFilename` when
`fields.filename` decodes to `""`; (2) an RFC 2231 numbered continuation
(`filename*N`/`filename*N*`) is detected separately from the bare
`filename*` parameter -- full multi-segment reassembly and decoding was
judged disproportionate to a form real browsers never emit and only a
minority of backends resolve, so instead the plain `filename` is reparsed
directly from the raw header as the primary reading and
`MULTIPART_STRICT_ERROR` is raised via a new `malformed` flag, so the
discrepancy is surfaced rather than resolved silently; (3)
`MULTIPART_INVALID_QUOTING` now defaults to `"0"` in `WAF.newTransaction`,
matching `MULTIPART_DUPLICATE_PART_HEADER`. All three became dedicated cases
in `TestMultipartFilenameStar`, and (3) also became an engine profile case in
`multipart_filename_star.yaml` asserting the `logdata`-rendered value.

A follow-up review comment on (2) found that this first attempt discarded
`mime.ParseMediaType`'s own reading of the continuation outright, even though
that reading is reliable for a utf-8/us-ascii continuation piece (the same
condition under which it is already trusted for the bare `filename*` case) --
silently losing a value Coraza used to surface before this fix existed:

> "This drops the continuation's value instead of keeping it as a second
> name. […] For two inputs, Coraza now sees less than it did before this
> commit […] Werkzeug/Flask honours the continuation and stores `shell.php`.
> Go backends using the standard `mime/multipart` package should too, since
> this is the same reading Coraza used before. […] Suggestion: keep the
> parser's reading as `altFilename` so the existing code that adds both names
> covers it."
> — @M4tteoP ([review comment](https://github.com/corazawaf/coraza-ghsa-3wr7-993q-jrff/pull/1#discussion_r4139178019))

Adopted: the independently-reparsed plain `filename` stays primary (it is the
only reading Coraza can vouch for without decoding the continuation itself),
and `mime.ParseMediaType`'s own reading is now kept as `altFilename` whenever
it differs and is non-empty, using the same dual-reading mechanism already in
place for the bare `filename*` case. Two more cases were added to
`TestMultipartFilenameStar` covering both continuation forms
(`filename*0=`/`filename*0*=utf-8''...`) with a plain-filename decoy, each
confirmed to fail without this second fix.

## Participants

- @fzipi — author
- @jptosso — review (raised the precedence/dual-reading objection above)
- @M4tteoP — review (found the empty-`filename*`, RFC 2231 continuation, and
  `MULTIPART_INVALID_QUOTING` default gaps above, plus the follow-up finding
  that the first continuation fix dropped a recoverable reading)

## Consequences

- **Positive:** A `FILES`-scoped rule now sees both the `filename*` value
  under any RFC-5987-legal charset and the plain `filename` value when they
  differ, closing the decoy-`filename` bypass in GHSA-3wr7-993q-jrff in
  either direction rather than relocating it. A part carrying only
  `filename*` is still routed and size-tracked as a file upload. Operators
  get charset/language visibility to write their own allowlist rather than
  Coraza choosing one silently.
- **Negative / follow-up:** two names in `FILES` per differing part is more
  than a rule author may expect from a single upload; an extension/name
  blocklist still works unchanged (it matches on any value), but a rule that
  assumes exactly one `FILES` entry per part could double-count. No such rule
  exists in CRS today. A dedicated discrepancy signal (e.g.
  `MULTIPART_FILENAME_DISCREPANCY`), so an operator can alert on the
  disagreement directly instead of inferring it from two `FILES` values, was
  deliberately deferred past this release -- nothing about it is
  security-relevant on its own, since the blocklist path already covers the
  bypass. An RFC 2231 numbered continuation of `filename` is detected and
  flagged (`MULTIPART_STRICT_ERROR`) but not reassembled and decoded itself --
  a form real browsers never emit -- so a continuation spanning more than one
  segment, or a single segment under a charset `mime.ParseMediaType` cannot
  decode either, still only surfaces the plain `filename` reading and the
  anomaly signal, not the continuation's own intended value.

## References

- Advisory: https://github.com/corazawaf/coraza/security/advisories/GHSA-3wr7-993q-jrff
- Advisory PR (private fork): https://github.com/corazawaf/coraza-ghsa-3wr7-993q-jrff/pull/1
- ModSecurity parity fix: https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-5pww-8rfg-9crf
- Related ADRs: ADR-0017 (`MULTIPART_STRICT_ERROR`)
