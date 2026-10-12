# ADR-0062: `SecRequestBodyMultipartXMLParts` directive

- **Status:** proposed
- **Date:** 2026-09-07
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1716](https://github.com/corazawaf/coraza/pull/1716)
- **Issue(s):** No linked issue
- **Deciders:** @victorserbu2709 (author)
- **Category:** Feature

## Context and Problem

The body processor is chosen once per transaction, from the request `Content-Type`
or from `ctl:requestBodyProcessor`. For a `multipart/form-data` body that choice is
`multipart`, and the multipart processor never looks at the individual parts'
content types. A part carrying XML is therefore copied to a temporary file and
otherwise ignored: only `FILES`, `FILES_NAMES`, `FILES_SIZES` and `FILES_TMPNAMES`
are populated, holding the filename, the form field name, the size and a path.

The consequence is that `XML:/*` and `XML://@*` are unreachable for an uploaded XML
document, even though the identical bytes sent as an `application/xml` request body
are parsed and exposed. Since no other collection carries file part content either
— `ARGS` does not receive it, `REQUEST_BODY` is only set by the `raw` and
`urlencoded` processors, and `FILES_TMP_CONTENT` is declared but never written —
rules that inspect request data have no target holding an uploaded file's bytes.

For CRS this means a payload in an uploaded XML file is invisible to rules that
catch the same payload in a form field. CRS 4.x targets `FILES` and `FILES_NAMES`
in several places, but only ever to inspect filenames; it contains no reference to
`FILES_TMPNAMES` or `FILES_TMP_CONTENT`.

## Decision Drivers

- Close the gap between an XML request body and an XML multipart part without
  requiring rule changes: CRS already targets `XML:/*|XML://@*`.
- Do not change the behaviour of an existing configuration. ModSecurity does not
  parse multipart parts, so doing it unconditionally would be both a parity
  deviation and a silent change for every deployment.
- Do not buffer whole uploads in memory. `RATIONALE.md` requires that a change
  which buffers more be justified; file parts are currently streamed to disk and
  should stay that way.
- Keep the multipart variables exactly as they are, whether a part parses or not.
- A malformed part must not become a way to hide content from the rules.

## Considered Options

- **A — Expose the raw file bytes in a collection** (populate `FILES_TMP_CONTENT`,
  or push file content into `ARGS_POST`), and let rules inspect them directly.
- **B — Parse XML parts and feed the existing XML collection**, gated by a new
  directive, default off.
- **C — Leave it to integrators**, who can already replace the `multipart` body
  processor through `plugins.RegisterBodyProcessor`.
- **D — General nested body processing** (#917): map a part's content type, or a
  chosen variable, to any body processor, which writes into its own collections.
  Raised in review (see Technical Discussion); not decided at the time of writing.

## Decision Outcome

Chosen: **option B**.

Option A is the smaller change and matches ModSecurity v2's `FILES_TMP_CONTENT`,
but handing unparsed file bytes to CRS's XSS rules produces false positives on
ordinary uploads. Measured against `@detectXSS` with `t:none`, the raw bytes of a
benign document match on their own syntax: an XML declaration (`<?xml version="1.0"?>`)
matches, `<!DOCTYPE html>` matches, and a benign SVG matches. Every XML, SVG, XHTML
or HTML upload would therefore score on 941100 before any payload is involved.

Option B avoids that by construction. The declaration and the tag syntax are
consumed as structure and never reach the operator; what reaches it is element
content and attribute values, which is the same shape of data `XML:` carries for an
XML request body. The engine profile in `testing/engine/multipart.go` asserts both
directions: an entity-encoded payload in an uploaded document triggers `@detectXSS`,
and a benign XML document does not.

Option C stays available and is the right answer for integrators wanting different
semantics, but it requires every one of them to reimplement multipart parsing,
because the body processor registry has a public register function and no public
getter — a processor cannot be retrieved and composed with.

Option D would subsume B, which would become its first case. It is a much larger
design (dispatch configuration, collection naming, recursion limits, JSON and
urlencoded content inside `ARGS`) and is left to the discussion in #917.

The directive is `SecRequestBodyMultipartXMLParts On|Off`, defaulting to `Off`.

### Implementation notes

A part is handed to the tokenizer when any of three hints holds: its part
`Content-Type` media type contains `xml`, its filename carries a known XML
extension, or its content begins with an XML declaration. All three are attacker
controlled; they widen coverage rather than establish trust. A part that matches a
hint but is not well-formed XML is reported as described below. The third hint is the one that matters in practice,
because a client that cannot type a file sends `application/octet-stream`.

Parsing happens on the way to disk, through an `io.TeeReader`, so a part is not
held in memory. The remainder of a part is drained through the same tee after the
tokenizer stops, so the stored file and `FILES_SIZES` are complete whether parsing
reached the end or stopped at a syntax error. A leading BOM is written straight to
the destination rather than through the decoder, which would otherwise emit it as
character data and expose it as a bogus `XML:/*` value.

Values extracted from every XML part are merged and written once, after the loop.
Writing per part would silently drop all but the last, because `collections.Map.Set`
replaces rather than appends.

A part that fails to parse keeps the values tokenized before the error, and the
first such failure is returned by the body processor only after every part has been
processed. The transaction then sets `REQBODY_ERROR`, as it does for a malformed
`application/xml` body, so the recommended rule 200002 rejects the request.
Returning the error immediately would stop at that part and leave `FILES` and the
other multipart variables of the later parts unset. Skipping the part silently, as
an earlier revision did, let an attacker hide a payload behind a malformed tail
(`<r>&lt;script&gt;…</r><x "`) with nothing recording that parsing failed. A
failure to read the part, such as a body truncated mid-part, is still handled by the
multipart processor's own unexpected-EOF logic and is not reported as an XML error.
`MULTIPART_STRICT_ERROR` is deliberately not set for a parse failure: it has defined
ModSecurity semantics for multipart structure errors, and the recommended
configuration keys rule 200003 off it.

## Technical Discussion

@jptosso asked for the feature to be aligned with ModSecurity and with the broader
idea of nested body processing:

> "There is some old discussion about this somewhere, basically being able to create
> "recursive" body processing... For multipart it's actually easier because we can
> use the mime, for urlencoded or json we have to manually state this...
>
> For this I would prefer some alignment with modsecurity @airween"
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/1716#issuecomment-5572535557))

@airween pointed at #917 and a related idea for argument values:

> "May be #917 is the issue where it was asked? […] I was thinking about a similar
> feature, eg. explode arguments from unique targets `ARGS_VALUES`, eg: `q={"a":1}`."
> — @airween ([comment](https://github.com/corazawaf/coraza/pull/1716#issuecomment-5607616136))

This is recorded as option D. Neither ModSecurity v2 nor v3 parses multipart parts;
both expose the raw bytes as `FILES_TMP_CONTENT` only when `SecUploadKeepFiles` or
`SecTmpSaveUploadedFiles` is on, which is option A.

The automated review found that skipping a malformed part was a bypass, which led
to the current handling of parse failures:

> "**Attackers can bypass the feature: one syntax error drops every value extracted
> before it.** […] Example: an attacker uploads `<r>&lt;script&gt;…</r>` followed by
> a malformed tail such as `<x "`. The payload never reaches `XML:/*` or `XML://@*`,
> and no variable records that parsing failed."
> — @coderabbitai ([comment](https://github.com/corazawaf/coraza/pull/1716#discussion_r4192441998))

## Participants

- @victorserbu2709 — author

## Consequences

- **Positive:** an uploaded XML document is inspectable by the `XML:/*|XML://@*`
  targets CRS already uses, with no ruleset change. Works on builds without
  filesystem access, where the part is drained rather than stored.
- **Negative / follow-up:** a deviation from ModSecurity, which never parses
  multipart parts — hence the default of `Off`. Parsing costs CPU per XML part and
  holds the extracted values for the lifetime of the transaction, bounded by
  `SecRequestBodyLimit`. Only XML is dispatched: JSON parts, and file content in
  general, remain uninspectable, and `FILES_TMP_CONTENT` remains unimplemented.
  With the recommended configuration, an upload that matches an XML hint but is not
  well-formed (a non-XML file named `.svg`, say) is rejected by rule 200002, the same
  outcome as sending it as an `application/xml` body.

## References

- Related ADRs: ADR-0010 (raw body processor), ADR-0046 (`SecUploadKeepFiles`),
  ADR-0054 (ignore unexpected EOF in XML body processor)
