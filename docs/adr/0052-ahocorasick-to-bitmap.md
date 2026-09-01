# ADR-0052: Replace Aho-Corasick with indexed-bitmap matcher for `@rx` `anyRequired` prefilter

- **Status:** accepted
- **Date:** 2026-04-09
- **Version:** unreleased (post-v3.7.0)
- **PR:** [#1597](https://github.com/corazawaf/coraza/pull/1597)
- **Issue(s):** No linked issue
- **Deciders:** @soujanyanmbri, @fzipi, @coderabbitai
- **Category:** Perf

## Context and Problem

The `@rx` prefilter ([ADR-0049](0049-rx-literal-prefilter.md)) used
Aho-Corasick for `anyRequired` alternations. Aho-Corasick scans at O(H)
with non-trivial allocation. A Wu-Manber-style indexed-bitmap matcher can
do sub-linear scans with zero match-time allocations.

Two additional structural issues were found:

1. Go's `regexp/syntax.Simplify()` rewrites `(select|sleep|substr)` into
   a trie with a 1-byte shared prefix. The old extractor saw the short
   prefix, returned `nil`, and built no prefilter at all.
2. `anyRequired` sets nested inside `OpConcat` nodes (e.g.
   `(?:^|["':;=])\s*(?:select|union|drop)`) were discarded.

## Decision Drivers

- Faster `anyRequired` scanning; zero-alloc match path.
- Recover literals from simplified tries so large SQL keyword sets
  actually benefit from the prefilter.
- Propagate `anyRequired` through `OpConcat` children.
- Cheap length-only prefilter for patterns with no extractable literals.

## Considered Options

- Keep Aho-Corasick, accept the allocations.
- Replace with Wu-Manber indexed-bitmap matcher + trie reconstruction + 
  propagation + min-length fallback.

## Decision Outcome

Chosen: **Wu-Manber indexed-bitmap matcher + three structural fixes.**

- `indexedMatcher` scanner with a 2-byte bigram shift table; sub-linear
  average step (`minNeedleLen/2`), zero heap allocation at match time,
  up to 256 needles before falling back.
- `trieReconstruct`: detects `OpConcat(OpLiteral, OpAlternate)` and
  prepends the shared prefix to each suffix branch, recovering the full
  keyword set for the scanner.
- `extractLiterals` walks `OpConcat` children and surfaces the most
  restrictive `anyRequired`.
- If no literals can be extracted and `minMatchLength >= 4`, a
  length-only prefilter `len(s) >= mml` is returned — free O(1) guard.

## Technical Discussion

**Safety claim from the PR body:**

> "The prefilter is **safe by construction**: it can only say 'definitely
> no match' (skip regex) or 'maybe match' (run regex). A bug in literal
> extraction degrades performance; it cannot produce a false negative.
> When in doubt (non-ASCII CI input, unknown AST nodes, unparseable
> patterns), we fall through to the regex."
> — @soujanyanmbri, PR body

**Coverage was a merge gate:**

> "Looks amazing @soujanyanmbri Can you add more coverage?"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1597#issuecomment-4189353503))

> "Thank you! Done, added more coverage. Please check :)"
> — @soujanyanmbri ([comment](https://github.com/corazawaf/coraza/pull/1597#issuecomment-4189392213))

No architectural debate — the three structural fixes plus the matcher
swap were approved on the evidence of CRS-scale benchmarks in the PR body.

## Participants

- @soujanyanmbri — author
- @fzipi — review (coverage driver)
- @coderabbitai[bot] — reviewer

## Consequences

- **Positive:** Large SQL-keyword alternations (previously un-prefiltered
  because of the trie-simplification issue) now short-circuit; zero-alloc
  hot path for `anyRequired` scanning.
- **Negative / follow-up:** `indexedMatcher` is a second literal-matching
  primitive alongside the `@pm` Aho-Corasick path — operator of the two
  codepaths must be aware of the distinct responsibilities.

## References

- PR: https://github.com/corazawaf/coraza/pull/1597
- Related ADRs: ADR-0049 (rx literal prefilter), ADR-0053 (`@pm` minLen
  prefilter)
