# ADR-0062: Size the `@rx` `anyRequired` matcher for one needle per keyword

- **Status:** proposed
- **Date:** 2026-11-05 (expected)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1806](https://github.com/corazawaf/coraza/pull/1806)
- **Issue(s):** [#1790](https://github.com/corazawaf/coraza/issues/1790)
- **Deciders:** @adilalperenciftci
- **Category:** Perf

## Context and Problem

[ADR-0052](0052-ahocorasick-to-bitmap.md) introduced the indexed-bitmap
(Wu-Manber) matcher for `anyRequired` sets and capped it at 256 needles; past
the cap the rule got no prefilter.

#1806 fixes trie reconstruction so that it only joins a factored prefix to
literals that are contiguous in matching input (#1790). Done strictly, that
loses literals: a branch that cannot join disables the whole alternation, and
the CRS command and function lists (932210, 933151, 933161, 942150-942152)
fell back to the length check. Recovering them means keeping one needle per
keyword and expanding optional groups (`CO(?:MPRES)?S` gives `compress` and
`cos`), which pushes five CRS rules (932180, 932235, 932260, 933151, 933152)
to 250-700 needles, above the old cap. They are among the most expensive
rules in the set.

Expanding optional groups has its own cost: `Simplify()` writes `{0,n}` as n
nested optional groups, and each expansion repeats the walk of everything
after it. Without a bound,
`x(?:bc){0,20}(?:de){0,20}(?:fg){0,20}(?:hi){0,20}y` took over a minute to
compile.

## Decision Drivers

- No false negatives: the prefilter may only skip the regex when no match is
  possible.
- Keep a prefilter on the CRS rules that dominate `@rx` cost.
- Bounded rule compilation time for any pattern.

## Considered Options

- Keep the 256 cap and give the large keyword sets no prefilter.
- Raise the cap, reduce sets before building the matcher, and bound the
  optional-group expansion per walk.
- Keep short shared-prefix needles (`co`, `mi`, `sh`) to stay under 256.
  Sound, but such needles occur in most inputs, so the regex runs anyway.

## Decision Outcome

Chosen: **raise the cap, reduce, and bound the expansion**, because it keeps
the prefilter sound and on the expensive rules while bounding compile time.

- `anyRequiredMaxN` goes from 256 to 1024. Measured over every CRS `@rx`
  rule, the matcher at 250-700 needles still beats running those regexes
  unfiltered.
- `dropSuperstrings` removes duplicate needles and needles that contain
  another needle before the matcher is built. It is quadratic, so it only
  runs on sets up to `maxSupersetInput` (4 x `anyRequiredMaxN` = 4096).
- When a set is unusable (too many needles, too many inputs to reduce, or a
  needle too short), `prefilterFunc` keeps the minimum-length guard from
  ADR-0052 instead of returning no prefilter.
- `maxQuestExpansions` (64) bounds the optional groups one reconstruction
  walk expands. Past it an optional group is treated as a node literals
  cannot be joined across. The CRS rules need at most a few dozen.

**Benchmark method.** Prefilter plus regex over every CRS `@rx` rule, run
in-package on one core, best of 7, on 1 KB and 10 KB of a repeated byte,
1 KB of prose and 10 KB of JSON. Total time is 15-22% lower than both
earlier heads of the PR on all four inputs, and 160 rules get a prefilter
instead of 155. Soundness is checked by `TestCRSPrefilterSafety` over the
CRS v4 FTW attack payloads and by `FuzzPrefilterNoFalseNegatives`.

## Technical Discussion

The cap and the reduction came out of a load test of the PR on Envoy, which
found that an intermediate head lost the sets of two CRS rules:

> "It seems to come from 932260 and 942151. Both lose all their literals at this head (234 and 139 at `2067304`), so on my test value, one field of repeated `x`, they fall through to the regex."
> — @segflaunt ([comment](https://github.com/corazawaf/coraza/pull/1806#issuecomment-6661671082))

## Participants

- @adilalperenciftci — author
- @segflaunt — load testing
- @coderabbitai[bot] — review

## Consequences

- **Positive:** the CRS command, function and SQL keyword lists keep a
  sound prefilter; compile time stays bounded for repeated optional groups.
- **Negative / follow-up:** matchers with up to 1024 needles use more memory
  per rule than the 256 cap allowed. Raise the cap again only if profiling
  shows Wu-Manber still wins beyond it.

## References

- PR: https://github.com/corazawaf/coraza/pull/1806
- Issue: https://github.com/corazawaf/coraza/issues/1790
- Related ADRs: ADR-0049 (rx literal prefilter), ADR-0052 (Aho-Corasick to
  indexed-bitmap matcher, superseded by this record)
