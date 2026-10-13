# ADR-0061: Zero-copy haystack for the `@pm` Aho-Corasick matcher

- **Status:** proposed
- **Date:** 2026-10-14 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1-cl5)
- **PR:** [#26](https://github.com/cloudlinux/coraza/pull/26) (expected number; update before merge)
- **Issue(s):** No linked issue (CloudLinux DEF-57621, large JSON request bodies)
- **Deciders:** Gabriel Grigoras (CloudLinux)
- **Category:** Perf

## Context and Problem

`@pm`, `@pmFromFile` and `@pmFromDataset` share `pmEvaluate`, which calls the
`aho-corasick` library's `matcher.Iter(value)`. That method is
`IterByte([]byte(haystack))`: it copies the whole value into a new `[]byte` on
every call. ADR-0053 already names the copy, and answers it only for values
shorter than the shortest pattern.

For a value that is large and not short, nothing avoids it. Each `@pm` rule
tests each of its targets, so a large request body is copied once per rule and
per argument. A CPU and allocation profile of the Imunify360 "full" coraza
ruleset (7152 `SecRule` lines) handling one POST with a JSON object of 8 members
and 4.7 MB in total (the `perf-cloudways-badday` lab shape of DEF-57621) shows
`AhoCorasick.Iter` as 1209 MB of the 2025 MB allocated over 6 transactions, 60%
of all allocations and about 200 MB, some 40 times the body, per transaction. The
copy is also a share of the `memmove` time that remains once `SecRxPreFilter`
has removed most regular-expression work. The wafd process handles these bodies
on its request path, and allocation volume sets how often its GC runs, which
every request next to them pays for.

## Decision Drivers

- No allocation proportional to the value for a pattern match that only needs to
  read it.
- No change to what matches: same matcher, same options, same results, including
  the capture offsets.
- Stay inside what the project allows for `unsafe` (AGENTS.md: reuse the
  helpers in `internal/strings`; a new use needs a benchmark, an ADR and
  reviewer agreement).
- TinyGo builds keep working.

## Considered Options

- Keep `Iter(value)`. The copy stays.
- Pool and reuse the `[]byte` buffers. Removes the allocation but not the copy
  (`memmove` of the whole value), and a pool that has held a multi-megabyte buffer
  keeps that memory alive.
- Change the library so it takes a string. Not in our hands; the library is a
  dependency and its `IterByte` already takes a slice.
- Move `@pm` to the Wu-Manber `indexedMatcher` of ADR-0052. A much larger change
  with its own limits (needle count, leftmost-longest capture semantics that
  `@pm` has to keep).
- View the string's bytes in place with `unsafe.Slice(unsafe.StringData(s), len(s))`
  and call `IterByte`. One new helper in `internal/strings`, where the project
  keeps its other zero-copy conversion (`WrapUnsafe`).

## Decision Outcome

Chosen: **the in-place view.** `internal/strings.UnsafeBytes(s)` returns the
string's bytes without copying, with `len == cap` so that an `append` would
reallocate instead of writing into the string. `pmEvaluate` passes it to
`IterByte`. The helper is documented as read-only.

This is safe because the matcher only reads the haystack. At the library version
pinned in `go.mod` (`v0.0.0-20250424160509-463d218d4745`) the iterator stores the
slice, and the search code (`automaton.go`) and the prefilters (`prefilter.go`)
index it and never assign to it. Both automata Coraza builds go through that same
code: the DFA (`dfa.go`, `DFA: true` in `@pm` and `@pmFromDataset`) and the NFA
(`nfa.go`, `DFA: false` in `@pmFromFile`) only forward the slice to it. A library
update that wrote to the haystack would break the assumption, so a dependency
bump has to keep that in view; `TestPmDoesNotCopyLargeValue` and
`TestPmFindsPatternInLargeValue` pin the behaviour.

The capture path is unchanged: matches are still reported as offsets, and the
captured text is sliced from the original string, not from the view.

## Technical Discussion

No substantive technical discussion recorded; the change was drafted from the
DEF-57621 profile and has not been reviewed yet.

## Participants

- Gabriel Grigoras (CloudLinux): author

## Consequences

- **Positive:** `@pm` no longer allocates per evaluation in proportion to the
  value. `TestPmDoesNotCopyLargeValue` asserts at most 1/16 of a 1 MiB value
  allocated per evaluation, where the copy allocated all of it.
  `BenchmarkPmLargeValue` measures it per value size; the before and after
  figures, and the effect on the 4.7 MB lab body, are in the pull request.
- **Negative / follow-up:** One more use of `unsafe`, in the one place the
  project already accepts it, with a documented read-only contract. The fork now
  carries this patch relative to upstream; it is small and can be proposed
  upstream. Replacing the Aho-Corasick matcher of `@pm` with a faster one stays
  open: it is the largest CPU cost left after the prefilter in the DEF-57621
  profile.

## References

- Related ADRs: ADR-0019 (`unsafe.StringData` refactor), ADR-0049 and ADR-0050
  (`@rx` prefilter, `SecRxPreFilter`), ADR-0052 (indexed-bitmap matcher), ADR-0053
  (`@pm` `minLen` prefilter)
- Library: https://github.com/petar-dambovaliev/aho-corasick
