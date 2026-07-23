# ADR-0041: `ruleRemoveById` range storage (no expansion)

- **Status:** accepted
- **Date:** 2026-03-09
- **Version:** v3.4.0
- **PR:** [#1538](https://github.com/corazawaf/coraza/pull/1538)
- **Issue(s):** No linked issue
- **Deciders:** @app/copilot-swe-agent (author)
- **Category:** Perf

## Context and Problem

`rangeToInts` iterated every WAF rule and inserted each matching ID into
the per-transaction removal map one at a time. For broad CRS exclusion
ranges like `1000-9999`, this churned thousands of allocations per request
even though the effective filter was just two numbers.

## Decision Drivers

- Avoid thousands of per-request allocations for common CRS ranges.
- Keep the rule-evaluation skip check cheap.
- Cover both `ctl:ruleRemoveById` and `ctl:ruleRemoveTargetById` range
  forms.

## Considered Options

- Expand ranges into the map (status quo, O(range size) allocations).
- Store ranges separately as `[2]int`; evaluate with a short `len(ranges)`
  loop.
- Bitset indexed by rule ID (overkill for a handful of ranges).

## Decision Outcome

Chosen: **store ranges as `[2]int` entries on the transaction; rule-eval
loop checks both the ID map and the range slice.**

New helpers:

- `parseRange("start-end") → (start, end int)`
- `parseIDOrRange(...)` — handles single IDs and ranges
- `Transaction.RemoveRuleByIDRange(start, end)`
- `Transaction.GetRuleRemoveByIDRanges()` accessor
- `RuleGroup.rules` eval consults `ruleRemoveByIDRanges` in addition to the
  ID map.

Pool reuse resets the range slice alongside other per-transaction state.

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The Copilot
SWE agent delivered the change in response to a human-filed issue tracked
in the original prompt block of the PR body.

## Participants

- @app/copilot-swe-agent — author

## Consequences

- **Positive:** A `ctl:ruleRemoveById=1000-9999` directive no longer causes
  thousands of per-transaction allocations; the range lives as a single
  `[2]int` entry.
- **Negative / follow-up:** Rule-eval skip now has two data structures to
  consult (map + range slice). Both small, overall cost is net-negative.

## References

- PR: https://github.com/corazawaf/coraza/pull/1538
- Related ADRs: ADR-0038 (map for `ruleRemoveByID`)
