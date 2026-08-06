# ADR-0047: Regex keys in `ctl:ruleRemoveTarget{ById,ByTag,ByMsg}`

- **Status:** accepted
- **Date:** 2026-03-21
- **Version:** v3.5.0
- **PR:** [#1561](https://github.com/corazawaf/coraza/pull/1561)
- **Issue(s):** No linked issue (parallels earlier attempt [#1207](https://github.com/corazawaf/coraza/pull/1207))
- **Deciders:** @fzipi, @M4tteoP, @app/copilot-swe-agent
- **Category:** Feature

## Context and Problem

`ctl:ruleRemoveTargetById` and siblings accepted only exact string keys.
For dynamically indexed JSON args (`ARGS:json.0.field`,
`ARGS:json.1.field`, …), this forced operators to either disable the rule
entirely or exclude the whole collection. Regex-delimited keys
(`ARGS:/^json\.\d+\.field$/`) close this gap.

## Decision Drivers

- Per-URI exclusions for dynamically-indexed variables.
- Reuse logic from an earlier attempt (#1207) — notably its `HasRegex`
  helper and escape-slash handling.
- Dedupe compiled regexes across rules that share the same pattern
  (memoize).

## Considered Options

- Implement only in `ctl.go` with ad-hoc regex detection.
- Extract `HasRegex` into `internal/strings` and reuse in `rule.go` +
  `ctl.go`.
- Pass the memoizer through `OperatorOptions` to dedupe
  `regexp.MustCompile` calls.

## Decision Outcome

Chosen: **extracted `HasRegex` + memoizer-based regex dedup**.

- `internal/strings/strings.go` — new `HasRegex(s string) (bool, string)`
  handling `/user\/` (literal) vs `/user\\/` (regex) correctly.
- `ctlFn.Init` type-asserts `plugintypes.RuleMetadata` to `*corazawaf.Rule`
  to extract its memoizer and pass it into `parseCtl`.
- `RemoveRuleTargetByID` grows a `keyRx *regexp.Regexp` parameter stored
  directly in `ruleVariableParams`.

Example from the PR:

```apache
SecRule REQUEST_URI "@beginsWith /api/jobs" \
  "id:100100,phase:1,pass,nolog,\
   ctl:ruleRemoveTargetById=932125;ARGS:/^json\.\d+\.jobdescription$/"
```

## Technical Discussion

**Reuse earlier work.** @fzipi steered the Copilot agent toward #1207's
`HasRegex`:

> "@copilot+claude-sonnet-4.6 Read https://github.com/corazawaf/coraza/pull/1207
> as it is another implementation of the same feature. In particular, you
> could take from there the `HasRegex` func (and tests) that will make the
> code more easy to read."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1561#issuecomment-4089545322))

**Memoize the compiled regex.**

> "@copilot Wouldn't this benefit from memoization?"
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1561#discussion_r2957185229))

> "Yes, great suggestion. Added a public `Memoizer()` getter on `*Rule`,
> updated `parseCtl` to accept a `plugintypes.Memoizer` parameter; when
> non-nil, it calls `memoizer.Do(rxPattern, ...)` so identical patterns
> across rules share a single compiled `*regexp.Regexp`"
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1561#discussion_r2957227192))

**POST JSON body test coverage.** @fzipi asked for a test that exercises
the JSON-body-processor path, where `json.0.desc` → `json.1.desc` etc.:

> "@copilot+claude-sonnet-4.6 While the test 'ruleRemoveTargetById regex
> key' targets GET arguments, a test that does POST using json formatted
> input would also be good to have."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1561#issuecomment-4089655772))

Four integration test stages cover all three `ctl` variants plus the
POST JSON body path.

## Participants

- @app/copilot-swe-agent — author
- @fzipi — review (drove reuse, memoize, POST test coverage, docs)
- @M4tteoP — review

## Consequences

- **Positive:** Operators can exclude dynamically-indexed variables
  precisely without nuking the rule or collection; compiled regex is
  memoized once per unique pattern across rules.
- **Negative / follow-up:** Regex exception matching carries a per-call
  cost (benchmarked); acceptable relative to the alternative of disabling
  rules wholesale.

## References

- PR: https://github.com/corazawaf/coraza/pull/1561
- Earlier attempt: https://github.com/corazawaf/coraza/pull/1207
- Related ADRs: ADR-0037 (whole-collection exclusion)
