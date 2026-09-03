# ADR-0021: Square brackets in macro-expanded variable names

- **Status:** accepted
- **Date:** 2024-11-21
- **Version:** v3.3.0
- **PR:** [#1226](https://github.com/corazawaf/coraza/pull/1226)
- **Issue(s):** No linked issue
- **Deciders:** @geoolekom, @M4tteoP, @jcchavezs
- **Category:** Parity (framework parameter conventions)

## Context and Problem

PHP and jQuery conventions produce parameter names containing square
brackets (`ARGS.fields[]`, `fields[name]`). Coraza's macro-expansion parser
rejected these names, breaking macros like
`%{ARGS.db-reset-tables[]}` in rule messages and forcing users to rewrite
otherwise-standard rules.

## Decision Drivers

- Compatibility with web-framework parameter conventions.
- No behaviour change for variable lookups that already worked — only the
  macro-expansion parser needed widening.

## Considered Options

- Teach every rule-parsing entrypoint to accept brackets.
- Widen only the macro-expansion parser, which is where the breakage was.

## Decision Outcome

Chosen: **widen only the macro-expansion parser**, matching the narrow scope
of the observed bug.

## Technical Discussion

The review's substantive thread was about scoping the change correctly.

> "I just wish to double-check the scope of the PR, because the description
> seems not fully aligned with the code. I tested the following rules, and
> they actually worked as expected. `SecRule ARGS:key[] …` … What does this
> PR fixes?"
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1226#issuecomment-2491006691))

> "oh, yes. Indeed, I meant the variables in macro. I missed a `msg` part in
> my example, my bad."
> — @geoolekom ([comment](https://github.com/corazawaf/coraza/pull/1226#issuecomment-2491029430))

> "Ok, great, thanks for confirming it!"
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1226#issuecomment-2491685710))

## Participants

- @geoolekom — author
- @M4tteoP — review (scope clarification)
- @jcchavezs — review

## Consequences

- **Positive:** CRS and downstream rulesets with PHP/jQuery-style parameter
  names can use macros referencing them without workarounds.
- **Negative / follow-up:** None — the change is additive in the parser.

## References

- PR: https://github.com/corazawaf/coraza/pull/1226
