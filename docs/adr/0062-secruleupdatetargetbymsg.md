# ADR-0062: `SecRuleUpdateTargetByMsg` matches the message by string equality

- **Status:** proposed
- **Date:** 2026-10-27 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#PRNUM](https://github.com/corazawaf/coraza/pull/PRNUM)
- **Issue(s):** [#1818](https://github.com/corazawaf/coraza/issues/1818)
- **Deciders:** @fzipi
- **Category:** Parity (ModSecurity v3)

## Context and Problem

`SecRuleUpdateTargetByMsg` was routed to the shared `directiveUnsupported`
handler, so it loaded without an error or a warning and changed nothing. Its
siblings `SecRuleUpdateTargetById` and `SecRuleUpdateTargetByTag` (ADR-0012)
apply their targets, and ModSecurity v2 and v3 both implement it, so tuning
files carried over from ModSecurity loaded cleanly and silently lost these
lines: added targets were never inspected and excluded targets kept being
inspected.

The ModSecurity branches disagree on how the message selects rules. v2
(`cmd_rule_update_target_by_msg`, `apache2/apache2_config.c`) compiles the
first argument as a regular expression. v3 (`RuleWithOperator::containsMsg`)
compares it for equality.

## Decision Drivers

- Make the directive do what the configuration says, like its siblings.
- Select rules the same way the other message-based exclusions in Coraza do:
  `SecRuleRemoveByMsg` and `ctl:ruleRemoveByMsg` compare `msg` for
  case-sensitive equality.
- A message usually contains spaces, so the arguments need quote-aware
  splitting, unlike the `strings.Fields` split used for tags and IDs.

## Considered Options

- Keep the directive accepted and ignored, but warn at load time.
- Implement it with case-sensitive string equality on the unexpanded message
  (ModSecurity v3, Coraza's `SecRuleRemoveByMsg`).
- Implement it with the message as a regular expression (ModSecurity v2).

## Decision Outcome

Chosen: **string equality**, because it matches ModSecurity v3 and every other
message-based selector in Coraza, so one message selects the same rules in
`SecRuleRemoveByMsg` and `SecRuleUpdateTargetByMsg`. A v2 configuration whose
message is a literal string behaves the same; one that relies on regex
metacharacters matches no rule.

The message and the target list are each either quoted with `'` or `"`, with
`\"` or `\'` escaping a quote inside, or a run of non-space characters.
Missing, extra or unbalanced arguments are a syntax error.

## Technical Discussion

No substantive technical discussion recorded on the issue thread; it has no
comments. Update this section with quotes if review produces discussion.

## Participants

- @fzipi — author

## Consequences

- **Positive:** Configurations that use the directive now take effect, and
  malformed lines fail at load time instead of being ignored.
- **Negative / follow-up:** Behaviour change for existing configurations:
  lines that loaded as no-ops now change rule targets, and a malformed line or
  an unknown variable in the target list of a matching rule now fails the
  load. v2-style regex messages match nothing.

## References

- PR: https://github.com/corazawaf/coraza/pull/PRNUM
- Issue: https://github.com/corazawaf/coraza/issues/1818
- Related ADRs: ADR-0012 (`SecRuleUpdateTargetByTag`), ADR-0020
  (`SecRuleUpdateActionById`)
