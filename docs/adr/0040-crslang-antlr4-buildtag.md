# ADR-0040: Gate `crslang` ANTLR4 parser behind a build tag

- **Status:** accepted
- **Date:** 2026-03-08
- **Version:** v3.4.0
- **PR:** [#1536](https://github.com/corazawaf/coraza/pull/1536)
- **Issue(s):** No linked issue
- **Deciders:** @app/copilot-swe-agent (author)
- **Category:** Feature (new experimental parser) + Refactor (binary-size hygiene)

## Context and Problem

The experimental ANTLR4-based SecLang parser (`experimental/seclang/parser_v2.go`)
pulled in heavy dependencies (`antlr4-go`, `crslang`, `seclang_parser`)
unconditionally, bloating every default Coraza build even though only a
handful of developers need the new parser.

## Decision Drivers

- Keep default binary size small — most users don't need the ANTLR4 parser.
- Still allow opt-in testing and development of the experimental parser.
- Zero default-behaviour change.

## Considered Options

- Leave dependencies compiled in.
- Split to a separate module / repository.
- Gate behind a build tag so the code compiles only when explicitly opted
  in.

## Decision Outcome

Chosen: **build-tag gate** — `//go:build coraza.experimental.crslang_parser`
on `parser_v2.go` and its test file. Default builds skip the package
entirely:

```
go build -tags=coraza.experimental.crslang_parser ./...
go test -tags=coraza.experimental.crslang_parser ./experimental/seclang/...
```

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The Copilot
SWE agent authored the refactor; reviewers approved on the strength of the
binary-size motivation captured in the PR body.

## Participants

- @app/copilot-swe-agent — author

## Consequences

- **Positive:** Default Coraza builds no longer drag in ANTLR4; experimental
  parser work continues under the tag.
- **Negative / follow-up:** One more build-tag combination the CI matrix
  must cover for the experimental parser specifically.

## References

- PR: https://github.com/corazawaf/coraza/pull/1536
