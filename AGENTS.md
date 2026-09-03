# AGENTS.md

Guidance for humans and coding agents working on Coraza. This file is the single
source of truth; `.github/copilot-instructions.md` points here.

Coraza is a Web Application Firewall engine in Go. It implements the Seclang
directive language and is compatible with OWASP CRS.

---

# Testing

Read this whole section before writing a single test. Coraza's test suite grew
from 64 to 148 files in three years while the engine barely changed shape. Most
of that growth is duplicated coverage, not new coverage. The rules below exist
to stop that.

## The prime directive

**A behaviour has exactly one home.** Before writing a test, find the home. If a
test for that behaviour already lives there, add a case to it. Do not create a
second home.

## Layer map

| What you are testing | Home | Do NOT put it in |
|---|---|---|
| Rule and directive semantics: given these rules and this request, expect these rule IDs, this interruption, these variables, this audit log | a profile in `testing/engine/*.go` | a hand-written `NewWAF` + `tx.Process*` test |
| Seclang parse errors, directive argument validation, rule compilation failures | table test in `internal/seclang` | engine profiles |
| One operator's boolean result for given inputs | table test in `internal/operators` | engine profiles |
| One transformation's string output | table test in `internal/transformations` | operators, engine profiles |
| Go API contract of a public type (config, options, exported interfaces) | test next to the type | engine profiles |
| HTTP integration: middleware, interceptor, body streaming, websockets | `http/` | `internal/corazawaf`, `internal/seclang` |
| CRS regression | `testing/coreruleset` (go-ftw) | anywhere else |
| Behaviour of the test harness itself | nowhere — see "Do not test the harness" | `testing/` |

## Decision procedure

Run this in order. Stop at the first match.

1. **Can the behaviour be expressed as "rules + request → expected output"?**
   Then it is a profile in `testing/engine/`. Write it there and stop.
   Almost everything about rule evaluation, actions, phases, chains, logging,
   `setvar`, transformations-in-context, and audit logs fits here.
2. **Is it one pure function with several inputs?**
   Add a **row** to the existing table test. Do not add a test function.
3. **Neither?**
   Write a test function, and put a one-line comment saying why it could not be
   a profile. If you cannot state a reason, it was a profile.

## Engine profiles are the default

`testing/profile` + `testing/engine/*.go` is the declarative harness. A profile
is a ruleset, a set of requests, and expected outputs. `testing/coraza_test.go`
runs every registered profile across the whole build-tag matrix for free.

Each `profile.Test` may carry its own `Rules`, so group a profile by the
**behaviour** under test, not by the ruleset. `testing/engine/logging_and_variables.go`
is the reference example.

Available assertions in `profile.ExpectedOutput`:

| Field | Asserts |
|---|---|
| `TriggeredRules` / `NonTriggeredRules` | a rule id matched at least once / never |
| `TriggeredRulesCount` | the **exact** number of matches per rule id |
| `LogContains` / `NoLogContains` | a substring is present / absent in the error logs |
| `LogContainsCount` | the **exact** number of occurrences of a substring |
| `Variables` | a transaction variable's value, e.g. `"TX:score": "7"` |
| `Interruption` | the interruption's rule id, action, status and data |
| `AuditLog` | audit log parts, message count, message contents |
| `ExpectError` | running the phases returns an error |

If your case needs an assertion that does not exist, **add the assertion to the
harness**, do not hand-roll a transaction test. Extending `ExpectedOutput` pays
off across every future case; a hand-rolled test pays off once.

```go
{
    Title: "a rule matching many args logs once and repeats no tag",
    Rules: `
SecRuleEngine On
SecRule ARGS ".*" "id:1,phase:1,log,pass,tag:'some1'"
`,
    Stages: []profile.Stage{{Stage: profile.SubStage{
        Input:  profile.StageInput{URI: "/?test1=123&test2=456"},
        Output: profile.ExpectedOutput{
            TriggeredRulesCount: map[int]int{1: 1},
            LogContainsCount:    map[string]int{`[tag "some1"]`: 1},
        },
    }}},
}
```

## Table tests

Unit tests for pure functions are table-driven, and **every table uses
`t.Run`**. A table without subtests reports one failure for the whole table and
cannot be run selectively.

```go
tests := []struct {
    name string
    in   string
    want string
}{...}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) { ... })
}
```

Variations of one behaviour are **rows**, never separate functions.
`TestFoo_EmptyInput`, `TestFoo_NilInput`, `TestFoo_LongInput` is three rows of
`TestFoo`, not three functions.

## Do not test the harness

`testing/`, `testing/profile`, and test helpers are exercised by every profile
that runs through them. A test asserting that the harness formats its own error
strings correctly, or that a helper's argument validation returns the right
error, is coverage with no defect-finding power. Delete it on sight.

## Anti-patterns

Each of these produced real duplication in this repo. Do not add more.

- **Coverage-driven tests.** A test written to reach an uncovered line or
  branch, with no failure mode in mind. Coverage is an outcome, not a target.
- **The same scenario at several layers.** A chained-rule test in
  `internal/seclang`, a near-identical one in `internal/corazawaf`, and a
  profile in `testing/engine`. Pick the layer from the map above.
- **One function per assertion.** Splitting `TestX` into
  `TestX_CaseA` … `TestX_CaseF` because each has one `if`.
- **Constructor and accessor tests.** Asserting `New()` returns non-nil, that a
  getter returns what a setter just set, or that `String()` contains a substring.
- **Restating the implementation.** A test that recomputes the expected value
  with the same expression the code uses passes for any behaviour.
- **A new `_test.go` file per feature.** Add to the package's existing test file
  unless the package has none.
- **Benchmarks without a claim.** Add a benchmark only when a specific
  performance change is being argued, and only alongside a before/after number.
- **Table tests without `t.Run`.**

## Instructions specific to coding agents

- **Default to zero new test functions.** The expected output of most changes is
  new *rows* and new *profile cases*, not new functions or files.
- **Search before writing.** Grep the repo for the behaviour and read the
  existing profiles for the area. State what you found and why it is
  insufficient before adding anything.
- **A bug fix gets one regression case**, in the profile that owns that
  behaviour. Not one per code path you touched.
- **Never add tests "for completeness", "for edge cases", or "to raise
  coverage"** unless explicitly asked. If you believe coverage is genuinely
  missing, say so and let a human decide.
- **Deleting a redundant test is a valid, welcome change.** If you find a test
  that duplicates a profile, say so; do not add a third copy.
- When you extend `ExpectedOutput`, verify the assertion **fails** when the
  expectation is wrong, not only that it passes.

## Running tests

```
go run mage.go test        # full matrix: default, no_memoize, CRS, multiphase, tinygo
go run mage.go check       # tests plus lint
go test ./testing/         # every declarative engine profile
go test -race ./...
```

Coraza is built under several build tags. A change to rule evaluation must pass
at least `coraza.no_memoize`, `coraza.rule.multiphase_evaluation` and
`coraza.rule.no_regex_multiline`. Profiles run under all of them automatically;
hand-written tests usually do not, which is another reason to prefer profiles.

---

# Code style and conventions

## General Go

- Follow standard Go conventions and idioms; format with `gofmt`.
- Prefer clear, readable code over clever optimisations.
- Keep functions small and focused on a single responsibility.

## Naming

- camelCase for variables and unexported functions (`ruleset`, `parseRule`).
- PascalCase for exported types and functions (`WAF`, `Transaction`).
- Descriptive names for collections (`rules []Rule`, not `r []Rule`).

## Error handling

- Always check and handle errors explicitly.
- Never panic in library code.
- Wrap errors with context: `fmt.Errorf("context: %w", err)`.
- Use custom error types for domain-specific errors.
- Log errors at the appropriate level and avoid interpolation.

## Comments and documentation

- Package-level documentation for every package.
- Document all exported functions, types and variables, starting the comment
  with the name of the item.
- Use complete sentences.

---

# Project-specific guidelines

## Rules and directives

- Rules are immutable after compilation.
- Support ModSecurity directives where possible; document intentional deviations.
- Validate rule syntax during parsing and give clear errors for invalid rules.

## Transaction processing

- Transactions must be concurrent-safe and hold isolated state.
- Clean up resources after transaction completion.
- Support interruption (block/drop) at any phase.

## Performance

- **Be obsessed about performance in critical paths and memory leaks.**
- Avoid excessive locking and unnecessary allocations in hot paths.
- Use object pooling for frequently created objects (e.g. transactions).
- Profile and benchmark before optimising; target real bottlenecks, in the order
  of microseconds rather than nanoseconds.
- Minimise rule evaluation overhead; only evaluate necessary rules.

## Security

- Never log sensitive data (passwords, tokens, session IDs).
- Validate all inputs.
- Use constant-time comparisons for security-sensitive operations.
- Be cautious with regexes that could cause ReDoS.

## Concurrency

- Be mindful of the TinyGo environment and its limitations; use build tags when
  necessary.
- Protect shared state with mutexes; document thread-safety guarantees.
- Maintain consistent lock ordering to avoid deadlocks.
- Use `sync.Pool` for object reuse.

## File organisation

- Packages are internal unless they are part of the public API.
- Use `experimental/` for experimental features.
- Keep tests in the same package as the code under test.

## Dependencies

- Minimise external dependencies; prefer the standard library.
- Document why each dependency is needed.

## Anti-patterns

- No global mutable state.
- No reflection in performance-critical code.
- Do not ignore errors.
- Avoid long parameter lists; use structs or the options pattern.
- Do not mix business logic with I/O.

## Logging

- Use structured logging with relevant context (transaction ID, rule ID).
- Do not log in tight loops.

## Adding a feature

1. Establish a solid use case with more than one potential user.
2. Document the feature.
3. Update the relevant examples.
4. Keep backward compatibility.
