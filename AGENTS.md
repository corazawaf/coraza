# Coraza: guide for contributors and coding agents

This file is the single source of truth for humans and coding agents (GitHub
Copilot, Claude, Cursor, etc.) working on Coraza. `.github/copilot-instructions.md`
and `CLAUDE.md` only point here. When this file and a tool-specific file disagree,
this file wins.

Read the [Testing](#testing), [Architecture Decision Records](#architecture-decision-records),
[Pull requests](#pull-requests) and [Security](#security) sections before changing
anything. The rest is a map of the codebase.

## Project overview

Coraza is a Web Application Firewall (WAF) engine written in Go. It implements the
SecLang directive language (compatible with ModSecurity v2/v3), is fully compatible
with OWASP CRS v4, and is an OWASP Production Project. Coraza also supports TinyGo
compilation for environments with constrained runtimes (e.g. WASM).

Other documents worth knowing:

- [`README.md`](README.md): usage, build tags, FIPS mode, tooling.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): community, how to report issues, how to propose enhancements.
- [`SECURITY.md`](SECURITY.md): vulnerability reporting policy. See [Security](#security).
- [`RATIONALE.md`](RATIONALE.md): why body-buffering limits must be chosen carefully.
- [`docs/adr/README.md`](docs/adr/README.md): the Architecture Decision Record standard.

## Repository structure

| Directory | Purpose |
| --- | --- |
| `types/` | Public API interfaces: `Transaction`, `WAF`, `MatchData`, `Interruption`, `RuleMetadata`, variables |
| `collection/` | Public collection interfaces: `Collection`, `Single`, `Keyed`, `Map` |
| `debuglog/` | Debug logging interfaces and helpers |
| `http/` | HTTP middleware and interceptor, plus `http/e2e/` end-to-end runner |
| `testing/` | Declarative engine test harness (`profile/`, `engine/`), CRS regression (`coreruleset/`), e2e and ModSecurity comparison suites |
| `examples/` | Usage examples (e.g. `http-server`) |
| `experimental/` | Experimental public API: `WAFWithRules`, `WAFCloser`, rule observer |
| `experimental/plugins/` | Plugin registration: `RegisterOperator()`, `RegisterTransformation()`, `RegisterAction()`, `RegisterBodyProcessor()`, `RegisterAuditLogWriter()`, `RegisterAuditLogFormatter()` |
| `experimental/plugins/plugintypes/` | Plugin interfaces: `Operator`, `Transformation`, `Action`, `BodyProcessor`, `TransactionState`, `RuleMetadata` |
| `experimental/plugins/macro/` | Macro expansion for rule messages and log data |
| `internal/corazawaf/` | Core `WAF`, `Transaction`, `Rule` and `RuleGroup` implementation |
| `internal/corazarules/` | Rule metadata and match data implementation |
| `internal/collections/` | Variable storage implementations: `Map`, `Named`, `Single`, `Sized`, `Concat` |
| `internal/operators/` | Built-in operator implementations |
| `internal/transformations/` | Built-in transformation implementations |
| `internal/actions/` | Built-in action implementations |
| `internal/seclang/` | SecLang rule and directive parser |
| `internal/auditlog/` | Audit logging: serial, concurrent, syslog, HTTPS writers; JSON, OCSF and legacy formatters |
| `internal/bodyprocessors/` | Body parsers: JSON, XML, multipart, urlencoded, raw |
| `internal/variables/` | Variable type system with generated maps |
| `internal/memoize/` | Cache for compiled regexes and Aho-Corasick tables, on by default (see build tags) |
| `internal/strings/`, `internal/url/`, `internal/cookies/`, `internal/io/` | Utility packages |
| `internal/sync/` | TinyGo-compatible sync primitives (`pool.go`, `pool_std.go`, `pool_tinygo.go`) |
| `internal/environment/` | Build environment detection (FS access, etc.) |
| `docs/adr/` | Architecture Decision Records |

## Architecture: request processing pipeline

Every HTTP request/response flows through 5 phases. Each `Process*` method triggers
`WAF.Rules.Eval(phase, tx)` and checks for interruptions. Signatures below are those
of the public `types.Transaction` interface.

### Phase 1 - Request headers

```text
ProcessConnection(clientIP, clientPort, serverIP, serverPort)
  -> ProcessURI(uri, method, httpVersion)
  -> AddRequestHeader(key, value)  // repeat per header
  -> ProcessRequestHeaders() -> *Interruption
```

### Phase 2 - Request body

```text
WriteRequestBody([]byte)      -> (*Interruption, int, error)
ReadRequestBodyFrom(io.Reader) -> (*Interruption, int, error)
  -> ProcessRequestBody()      -> (*Interruption, error)
```

The write helpers buffer up to the configured limit and return the number of bytes
written. They can surface an interruption on their own: when the body exceeds the
limit and `SecRequestBodyLimitAction` is `Reject`, or when the action is
`ProcessPartial` and the limit is reached, in which case `ProcessRequestBody` runs
automatically. The body processor (JSON, XML, multipart, urlencoded, raw) is selected
from the `Content-Type` header, or forced with `ctl:requestBodyProcessor`, and fills
variables such as `ARGS_POST`, `REQUEST_BODY` and `FILES`.

### Phase 3 - Response headers

```text
AddResponseHeader(key, value)  // repeat per header
  -> ProcessResponseHeaders(statusCode, proto) -> *Interruption
```

### Phase 4 - Response body

```text
WriteResponseBody([]byte)       -> (*Interruption, int, error)
ReadResponseBodyFrom(io.Reader) -> (*Interruption, int, error)
  -> ProcessResponseBody()      -> (*Interruption, error)
```

Same contract as the request body helpers.

### Phase 5 - Logging

```text
ProcessLogging()
```

**Key files:**

- `types/transaction.go`: `Transaction` interface (public API)
- `internal/corazawaf/transaction.go`: `Transaction` implementation
- `internal/corazawaf/rulegroup.go`: `RuleGroup.Eval(phase, tx)` iterates rules in syntactic order

## Architecture: rule evaluation

When `RuleGroup.Eval(phase, tx)` is called, each rule in the group is evaluated in
order. Evaluation stops early if an interruption is triggered (except in the logging
phase).

### Step-by-step evaluation (`Rule.Evaluate` / `Rule.doEvaluate`)

1. **Variable extraction**: each rule's `variables` list is iterated. For each
   variable, `tx.GetField(v)` extracts values from the transaction's collections,
   applying key filtering (exact string or regex) and exceptions (`!VARIABLE:key`).
   The `&VARIABLE` syntax returns the count instead of the value.

2. **Transformation pipeline** (`Rule.transformArg`): each extracted value passes
   through the rule's ordered list of transformations. Results are cached per
   (variable, key, transformation prefix) to avoid redundant work; the `TX` variable
   is never cached. `multiMatch` runs the operator after each transformation.

3. **Operator evaluation**: `Rule.executeOperator(transformedValue, tx)` calls
   `Operator.Evaluate(tx, value) -> bool`. If the rule has `Negation` set, the
   result is inverted.

4. **Action execution** (only on the parent rule, not chain children):
   - **Flow actions** first (e.g. `skip`, `skipAfter`): always evaluated
   - **Disruptive actions** (e.g. `deny`, `drop`, `redirect`): only when
     `SecRuleEngine` is `On` (not `DetectionOnly`)
   - **Non-disruptive actions** (e.g. `log`, `setvar`, `capture`): evaluated per match

5. **Chain processing**: if a rule has `Chain` set, the parent must match first.
   Then each chained rule is evaluated recursively via `doEvaluate`. All rules in the
   chain must match for the overall rule to match.

**Key files:**

- `internal/corazawaf/rule.go`: `Rule` struct, `Evaluate()`, `doEvaluate()`, `transformArg()`, `executeOperator()`
- `internal/corazawaf/rulegroup.go`: `RuleGroup.Eval()` with phase filtering, skip/skipAfter, allow handling

## Plugin system

Every extension point has an internal registry and a public wrapper in
`experimental/plugins`. Built-in implementations register from inside their own
package (`internal/operators.Register`, `internal/transformations.Register`,
`internal/actions.Register`); integrators register from their own package through
`experimental/plugins`, which forwards to the same registries. Never import
`experimental/plugins` from an `internal/` package: it imports them, so that is an
import cycle.

### Operators

```go
// Interface (plugintypes/operator.go)
type Operator interface {
    Evaluate(TransactionState, string) bool
}
type OperatorFactory func(options OperatorOptions) (Operator, error)

// Registration from an integrator package (plugins/operators.go)
plugins.RegisterOperator("myop", factory)
```

`OperatorOptions` carries the raw `Arguments`, the `Path` search list for file
based operators, the `Root` filesystem and a `Memoizer` for expensive compilations.

### Transformations

```go
// Type signature (plugintypes/transformation.go)
type Transformation = func(input string) (output string, changed bool, err error)

// Registration from an integrator package (plugins/transformations.go)
plugins.RegisterTransformation("mytrans", transformFunc)
```

### Actions

```go
// Interface (plugintypes/action.go)
type Action interface {
    Init(RuleMetadata, string) error
    Evaluate(RuleMetadata, TransactionState)
    Type() ActionType
}
// ActionType: ActionTypeMetadata (1), ActionTypeDisruptive (2), ActionTypeData (3),
//             ActionTypeNondisruptive (4), ActionTypeFlow (5)

// Registration from an integrator package (plugins/actions.go)
plugins.RegisterAction("myaction", func() plugintypes.Action { return &myAction{} })
```

### Body processors and audit log

- `plugins.RegisterBodyProcessor(name, factory)`: a `plugintypes.BodyProcessor`
  selected by `ctl:requestBodyProcessor` or content type.
- `plugins.RegisterAuditLogWriter(name, factory)` and
  `plugins.RegisterAuditLogFormatter(name, formatter)`: selected by
  `SecAuditLogType` and `SecAuditLogFormat`.

## Collection system

WAF variables are stored in typed collections within each transaction.

| Interface | Description | Example variables |
| --- | --- | --- |
| `collection.Single` | Single string value | `REQUEST_METHOD`, `RESPONSE_STATUS`, `REQUEST_URI` |
| `collection.Keyed` | Named lookups with key/regex support | `REQUEST_HEADERS`, `ARGS`, `TX` |
| `collection.Map` | Mutable keyed collection (extends `Keyed`) | `REQUEST_HEADERS`, `ARGS_POST`, `ARGS_GET` |

Collections are NOT concurrent-safe. Each transaction has its own isolated set.

**Key files:**

- `collection/collection.go`: public interfaces `Collection`, `Single`, `Keyed`, `Map`
- `internal/collections/map.go`: map implementation with case-insensitive option
- `internal/collections/named.go`: named collection implementation
- `internal/collections/single.go`: single value collection
- `internal/collections/sized.go`: size-tracking collection
- `internal/collections/concat.go`: read-only view over several maps (e.g. `ARGS`)

## SecLang parser

The parser compiles SecLang directives into WAF rules and configuration.

### Entry points

- `Parser.FromFile(path)`: load from file (supports glob patterns with `*`)
- `Parser.FromString(data)`: load from string

### Parsing flow

1. Lines are read with `bufio.Scanner`
2. Line continuations (`\` at end) and backtick multi-line blocks are handled
3. Comments (`#`) are skipped
4. Each complete line is split into directive name + options
5. The directive name is looked up in `directivesMap` (generated) and the
   corresponding function is called
6. `Include` is handled specially with recursion protection (`maxIncludeRecursion`)

### Rule format

```text
SecRule VARIABLES "OPERATOR" "ACTIONS"
```

- **Variable syntax**: `VARIABLE[:key]`, `VARIABLE:/regex/`, `&VARIABLE` (count),
  `!VARIABLE:key` (exception), `VARIABLE1|VARIABLE2` (multiple)
- **Operator syntax**: `@operatorName arguments` (e.g. `@rx pattern`, `@eq 0`)
- **Actions**: comma-separated list (e.g. `id:100,phase:1,deny,log,msg:'Blocked'`)

**Key files:**

- `internal/seclang/parser.go`: `Parser` struct, `FromFile()`, `FromString()`, line parsing
- `internal/seclang/rule_parser.go`: `RuleParser`, `ParseVariables()`, variable/operator/action parsing
- `internal/seclang/directives.go`: directive implementations
- `internal/seclang/directivesmap.gen.go`: generated directive name -> function map

## Build system and TinyGo

### Mage tasks

```bash
go run mage.go test       # go test ./..., again with -tags=coraza.no_memoize, examples/http-server with -race,
                          # testing/coreruleset under default, no_memoize, multiphase and no_regex_multiline tags,
                          # then TestRx* under no_regex_multiline and TestCaseSensitive* under case_sensitive_args_keys
go run mage.go lint       # Lint (generates code, checks formatting, runs golangci-lint)
go run mage.go check      # test + lint
go run mage.go coverage   # Tests with coverage and race detector (BUILD_TAGS env var selects tags)
go run mage.go format     # Format code (go generate, goimports, addlicense)
go run mage.go fuzz       # Run fuzz tests
go run mage.go adr        # Validate docs/adr (format, header fields, index)
go run mage.go precommit  # Install the pre-commit git hook
```

### Build tags

The authoritative list is the "Build tags" section of [`README.md`](README.md).
Summary:

| Tag | Effect |
| --- | --- |
| `coraza.disabled_operators.<name>` | Exclude a specific operator from compilation |
| `coraza.rule.multiphase_evaluation` | Evaluate rule variables in the phases they become ready |
| `coraza.rule.case_sensitive_args_keys` | Case-sensitive ARGS key matching (RFC 3986) |
| `coraza.rule.no_regex_multiline` | Disable default multiline mode in the `@rx` operator |
| `coraza.rule.mandatory_rule_id_check` | Require the `id` action for all SecRule/SecAction |
| `coraza.rule.rx_prefilter` | Default `SecRxPreFilter` to `On` (testing only) |
| `coraza.no_memoize` | Disable the default memoization of regex and Aho-Corasick builders |
| `no_fs_access` | Disable filesystem access (no file body buffers, no file operators) |
| `tinygo` | Set by the TinyGo toolchain; selects TinyGo-compatible sync primitives and FS handling |

Memoization is on by default and shares compiled patterns across WAF instances;
long-lived processes that reload rules should call `WAF.Close()` through
`experimental.WAFCloser` (see ADR-0042 and ADR-0043).

### Generated code

- `internal/seclang/directivesmap.gen.go`: generated from `internal/seclang/generator/`
- `internal/variables/variablesmap.gen.go`: generated from `internal/variables/generator/`

Run `go generate ./...` to regenerate (also done by `go run mage.go format` and
`go run mage.go lint`). Generated files are excluded from coverage (`codecov.yml`).

### TinyGo

TinyGo support affects concurrency primitives and filesystem access. The
`internal/sync/` package provides pool implementations:

- `pool_std.go`: standard Go `sync.Pool`
- `pool_tinygo.go`: TinyGo-compatible alternative

CI runs `tinygo test` over `internal/...` with and without `coraza.no_memoize`.
When touching concurrency or I/O, keep the TinyGo build green and use build tags
when necessary.

## Common tasks

Each task below adds a directive, operator, action or transformation. Those are
structural changes: the PR **must** include an ADR (see
[Architecture Decision Records](#architecture-decision-records)) and tests in the
home the [Testing](#testing) section assigns.

### Adding an operator

There are two workflows. Pick one; do not mix them.

**Built-in operator** (lives in `internal/operators`, registers through the
package's own `Register`):

1. Create `internal/operators/my_operator.go`:

   ```go
   package operators

   import "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"

   type myOperator struct {
       data string
   }

   func newMyOperator(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
       return &myOperator{data: options.Arguments}, nil
   }

   func (o *myOperator) Evaluate(tx plugintypes.TransactionState, value string) bool {
       // implementation
       return false
   }

   func init() {
       Register("myOperator", newMyOperator)
   }
   ```

2. Add rows to the operator's table test in `internal/operators/`, plus an engine
   profile if the behaviour depends on transaction state.

**External operator plugin** (lives in the integrator's package):

```go
package mywaf

import (
    "github.com/corazawaf/coraza/v3/experimental/plugins"
    "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func init() {
    plugins.RegisterOperator("myOperator", func(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
        return &myOperator{data: options.Arguments}, nil
    })
}
```

### Adding a transformation

**Built-in** (`internal/transformations`): add `my_transform.go` with
`func myTransform(input string) (string, bool, error)`, register it in the `init()`
list in `internal/transformations/transformations.go`, and add rows to the
package's table tests. Return `changed == false` when the output equals the input.

**External**: call `plugins.RegisterTransformation("myTransform", myTransform)`
from the integrator's package.

### Adding an action

**Built-in** (`internal/actions`): add `my_action.go` implementing
`plugintypes.Action`, register it in the `init()` list in
`internal/actions/actions.go`, and cover it with an engine profile.

```go
type myAction struct{}

func (a *myAction) Init(metadata plugintypes.RuleMetadata, data string) error { return nil }
func (a *myAction) Evaluate(metadata plugintypes.RuleMetadata, tx plugintypes.TransactionState) {}
func (a *myAction) Type() plugintypes.ActionType { return plugintypes.ActionTypeNondisruptive }
```

**External**: call `plugins.RegisterAction("myAction", func() plugintypes.Action { return &myAction{} })`
from the integrator's package.

### Adding a directive

1. Add the directive function in `internal/seclang/directives.go`:

   ```go
   func directiveMyDirective(options *DirectiveOptions) error { ... }
   ```

2. Run `go generate ./internal/seclang/...` to regenerate the directives map.
3. If the directive sets WAF-level config, add the field to `internal/corazawaf/waf.go`.
4. Document it (README or `coraza.conf-recommended` when it is user-facing) and
   add parse-error rows in `internal/seclang` plus a profile for its behaviour.

## Testing

Read this whole section before writing a single test. Coraza's test suite grew
from 64 to 148 files in three years while the engine barely changed shape. Most of
that growth is duplicated coverage, not new coverage. The rules below exist to stop
that.

### The prime directive

**A behaviour has exactly one home.** Before writing a test, find the home. If a
test for that behaviour already lives there, add a case to it. Do not create a
second home.

### Layer map

| What you are testing | Home | Do NOT put it in |
| --- | --- | --- |
| Rule and directive semantics: given these rules and this request, expect these rule IDs, this interruption, this log line | a profile in `testing/engine/*.go` | a hand-written `NewWAF` + `tx.Process*` test |
| SecLang parse errors, directive argument validation, rule compilation failures | table test in `internal/seclang` | engine profiles |
| One operator's boolean result for given inputs | table test in `internal/operators` | engine profiles |
| One transformation's string output | table test in `internal/transformations` | operators, engine profiles |
| One body processor's parsing of a payload into variables | table test in `internal/bodyprocessors` | engine profiles, `internal/corazawaf` |
| Go API contract of a public type (config, options, exported interfaces) | test next to the type | engine profiles |
| HTTP integration: middleware, interceptor, body streaming, websockets | `http/` | `internal/corazawaf`, `internal/seclang` |
| CRS regression | `testing/coreruleset` (go-ftw) | anywhere else |
| Behaviour of the test harness itself | nowhere, see "Do not test the harness" | `testing/` |

### Decision procedure

Run this in order. Stop at the first match.

1. **Can the behaviour be expressed as "rules + request -> expected output"?**
   Then it is a profile in `testing/engine/`. Write it there and stop. Almost
   everything about rule evaluation, actions, phases, chains, logging, `setvar`,
   transformations-in-context and `ctl` fits here.
2. **Is it one pure function with several inputs?** Add a **row** to the existing
   table test. Do not add a test function.
3. **Neither?** Write a test function, and put a one-line comment saying why it
   could not be a profile. If you cannot state a reason, it was a profile.

### Engine profiles are the default

`testing/profile` + `testing/engine/*.go` is the declarative harness. A profile is
a ruleset (`profile.Profile.Rules`), a set of tests, each with request stages and
expected outputs. `testing/coraza_test.go` runs every registered profile, and CI
runs it across the whole build-tag matrix for free.

Group profiles by the **behaviour** under test (`setvar.go`, `chains.go`,
`disruptive_actions.go`), not by the ruleset that happens to trigger it.

Available assertions in `profile.ExpectedOutput`:

| Field | Asserts |
| --- | --- |
| `TriggeredRules` / `NonTriggeredRules` | a rule id matched at least once / never |
| `LogContains` / `NoLogContains` | a substring is present / absent in the error log |
| `Interruption` | the interruption's rule id, action, status and data |
| `ExpectError` | running the phases returns an error |
| `Status`, `Headers`, `Data` | response status, headers and body (e2e style checks) |

If your case needs an assertion that does not exist, **add the assertion to the
harness** (`testing/profile/profile.go` and the checks in `testing/engine.go`), do
not hand-roll a transaction test. Extending `ExpectedOutput` pays off across every
future case; a hand-rolled test pays off once. When you extend it, verify the new
assertion **fails** when the expectation is wrong, not only that it passes.

```go
var _ = profile.RegisterProfile(profile.Profile{
    Meta: profile.Meta{
        Author:      "you",
        Description: "a rule matching many args logs once",
        Enabled:     true,
        Name:        "args_logging.yaml",
    },
    Tests: []profile.Test{{
        Title: "one log line per rule",
        Stages: []profile.Stage{{Stage: profile.SubStage{
            Input:  profile.StageInput{URI: "/?test1=123&test2=456"},
            Output: profile.ExpectedOutput{
                TriggeredRules: []int{1},
                LogContains:    `[tag "some1"]`,
            },
        }}},
    }},
    Rules: `
SecRuleEngine On
SecRule ARGS ".*" "id:1,phase:1,log,pass,tag:'some1'"
`,
})
```

### Table tests

Unit tests for pure functions are table-driven, and **every table uses `t.Run`**.
A table without subtests reports one failure for the whole table and cannot be run
selectively.

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
`TestFoo`, not three functions. Every table has positive and negative rows.

### Do not test the harness

`testing/`, `testing/profile` and test helpers are exercised by every profile that
runs through them. A test asserting that the harness formats its own error strings
correctly, or that a helper's argument validation returns the right error, is
coverage with no defect-finding power. Delete it on sight.

### Testing anti-patterns

Each of these produced real duplication in this repo. Do not add more.

- **Coverage-driven tests.** A test written to reach an uncovered line or branch,
  with no failure mode in mind. Coverage is an outcome, not a target.
- **The same scenario at several layers.** A chained-rule test in
  `internal/seclang`, a near-identical one in `internal/corazawaf`, and a profile in
  `testing/engine`. Pick the layer from the map above.
- **One function per assertion.** Splitting `TestX` into `TestX_CaseA` ...
  `TestX_CaseF` because each has one `if`.
- **Constructor and accessor tests.** Asserting `New()` returns non-nil, that a
  getter returns what a setter just set, or that `String()` contains a substring.
- **Restating the implementation.** A test that recomputes the expected value with
  the same expression the code uses passes for any behaviour.
- **A new `_test.go` file per feature.** Add to the package's existing test file
  unless the package has none.
- **Benchmarks without a claim.** Add a benchmark only when a specific performance
  change is being argued, and only alongside a before/after number in the PR.
- **Table tests without `t.Run`.**

### Coverage: good, not padded

Coverage is measured by `go run mage.go coverage` (race detector, atomic mode,
`-coverpkg=./...`) and reported to Codecov. Generated files and generators are
excluded by `codecov.yml`.

- **Coverage is a signal, not a target.** A red line in the report means "no test
  describes what this code does". The fix is to describe the behaviour, in its home
  from the layer map, with an assertion that would fail if the code were wrong.
- **Ask what reaches the branch.** For every uncovered branch: which input gets
  there, and what must happen? If that is a real behaviour, add one row or profile
  case asserting it. If nothing realistic reaches it, it is dead or defensive code:
  simplify it or leave it uncovered. Never write a test whose only purpose is to
  execute a line.
- **Critical paths first.** Rule evaluation, body processors, the SecLang parser,
  collections and the HTTP layer must have every reachable branch described. A
  helper's `String()` method does not need to.
- **Both directions.** Every behaviour has a matching and a non-matching case, a
  valid and an invalid input. A test suite that only proves the happy path has low
  coverage no matter what the percentage says.
- **Do not lower coverage silently.** If a change removes tests or leaves new
  branches undescribed, say so in the PR and why.
- **Show the numbers when you claim them.** Compare before and after with
  `go tool cover -func=build/coverage.txt` for the packages you touched, and put the
  delta in the PR description.
- **Coverage must survive the tag matrix.** Behaviour behind a build tag is covered
  only if a test runs under that tag. Profiles do; hand-written tests usually do not.

### Instructions specific to coding agents

- **Default to zero new test functions.** The expected output of most changes is
  new *rows* and new *profile cases*, not new functions or files.
- **Search before writing.** Grep the repo for the behaviour and read the existing
  profiles for the area. State what you found and why it is insufficient before
  adding anything.
- **A bug fix gets one regression case**, in the profile that owns that behaviour.
  Not one per code path you touched.
- **Never add tests "for completeness", "for edge cases" or "to raise coverage"**
  unless explicitly asked. If you believe coverage is genuinely missing, say so and
  let a human decide.
- **Deleting a redundant test is a valid, welcome change.** If you find a test that
  duplicates a profile, say so; do not add a third copy.
- **Run what CI runs.** A change to rule evaluation must pass at least
  `coraza.no_memoize`, `coraza.rule.multiphase_evaluation` and
  `coraza.rule.no_regex_multiline`. `go run mage.go test` covers that.

### Running tests

```bash
go run mage.go test        # full matrix: default, no_memoize, CRS, multiphase, no_regex_multiline
go run mage.go check       # tests plus lint
go test ./testing/         # every declarative engine profile
go test -race ./...
go test -tags=coraza.rule.multiphase_evaluation ./testing/coreruleset
```

Other suites: `testing/e2e` (against a live server, see README "E2E Testing"),
`testing/modsecurity` (ModSecurity comparison, separate module) and
`go run mage.go fuzz`.

## Architecture Decision Records

An ADR records what was decided, what the alternatives were and why one was chosen.
The standard lives in [`docs/adr/README.md`](docs/adr/README.md) and the template in
[`docs/adr/0000-template.md`](docs/adr/0000-template.md). This section only tells
you when the standard applies and what an agent must not do.

### When a PR needs one

Write an ADR, **in the same PR**, when the change alters the shape of Coraza:

- a new directive, operator, action, transformation, variable or collection
- a new subsystem, or a new plugin / experimental surface
- a breaking change to a public API
- an algorithmic or allocation change that shifts performance characteristics
- an internal refactor that changes how a subsystem is structured

Skip it for bug fixes, documentation, CI, chores and dependency bumps. If a reviewer
would have to ask "why this way?", write one.

### How to write one

1. Copy `docs/adr/0000-template.md` to `docs/adr/NNNN-short-slug.md`, taking the
   next free number (`ls docs/adr | tail`), lower-kebab-case slug.
2. Fill in all seven header fields. `Category` is exactly one of **Feature**,
   **Parity**, **Perf** or **Refactor**, optionally followed by one parenthetical
   qualifier. Use "No linked issue" rather than dropping `Issue(s)`. `Version` is
   the release the change lands in; use `unreleased (post-vX.Y.Z)` when unknown.
   `Date` is the merge date: use the expected date and update it before merge.
   `Status` is `proposed` while the PR is under review and `accepted` on merge.
3. Keep `Considered Options` honest: if there was only ever one option, say so.
4. `## Technical Discussion` must contain either verbatim quotes with permalinks
   into this repository (one comment per blockquote, `[...]` for every omission), or
   a line starting with "No substantive technical discussion recorded". For an ADR
   written alongside the change, the marker sentence is the normal case; update it
   with real quotes if review produces substantive discussion.
5. Add a row to the index table in `docs/adr/README.md`.
6. Run `go run mage.go adr`. CI runs the same check on any PR touching `docs/adr/`.

### Rules for coding agents

- **Never invent discussion, deciders or quotes.** A quote puts words in a named
  person's mouth; only copy text you can link to. If unsure, use the marker sentence.
- **Never rewrite an accepted ADR** to match a new change. Write a new one and set
  the old one's status to `superseded by ADR-NNNN`.
- **One category per record.** If a change feels like two, name the one that drove it.
- **Do not create an ADR for a bug fix** just because the diff is large.
- Reference related ADRs by number in `## References`; the index in
  `docs/adr/README.md` is the map of prior decisions. Read it before proposing a
  change that touches the same area.

## Pull requests

Follow [`CONTRIBUTING.md`](CONTRIBUTING.md) and fill in the pull request template
honestly: the checklist is a contract, not decoration.

### Before opening

- Enhancements are proposed in an
  [issue](https://github.com/corazawaf/coraza/issues) first, so the use case is
  agreed before code is written; bug fixes can go straight to a PR with a linked
  issue. The project does not use GitHub Discussions.
- One logical change per PR. No drive-by refactors, formatting or dependency bumps.
- `go run mage.go check` passes locally (or install the hook with
  `go run mage.go precommit`). `go run mage.go adr` passes if `docs/adr/` changed.
- Tests follow the [Testing](#testing) section. Structural changes ship with an ADR.
- Backward compatibility is kept. Intentional deviations from ModSecurity are
  documented in the code and the PR.
- User-facing changes update `README.md`, `coraza.conf-recommended` and the
  relevant example.

### Title and description

- Title in conventional-commit style, as in the history:
  `feat(seclang): ...`, `fix(bodyprocessors): ...`, `perf(rx): ...`,
  `docs(adr): ...`, `test(engine): ...`, `chore(deps): ...`.
- The description says **what** changed, **why** (link the issue),
  and **how it was verified**: which mage targets and build tags were run, and the
  before/after numbers for any performance or coverage claim.
- Call out behaviour changes, compatibility notes and follow-ups explicitly. A
  reviewer should not have to read the diff to learn that something changed.
- Link the ADR when there is one.

### Commits

- Small, self-contained commits with the same title style as PRs.
- Do not commit generated files by hand; run `go run mage.go format`.
- Do not commit build artifacts (`build/`), coverage files or editor settings.

## Security

### Vulnerabilities

- **Never open a public issue or PR describing an exploitable bug.** Report it
  through the GitHub security advisory link in [`SECURITY.md`](SECURITY.md). The
  project follows a 90-day coordinated disclosure timeline.
- A valid report needs a **working proof of concept**, affected versions and a
  concrete impact. `SECURITY.md` explains that speculative, theoretical or
  AI-generated reports without a reproducer are closed as invalid.
- **Coding agents do not file security reports.** If you find something that looks
  exploitable while working, stop, describe it privately to the maintainer you are
  working with, with a reproducer, and let a human decide how to disclose it.
- A fix for a reported vulnerability is developed on a private fork / advisory
  branch, not on a public PR, until the advisory is published.

### Secure coding

- Treat every request byte, rule argument and configuration value as
  attacker-controlled input. Validate it.
- Never log sensitive data (passwords, tokens, session IDs, request bodies at
  info level).
- Use constant-time comparisons for security-sensitive operations.
- Be cautious with regexes that could cause ReDoS; prefer the memoized builders
  and the `@rx` prefilter paths already in the engine.
- Respect body limits and their actions. [`RATIONALE.md`](RATIONALE.md) explains
  why the memory and disk limits must stay defensive; a change that buffers more
  needs an ADR.
- Never panic in library code; an integrator's process must not die because of a
  malformed request.

## Code style and conventions

### General Go

- Follow standard Go conventions and idioms; format with `gofmt` and `goimports`
  (`go run mage.go format`). Lint with `golangci-lint` via `go run mage.go lint`.
- Prefer clear, readable code over clever optimisations.
- Keep functions small and focused on a single responsibility.
- Every file starts with the Apache-2.0 license header (`addlicense` adds it).

### Naming

- camelCase for variables and unexported functions (`ruleset`, `parseRule`).
- PascalCase for exported types and functions (`WAF`, `Transaction`).
- Descriptive names for collections (`rules []Rule`, not `r []Rule`).

### Error handling

- Always check and handle errors explicitly.
- Never panic in library code.
- Wrap errors with context: `fmt.Errorf("context: %w", err)`.
- Use custom error types for domain-specific errors.
- Log errors at the appropriate level and avoid interpolation in log calls.

### Comments and documentation

- Package-level documentation for every package.
- Document all exported functions, types and variables, starting the comment with
  the name of the item, in complete sentences.

## Project-specific guidelines

### Rules and directives

- Rules are immutable after compilation.
- Support ModSecurity directives where possible; document intentional deviations.
- Validate rule syntax during parsing and give clear errors for invalid rules.

### Transaction processing

- Transactions must be concurrent-safe and hold isolated state.
- Clean up resources after transaction completion (`tx.Close()`).
- Support interruption (block/drop) at any phase.

### Performance

- **Be obsessed about performance in critical paths and memory leaks.**
- Avoid excessive locking and unnecessary allocations in hot paths.
- Use object pooling for frequently created objects (e.g. transactions).
- Profile and benchmark before optimising; target real bottlenecks, in the order of
  microseconds rather than nanoseconds, and put the numbers in the PR.
- Minimise rule evaluation overhead; only evaluate necessary rules.

### Concurrency

- Be mindful of the TinyGo environment and its limitations; use build tags when
  necessary.
- Protect shared state with mutexes; document thread-safety guarantees.
- Maintain consistent lock ordering to avoid deadlocks.
- Use `sync.Pool` (through `internal/sync`) for object reuse.

### File organisation

- Packages are internal unless they are part of the public API.
- Use `experimental/` for experimental public surface.
- Keep tests in the same package as the code under test.

### Dependencies

- Minimise external dependencies; prefer the standard library.
- Document why each dependency is needed.
- **No CGO.** Coraza is pure Go and must stay that way: it has to build with
  TinyGo, cross-compile without a C toolchain and embed in WASM. A dependency
  that needs CGO is rejected, however good it is.
- **`unsafe` is prohibited in most cases.** The only accepted use is zero-copy
  string/byte reinterpretation on a measured hot path, and that already exists
  in `internal/strings` and `internal/corazawaf/rule.go` (see ADR-0019). Reuse
  those helpers instead of adding a new `import "unsafe"`. A new use needs a
  benchmark that shows a real win, an ADR, and reviewer agreement.

### Code anti-patterns

- No CGO, and no new `unsafe` (see Dependencies).
- No global mutable state.
- No reflection in performance-critical code.
- Do not ignore errors.
- Avoid long parameter lists; use structs or the options pattern.
- Do not mix business logic with I/O.

### Logging

- Use structured logging (`debuglog`) with relevant context (transaction ID, rule ID).
- Do not log in tight loops.

### Adding a feature

1. Establish a solid use case with more than one potential user.
2. Document the feature, and record the decision in an ADR.
3. Update the relevant examples.
4. Keep backward compatibility.
