# Coraza WAF - LLM Navigation Guide

This document helps LLMs (GitHub Copilot, Claude, Cursor, etc.) understand the Coraza codebase architecture, navigate the code, and perform common tasks.

## Project Overview

Coraza is a Web Application Firewall (WAF) engine written in Go. It implements the SecLang directive language (compatible with ModSecurity v2/v3), is fully compatible with OWASP Core Rule Set (CRS) v4, and is an OWASP Production Project. Coraza also supports TinyGo compilation for environments with constrained runtimes (e.g. WASM).

## Repository Structure

| Directory | Purpose |
|---|---|
| `types/` | Public API interfaces: `Transaction`, `WAF`, `MatchData`, `Interruption`, `RuleMetadata`, variables |
| `collection/` | Public collection interfaces: `Collection`, `Single`, `Keyed`, `Map` |
| `debuglog/` | Debug logging interfaces and helpers |
| `http/` | HTTP integration helpers and end-to-end tests |
| `testing/` | Test utilities, test data, and CRS regression tests |
| `examples/` | Usage examples (e.g. `http-server`) |
| `experimental/plugins/` | Plugin registration system: `RegisterOperator()`, `RegisterTransformation()`, `RegisterAction()` |
| `experimental/plugins/plugintypes/` | Plugin interfaces: `Operator`, `Transformation`, `Action`, `TransactionState`, `RuleMetadata` |
| `experimental/plugins/macro/` | Macro expansion for rule messages and log data |
| `internal/corazawaf/` | Core WAF and Transaction implementation, RuleGroup evaluation |
| `internal/corazarules/` | Rule metadata and match data implementation |
| `internal/collections/` | Variable storage implementations: `Map`, `Named`, `Single`, `Sized` |
| `internal/operators/` | All operator implementations (~38 non-test files) |
| `internal/transformations/` | All transformation implementations (~33 non-test files) |
| `internal/actions/` | All action implementations (~33 non-test files) |
| `internal/seclang/` | SecLang rule and directive parser |
| `internal/auditlog/` | Audit logging: serial, concurrent, syslog, HTTPS writers; JSON and OCSF formatters |
| `internal/bodyprocessors/` | Body parsers: JSON, XML, multipart, urlencoded, raw |
| `internal/variables/` | Variable type system with generated maps |
| `internal/strings/`, `internal/url/`, `internal/cookies/` | Utility packages |
| `internal/sync/` | TinyGo-compatible sync primitives (`pool.go`, `pool_std.go`, `pool_tinygo.go`) |
| `internal/memoize/` | Memoization utilities for builders |
| `internal/environment/` | Build environment detection (FS access, etc.) |

## Architecture: Request Processing Pipeline

Every HTTP request/response flows through 5 phases. Each `Process*` method triggers `WAF.Rules.Eval(phase, tx)` and checks for interruptions.

### Phase 1 - Request Headers
```
ProcessConnection(clientIP, clientPort, serverIP, serverPort)
  -> ProcessURI(uri, method, httpVersion)
  -> AddRequestHeader(key, value)  // repeat per header
  -> ProcessRequestHeaders() -> *Interruption
```

### Phase 2 - Request Body
```
WriteRequestBody([]byte) / ReadRequestBodyFrom(io.Reader)
  -> ProcessRequestBody() -> (*Interruption, error)
```
The body processor type (JSON, XML, multipart, urlencoded) is auto-detected from the `Content-Type` header. The processor parses the body into WAF variables (e.g. `ARGS_POST`, `REQUEST_BODY`, `FILES`).

### Phase 3 - Response Headers
```
AddResponseHeader(key, value)  // repeat per header
  -> ProcessResponseHeaders(statusCode, proto) -> *Interruption
```

### Phase 4 - Response Body
```
WriteResponseBody([]byte) / ReadResponseBodyFrom(io.Reader)
  -> ProcessResponseBody() -> (*Interruption, error)
```

### Phase 5 - Logging
```
ProcessLogging()
```

**Key files:**
- `types/transaction.go` - Transaction interface (public API)
- `internal/corazawaf/transaction.go` - Transaction implementation
- `internal/corazawaf/rulegroup.go` - `RuleGroup.Eval(phase, tx)` iterates rules in syntactic order

## Architecture: Rule Evaluation

When `RuleGroup.Eval(phase, tx)` is called, each rule in the group is evaluated in order. Evaluation stops early if an interruption is triggered (except in the logging phase).

### Step-by-step evaluation (`Rule.Evaluate` / `Rule.doEvaluate`):

1. **Variable extraction**: Each rule's `variables` list is iterated. For each variable, `tx.GetField(v)` extracts values from the transaction's collections, applying key filtering (exact string or regex) and exceptions (`!VARIABLE:key`). The `&VARIABLE` syntax returns the count instead of the value.

2. **Transformation pipeline**: Each extracted value passes through the rule's ordered list of transformations. Results are cached per (variable, key, transformationID) to avoid redundant work. The TX variable is never cached. MultiMatch mode runs each transformation individually.

3. **Operator evaluation**: `Rule.executeOperator(transformedValue, tx)` calls `Operator.Evaluate(tx, value) -> bool`. If the rule has `Negation` set, the result is inverted.

4. **Action execution** (only on the parent rule, not chain children):
   - **Flow actions** first (e.g. `skip`, `skipAfter`) - always evaluated
   - **Disruptive actions** (e.g. `deny`, `drop`, `redirect`) - only when `RuleEngine` is `On` (not `DetectionOnly`)
   - **Non-disruptive actions** (e.g. `log`, `setvar`, `capture`) - evaluated per match

5. **Chain processing**: If a rule has `Chain` set, the parent must match first. Then each chained rule is evaluated recursively via `doEvaluate`. All rules in the chain must match for the overall rule to match. If any chain child fails, the entire rule is considered unmatched.

**Key files:**
- `internal/corazawaf/rule.go` - `Rule` struct, `Evaluate()`, `doEvaluate()`, `executeOperator()`, transformation caching
- `internal/corazawaf/rulegroup.go` - `RuleGroup.Eval()` with phase filtering, skip/skipAfter, allow handling

## Plugin System

Coraza is extended through plugins. All registration happens via the `experimental/plugins` package.

### Operators

```go
// Interface (plugintypes/operator.go)
type Operator interface {
    Evaluate(TransactionState, string) bool
}
type OperatorFactory func(options OperatorOptions) (Operator, error)

// Registration (plugins/operators.go)
plugins.RegisterOperator("myop", factory)
```

### Transformations

```go
// Type signature (plugintypes/transformation.go)
type Transformation = func(input string) (output string, changed bool, err error)

// Registration (plugins/transformations.go)
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

// Registration (plugins/actions.go)
type ActionFactory = func() plugintypes.Action
plugins.RegisterAction("myaction", factory)
```

## Collection System

WAF variables are stored in typed collections within each transaction.

| Interface | Description | Example Variables |
|---|---|---|
| `collection.Single` | Single string value | `REQUEST_METHOD`, `RESPONSE_STATUS`, `REQUEST_URI` |
| `collection.Keyed` | Named lookups with key/regex support | `REQUEST_HEADERS`, `ARGS`, `TX` |
| `collection.Map` | Mutable keyed collection (extends `Keyed`) | `REQUEST_HEADERS`, `ARGS_POST`, `ARGS_GET` |

Collections are NOT concurrent-safe. Each transaction has its own isolated set.

**Key files:**
- `collection/collection.go` - Public interfaces: `Collection`, `Single`, `Keyed`, `Map`
- `internal/collections/map.go` - Map implementation with case-insensitive option
- `internal/collections/named.go` - Named collection implementation
- `internal/collections/single.go` - Single value collection
- `internal/collections/sized.go` - Size-tracking collection

## SecLang Parser

The parser compiles SecLang directives into WAF rules and configuration.

### Entry points
- `Parser.FromFile(path)` - Load from file (supports glob patterns with `*`)
- `Parser.FromString(data)` - Load from string

### Parsing flow
1. Lines are read with `bufio.Scanner`
2. Line continuations (`\` at end) and backtick multi-line blocks are handled
3. Comments (`#`) are skipped
4. Each complete line is split into directive name + options
5. The directive name is looked up in `directivesMap` (generated) and the corresponding function is called
6. `include` is handled specially with recursion protection (max 100 levels)

### Rule format
```
SecRule VARIABLES "OPERATOR" "ACTIONS"
```
- **Variable syntax**: `VARIABLE[:key]`, `VARIABLE:/regex/`, `&VARIABLE` (count), `!VARIABLE:key` (exception), `VARIABLE1|VARIABLE2` (multiple)
- **Operator syntax**: `@operatorName arguments` (e.g. `@rx pattern`, `@eq 0`)
- **Actions**: comma-separated list (e.g. `id:100,phase:1,deny,log,msg:'Blocked'`)

**Key files:**
- `internal/seclang/parser.go` - `Parser` struct, `FromFile()`, `FromString()`, line parsing
- `internal/seclang/rule_parser.go` - `RuleParser`, `ParseVariables()`, variable/operator/action parsing
- `internal/seclang/directives.go` - Directive implementations
- `internal/seclang/directivesmap.gen.go` - Generated directive name -> function map

## Build System and TinyGo

### Mage tasks
```bash
go run mage.go test       # Run all tests (including memoize_builders, multiphase, CRS)
go run mage.go lint       # Lint (generates code, checks formatting, runs golangci-lint)
go run mage.go coverage   # Tests with coverage and race detector
go run mage.go format     # Format code (go generate, goimports, addlicense)
go run mage.go fuzz       # Run fuzz tests
```

### Build tags
| Tag | Effect |
|---|---|
| `coraza.disabled_operators.<name>` | Exclude a specific operator from compilation |
| `coraza.rule.multiphase_evaluation` | Evaluate rule variables in phases they become ready |
| `coraza.rule.case_sensitive_args_keys` | Case-sensitive ARGS key matching (RFC 3986) |
| `coraza.rule.no_regex_multiline` | Disable default multiline mode in `@rx` operator |
| `coraza.rule.mandatory_rule_id_check` | Require `id` action for all SecRule/SecAction |
| `tinygo` | TinyGo-compatible build (affects sync primitives, FS access) |
| `memoize_builders` | Enable memoization of operator/transformation builders |
| `no_fs_access` | Disable filesystem access |

### Generated code
- `internal/seclang/directivesmap.gen.go` - Generated from `internal/seclang/generator/`
- `internal/variables/variablesmap.gen.go` - Generated from `internal/variables/generator/`

Run `go generate ./...` to regenerate (also done by `go run mage.go format` and `go run mage.go lint`).

### TinyGo
TinyGo support affects concurrency primitives. The `internal/sync/` package provides pool implementations:
- `pool_std.go` - Standard Go `sync.Pool`
- `pool_tinygo.go` - TinyGo-compatible alternative

## Common Tasks

### Adding a new operator

1. Create `internal/operators/my_operator.go`:
   ```go
   type myOperator struct {
       data string
   }
   func (o *myOperator) Evaluate(tx plugintypes.TransactionState, value string) bool {
       // implementation
   }
   ```
2. Register in `internal/operators/` init or via `experimental/plugins/operators.go`:
   ```go
   plugins.RegisterOperator("myOperator", func(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
       return &myOperator{data: options.Arguments}, nil
   })
   ```
3. Add tests in `internal/operators/my_operator_test.go`

### Adding a new transformation

1. Create `internal/transformations/my_transform.go`:
   ```go
   func myTransform(input string) (string, bool, error) {
       // return (result, changed, nil)
   }
   ```
2. Register via `experimental/plugins/transformations.go`:
   ```go
   plugins.RegisterTransformation("myTransform", myTransform)
   ```
3. Add tests in `internal/transformations/my_transform_test.go`

### Adding a new action

1. Create `internal/actions/my_action.go` implementing `plugintypes.Action`:
   ```go
   type myAction struct {}
   func (a *myAction) Init(metadata plugintypes.RuleMetadata, data string) error { return nil }
   func (a *myAction) Evaluate(metadata plugintypes.RuleMetadata, tx plugintypes.TransactionState) { }
   func (a *myAction) Type() plugintypes.ActionType { return plugintypes.ActionTypeNondisruptive }
   ```
2. Register via `experimental/plugins/actions.go`:
   ```go
   plugins.RegisterAction("myAction", func() plugintypes.Action { return &myAction{} })
   ```
3. Add tests in `internal/actions/my_action_test.go`

### Adding a new directive

1. Add the directive function in `internal/seclang/directives.go`:
   ```go
   func directiveMyDirective(options *DirectiveOptions) error { ... }
   ```
2. Run `go generate ./internal/seclang/...` to regenerate the directives map
3. If the directive sets WAF-level config, add the field to `internal/corazawaf/waf.go`

## Testing Patterns

- **Table-driven tests** with `t.Run()` for logical grouping
- **Operator tests** follow SpiderLabs secrules-language-tests format with JSON test data in `testdata/` directories
- **Full test suite**: `go run mage.go test`
- **Coverage with race detector**: `go run mage.go coverage`
- **CRS regression tests**: Located in `testing/coreruleset/`
- **End-to-end HTTP tests**: Located in `http/` package
- **Fuzz tests**: `go run mage.go fuzz` (operators: SQLi/XSS, transformations: base64/cmdline)
