# Ollama-backed E2E Test for Streaming Body Processor

**Date:** 2026-06-07  
**Branch:** feat/streaming-body-processor-interface  
**Status:** Approved

## Problem

The `StreamingBodyProcessor` interface and `ProcessResponseBodyFromStream` path on `StreamingTransaction` have unit and middleware tests, but no end-to-end test against a real streaming source. This design adds an Ollama-backed e2e test that exercises the full relay path: real NDJSON records from a live LLM → WAF rule evaluation per record → verbatim relay to client with per-record flush.

## Scope

- New `testing/e2e/ollama/` package (3 files)
- No changes to existing source, interfaces, or test infrastructure
- Does not run in the standard `go test ./...` suite unless `OLLAMA_BASE_URL` is set

## Context

The LLM proxy pattern (go-llm-proxy reference) is sequential: the full request body (prompt) is consumed before the backend starts streaming response tokens. This means phases 1–2 complete before phases 3–4 begin — no full-duplex coordination is needed. The existing `StreamingTransaction` interface is sufficient. The e2e test validates the response-side streaming path only.

Ollama's `/api/chat` endpoint returns NDJSON (one JSON object per line), which maps cleanly to the `Record`-per-line model of `StreamingBodyProcessor`. The OpenAI-compatible SSE endpoint was considered but rejected: NDJSON is simpler to parse per-record and more directly exercises the new interface.

## File Layout

```
testing/e2e/ollama/
├── compose.yml           # Ollama service + named volume for model cache
├── run.sh                # Lifecycle: up → wait → pull → test → down
└── ollama_e2e_test.go    # Body processor + WAF proxy handler + test cases
```

## Components

### `compose.yml`

- Service: `ollama/ollama@sha256:<digest>` — **pin to a specific digest before merging**
- Port: `11434:11434`
- Named volume `ollama_models` mounted at `/root/.ollama` — model cache survives between runs
- Healthcheck: `curl -sf http://localhost:11434/api/version` every 5 s, 20 retries, 10 s start period
- `down` (without `--volumes`) preserves the model cache; `run.sh` uses this intentionally

### `run.sh`

- `set -euo pipefail`
- `trap cleanup EXIT` where `cleanup` calls `docker compose down` — runs even on panic or SIGINT
- `OLLAMA_MODEL` env var, defaults to `tinyllama`
- Polls `$OLLAMA_URL/api/version` until ready (separate from compose healthcheck — better UX)
- `docker compose exec ollama ollama pull "$MODEL"` — idempotent, skips download if cached
- Passes `OLLAMA_BASE_URL` and `OLLAMA_MODEL` into `go test -v -timeout 180s ./testing/e2e/ollama/...`

### `ollamaChatBodyProcessor`

Implements `plugintypes.StreamingBodyProcessor`. Registered in `init()` as `"ollama-chat"`.

**`ProcessResponseRecords`** — the only method with meaningful logic:
- Scans NDJSON lines with `bufio.Scanner`
- Unmarshals each line into `struct{ Message struct{ Content string } }`
- Yields one `Record` per non-empty line
- `Fields()` returns `{"ollama.content": "<content>"}` when content is non-empty; empty map for the terminal `done:true` line
- `Raw()` returns a copy of the raw bytes + trailing `\n` (ownership contract: safe to retain across calls)

**`ProcessRequest` / `ProcessResponse` / `ProcessRequestRecords`** — no-ops; Ollama requests are not streamed.

WAF variable set: `RESPONSE_ARGS:ollama.content` per record, cleared between records by the transaction loop (existing behaviour in `ProcessResponseBodyFromStream`).

**JSON unmarshal errors** on individual lines are silently ignored: the record is still yielded with an empty `Fields()` map and its raw bytes relayed verbatim. This keeps the stream intact for unrecognised or partial lines. Scanner-level I/O errors (network failure, unexpected EOF) are returned immediately and propagate through `ProcessResponseBodyFromStream`.

### WAF proxy handler

`ollamaWAFProxyHandler(waf coraza.WAF, ollamaURL string) http.HandlerFunc`

Phase sequence:
1. `ProcessConnection` → `ProcessURI` → `AddRequestHeader` × N → `ProcessRequestHeaders` — interrupt → 403
2. `io.ReadAll(r.Body)` → `WriteRequestBody` → `ProcessRequestBody` — interrupt → 403
3. Forward to Ollama via `http.Client`
4. `AddResponseHeader` × N → `ProcessResponseHeaders` — interrupt → 403
5. Commit response headers + status to client (`w.WriteHeader`)
6. `ProcessResponseBodyFromStream(resp.Body, flushWriter{w, flusher})` — on interruption: hijack TCP connection and close

**`flushWriter`:** wraps `http.ResponseWriter` + `http.Flusher`; calls `Flush()` after every `Write()`. Ensures each passing record reaches the client immediately without buffering.

**Header commit timing:** `w.WriteHeader` is called after phase 3 passes, before phase 4 begins. A phase 4 interruption cannot change the status code. The proxy signals interruption by dropping the TCP connection via `http.Hijacker`. This accurately represents production streaming WAF behaviour.

### Test cases

Both cases live in `TestOllamaStreaming(t)` using `t.Run`. The test skips if `OLLAMA_BASE_URL` is empty.

**WAF directives for both cases:**
```
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType application/x-ndjson
# Activate the streaming body processor for Ollama responses
SecRule RESPONSE_HEADERS:Content-Type "@contains application/x-ndjson" \
  "id:1,phase:3,pass,nolog,ctl:responseBodyProcessor=ollama-chat"
# Block rule evaluated per record
SecRule RESPONSE_ARGS:ollama.content "@rx CORAZA_BLOCK" "id:200,phase:4,deny,log"
```

**Case 1 — clean stream passes through**
- Prompt: `"Say hello and nothing else."`
- WAF rule: `SecRule RESPONSE_ARGS:ollama.content "@rx CORAZA_BLOCK" "id:200,phase:4,deny,log"`
- Assertions: status 200; at least one NDJSON line with non-empty content received; final line contains `"done":true`

**Case 2 — blocked content drops connection**
- Prompt: `"Reply with exactly the text CORAZA_BLOCK_TEST and nothing else."`
- Ollama options: `temperature:0`, `seed:42`
- WAF rule: same as case 1
- Assertions: reading the NDJSON stream hits `io.EOF` or `io.ErrUnexpectedEOF` before a line containing `"done":true` is seen

**Non-determinism mitigation:**
- `temperature:0` + `seed:42` makes `tinyllama` output stable for direct-repeat prompts
- Regex `CORAZA_BLOCK` (prefix, not full string) matches even if the model slightly reformats the output
- Failure message distinguishes non-determinism ("done:true reached client") from code bug

## Error handling

| Failure point | Behaviour |
|---|---|
| Ollama unreachable | `http.StatusBadGateway` from proxy; test fails with clear upstream error |
| Phase 1/2/3 interruption | `http.Error(w, "blocked", 403)` before any streaming starts |
| Phase 4 interruption | TCP connection hijacked and closed; client sees premature EOF |
| NDJSON scanner I/O error | `ollamaChatBodyProcessor` returns the error; `ProcessResponseBodyFromStream` surfaces it |
| JSON unmarshal error on one line | Silently skipped: empty `Fields()`, raw bytes relayed verbatim; stream continues |
| `http.Hijacker` unavailable | Interruption is silently swallowed — acceptable only in tests; `httptest.NewServer` always provides a hijackable writer |

## Out of scope

- Full-duplex / dual-transaction design (not needed for LLM proxy pattern; see analysis in conversation)
- OpenAI-compatible SSE endpoint (`/v1/chat/completions`)
- GHA workflow — test is local-only via Docker Compose + script for now
- Model other than `tinyllama` (configurable via `OLLAMA_MODEL` but not tested with others)
