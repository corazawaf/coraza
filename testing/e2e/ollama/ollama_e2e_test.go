//go:build !tinygo

package ollamae2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// --- ollamaRecord ---

type ollamaRecord struct {
	fields map[string]string
	raw    []byte
}

func (r ollamaRecord) Fields() map[string]string { return r.fields }
func (r ollamaRecord) Raw() []byte               { return r.raw }

// --- ollamaChatBodyProcessor ---

type ollamaChatBodyProcessor struct{}

func (*ollamaChatBodyProcessor) ProcessRequest(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (*ollamaChatBodyProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (*ollamaChatBodyProcessor) ProcessRequestRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions, _ func(int, plugintypes.Record) error) error {
	return nil
}

func (*ollamaChatBodyProcessor) ProcessResponseRecords(r io.Reader, _ plugintypes.BodyProcessorOptions, fn func(int, plugintypes.Record) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1*1024*1024)
	for i := 0; scanner.Scan(); i++ {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var line struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		fields := make(map[string]string)
		if json.Unmarshal(raw, &line) == nil && line.Message.Content != "" {
			fields["ollama.content"] = line.Message.Content
		}
		// Make an independent copy — scanner reuses the underlying buffer.
		relay := make([]byte, len(raw)+1)
		copy(relay, raw)
		relay[len(raw)] = '\n'
		if err := fn(i, ollamaRecord{fields: fields, raw: relay}); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func init() {
	plugins.RegisterBodyProcessor("ollama-chat", func() plugintypes.BodyProcessor {
		return &ollamaChatBodyProcessor{}
	})
}

// --- Unit tests for ollamaChatBodyProcessor ---

func TestOllamaChatBodyProcessor_Fields(t *testing.T) {
	input := strings.Join([]string{
		`{"model":"tinyllama","message":{"role":"assistant","content":"Hello"},"done":false}`,
		`{"model":"tinyllama","message":{"role":"assistant","content":" world"},"done":false}`,
		`{"model":"tinyllama","done":true,"total_duration":12345}`,
	}, "\n") + "\n"

	p := &ollamaChatBodyProcessor{}
	type rec struct {
		fields map[string]string
		raw    []byte
	}
	var got []rec
	err := p.ProcessResponseRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(_ int, r plugintypes.Record) error {
			f := make(map[string]string, len(r.Fields()))
			maps.Copy(f, r.Fields())
			rawCopy := make([]byte, len(r.Raw()))
			copy(rawCopy, r.Raw())
			got = append(got, rec{fields: f, raw: rawCopy})
			return nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 records, got %d", len(got))
	}
	if got[0].fields["ollama.content"] != "Hello" {
		t.Errorf("record 0: got %q, want %q", got[0].fields["ollama.content"], "Hello")
	}
	if got[1].fields["ollama.content"] != " world" {
		t.Errorf("record 1: got %q, want %q", got[1].fields["ollama.content"], " world")
	}
	if len(got[2].fields) != 0 {
		t.Errorf("record 2 (done:true) should have empty fields, got %v", got[2].fields)
	}
	for i, r := range got {
		if len(r.raw) == 0 || r.raw[len(r.raw)-1] != '\n' {
			t.Errorf("record %d raw does not end with newline", i)
		}
	}
}

func TestOllamaChatBodyProcessor_CallbackError(t *testing.T) {
	input := `{"message":{"content":"a"},"done":false}` + "\n" +
		`{"message":{"content":"b"},"done":false}` + "\n"
	p := &ollamaChatBodyProcessor{}
	count := 0
	sentinel := errors.New("stop")
	err := p.ProcessResponseRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(_ int, _ plugintypes.Record) error {
			count++
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
	if count != 1 {
		t.Errorf("expected callback called once before stop, got %d", count)
	}
}

func TestOllamaChatBodyProcessor_MalformedJSON(t *testing.T) {
	// Malformed lines get empty fields but are still relayed verbatim
	input := "not-json\n" + `{"message":{"content":"ok"},"done":false}` + "\n"
	p := &ollamaChatBodyProcessor{}
	type rec struct {
		fields map[string]string
		raw    string
	}
	var got []rec
	if err := p.ProcessResponseRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(_ int, r plugintypes.Record) error {
			got = append(got, rec{fields: r.Fields(), raw: string(r.Raw())})
			return nil
		}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	if len(got[0].fields) != 0 {
		t.Errorf("malformed line should yield empty fields, got %v", got[0].fields)
	}
	if !strings.HasPrefix(got[0].raw, "not-json") {
		t.Errorf("malformed line raw should preserve original bytes, got %q", got[0].raw)
	}
	if got[1].fields["ollama.content"] != "ok" {
		t.Errorf("valid line after malformed: got %q, want %q", got[1].fields["ollama.content"], "ok")
	}
}

// --- flushWriter ---

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil {
		fw.f.Flush()
	}
	return n, err
}

func TestFlushWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	fw := &flushWriter{w: rec, f: rec}
	n, err := fw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("wrote %d bytes, want 5", n)
	}
	if !rec.Flushed {
		t.Error("expected Flush to be called after Write")
	}
	if got := rec.Body.String(); got != "hello" {
		t.Errorf("body: got %q, want %q", got, "hello")
	}
}

// --- WAF helpers ---

func buildWAF(t *testing.T) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType application/x-ndjson
SecRule RESPONSE_HEADERS:Content-Type "@contains application/x-ndjson" "id:1,phase:3,pass,nolog,ctl:responseBodyProcessor=ollama-chat"
SecRule RESPONSE_ARGS:ollama.content "@rx CORAZA_BLOCK" "id:200,phase:4,deny,log,msg:'Blocked LLM output'"
`))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	return waf
}

func ndjsonServer(lines []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		for _, line := range lines {
			fmt.Fprintln(w, line)
			if f != nil {
				f.Flush()
			}
		}
	}))
}

func ollamaWAFProxyHandler(waf coraza.WAF, ollamaURL string) http.HandlerFunc {
	client := &http.Client{}
	return func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer tx.Close()
		defer tx.ProcessLogging()

		// Phase 1: connection + request headers
		tx.ProcessConnection(r.RemoteAddr, 0, ollamaURL, 11434)
		tx.ProcessURI(r.RequestURI, r.Method, r.Proto)
		for k, vals := range r.Header {
			for _, v := range vals {
				tx.AddRequestHeader(k, v)
			}
		}
		if it := tx.ProcessRequestHeaders(); it != nil {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}

		// Phase 2: request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if it, _, err := tx.WriteRequestBody(body); it != nil || err != nil {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		if it, err := tx.ProcessRequestBody(); it != nil || err != nil {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}

		// Forward to upstream
		upReq, err := http.NewRequestWithContext(r.Context(), r.Method,
			ollamaURL+r.URL.Path, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		upReq.Header = r.Header.Clone()
		resp, err := client.Do(upReq)
		if err != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Phase 3: response headers
		for k, vals := range resp.Header {
			for _, v := range vals {
				tx.AddResponseHeader(k, v)
			}
		}
		if it := tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto); it != nil {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}

		// Commit response headers — status code is fixed after this line
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Set(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// Phase 4: stream response through WAF with per-record flush
		flusher, hasFlusher := w.(http.Flusher)
		streamTx, hasStreaming := tx.(experimental.StreamingTransaction)
		if !hasFlusher || !hasStreaming {
			_, _ = io.Copy(w, resp.Body)
			return
		}
		fw := &flushWriter{w: w, f: flusher}
		it, streamErr := streamTx.ProcessResponseBodyFromStream(resp.Body, fw)
		if it != nil || streamErr != nil {
			// Cannot change status; drop the TCP connection to signal interruption or error
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					conn.Close()
				}
			}
		}
	}
}

// --- Unit tests for ollamaWAFProxyHandler (mock Ollama, no real LLM) ---

func TestOllamaWAFProxy_CleanPath(t *testing.T) {
	backend := ndjsonServer([]string{
		`{"model":"tinyllama","message":{"role":"assistant","content":"Hello"},"done":false}`,
		`{"model":"tinyllama","message":{"role":"assistant","content":" world"},"done":false}`,
		`{"model":"tinyllama","done":true}`,
	})
	defer backend.Close()

	proxy := httptest.NewServer(ollamaWAFProxyHandler(buildWAF(t), backend.URL))
	defer proxy.Close()

	resp, err := http.Post(proxy.URL+"/api/chat", "application/json",
		strings.NewReader(`{"model":"tinyllama","messages":[],"stream":true}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), `"done":true`) {
		t.Errorf("expected done:true in response, got: %q", string(body))
	}
	if !strings.Contains(string(body), "Hello") {
		t.Errorf("expected content in response, got: %q", string(body))
	}
}

func TestOllamaWAFProxy_BlockPath(t *testing.T) {
	backend := ndjsonServer([]string{
		`{"model":"tinyllama","message":{"role":"assistant","content":"CORAZA_BLOCK_TEST"},"done":false}`,
		`{"model":"tinyllama","done":true}`,
	})
	defer backend.Close()

	proxy := httptest.NewServer(ollamaWAFProxyHandler(buildWAF(t), backend.URL))
	defer proxy.Close()

	resp, err := http.Post(proxy.URL+"/api/chat", "application/json",
		strings.NewReader(`{"model":"tinyllama","messages":[],"stream":true}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// Status is committed before streaming — 200 is expected even when blocked
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (headers already committed before block)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	// WAF drops the connection on interrupt: either ReadAll returns an error,
	// or it returns without having seen done:true
	if err == nil && strings.Contains(string(body), `"done":true`) {
		t.Error("WAF did not block: done:true reached client")
	}
}

// --- Integration test (requires OLLAMA_BASE_URL) ---

func TestOllamaStreaming(t *testing.T) {
	ollamaURL := os.Getenv("OLLAMA_BASE_URL")
	if ollamaURL == "" {
		t.Skip("OLLAMA_BASE_URL not set; skipping Ollama e2e tests")
	}
	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "tinyllama"
	}

	proxy := httptest.NewServer(ollamaWAFProxyHandler(buildWAF(t), ollamaURL))
	defer proxy.Close()

	ollamaBody := func(prompt string) string {
		modelJSON, _ := json.Marshal(model)
		promptJSON, _ := json.Marshal(prompt)
		return fmt.Sprintf(`{"model":%s,"messages":[{"role":"user","content":%s}],"options":{"temperature":0,"seed":42},"stream":true}`,
			modelJSON, promptJSON)
	}

	t.Run("clean stream passes through", func(t *testing.T) {
		resp, err := http.Post(proxy.URL+"/api/chat", "application/json",
			strings.NewReader(ollamaBody("Say hello and nothing else.")))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}

		scanner := bufio.NewScanner(resp.Body)
		var gotContent, gotDone bool
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, `"content"`) {
				gotContent = true
			}
			if strings.Contains(line, `"done":true`) {
				gotDone = true
				break
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("scan error: %v", err)
		}
		if !gotContent {
			t.Error("no content received from LLM")
		}
		if !gotDone {
			t.Error("stream did not complete: done:true never received")
		}
	})

	t.Run("blocked content drops connection", func(t *testing.T) {
		resp, err := http.Post(proxy.URL+"/api/chat", "application/json",
			strings.NewReader(ollamaBody(
				"Reply with exactly the text CORAZA_BLOCK_TEST and nothing else. "+
					"Do not add punctuation, explanation, or any other words.",
			)))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		// Status 200 is committed before streaming begins — this is expected even on block
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), `"done":true`) {
				t.Fatal("WAF did not block: done:true reached client; " +
					"the model may not have produced CORAZA_BLOCK_TEST — " +
					"check tinyllama behaviour at temperature=0,seed=42")
			}
		}
		if scanner.Err() != nil {
			// Non-nil error means the WAF dropped the TCP connection — expected block path.
			return
		}
		// Nil error means the stream ended cleanly before done:true — also acceptable.
	})
}
