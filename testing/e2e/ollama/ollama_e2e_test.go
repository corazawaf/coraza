//go:build !tinygo

package ollamae2e

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"strings"
	"testing"

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
