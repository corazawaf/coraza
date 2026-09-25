// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func multipartProcessor(t *testing.T) plugintypes.BodyProcessor {
	t.Helper()
	mp, err := bodyprocessors.GetBodyProcessor("multipart")
	if err != nil {
		t.Fatal(err)
	}
	return mp
}

func TestProcessRequestFailsDueToIncorrectMimeType(t *testing.T) {
	mp := multipartProcessor(t)

	expectedError := "not a multipart body"

	if err := mp.ProcessRequest(strings.NewReader(""), corazawaf.NewTransactionVariables(), plugintypes.BodyProcessorOptions{
		Mime: "application/json",
	}); err == nil || err.Error() != expectedError {
		t.Fatal("expected error")
	}
}

func TestMultipartPayload(t *testing.T) {
	payload := strings.TrimSpace(`
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text default
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="a.txt"
Content-Type: text/plain

Content of a.txt.

-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file2"; filename="a.html"
Content-Type: text/html

<!DOCTYPE html><title>Content of a.html.</title>

-----------------------------9051914041544843365972754266--
`)

	mp := multipartProcessor(t)

	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=---------------------------9051914041544843365972754266",
	}); err != nil {
		t.Fatal(err)
	}
	// first we validate we got the headers
	headers := v.MultipartPartHeaders()
	header1 := "Content-Disposition: form-data; name=\"file2\"; filename=\"a.html\""
	header2 := "Content-Type: text/html"
	if h := headers.Get("file2"); len(h) == 0 {
		t.Fatal("expected headers for file2")
	} else {
		if len(h) != 2 {
			t.Fatal("expected 2 headers for file2")
		}
		if (h[0] != header1 && h[0] != header2) || (h[1] != header1 && h[1] != header2) {
			t.Fatalf("Got invalid multipart headers")
		}
	}
}

func TestInvalidMultipartCT(t *testing.T) {
	payload := strings.TrimSpace(`
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text default
-----------------------------9051914041544843365972754266
`)
	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=---------------------------9051914041544843365972754266; a=1; a=2",
	}); err == nil {
		t.Error("multipart processor should fail for invalid content-type")
	}
}

func TestMultipartErrorSetsMultipartStrictError(t *testing.T) {
	payload := "--a\n" +
		"\x0eContent-Disposition\x0e: form-data; name=\"file\";filename=\"1.jsp\"\n" +
		"Content-Disposition: form-data; name=\"post\";\n" +
		"\n" +
		"<%out.print(123)%>\n" +
		"--a--"
	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	strictError := v.MultipartStrictError()
	if strictError.Get() != "" {
		t.Errorf("expected strict error to be empty")
	}
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=a",
	}); err != nil {
		strictError = v.MultipartStrictError()
		if strictError.Get() != "1" {
			t.Error("expected strict error")
		}
	}
}

// TestMultipartCRLFAndLF tests a multipart payload with mixed CRLF and LF line endings.
// Golang mime/multipart reader uses the first line ending after the boundary and wants to keep it consistent.
// It will fail with NextPart: EOF if the line endings are mixed.
func TestMultipartCRLFAndLF(t *testing.T) {
	payload := "----------------------------756b6d74fa1a8ee2" +
		"Content-Disposition: form-data; name=\"name\"" +
		"" +
		"test" +
		"----------------------------756b6d74fa1a8ee2" +
		"Content-Disposition: form-data; name=\"filedata\"; filename=\"small_text_file.txt\"" +
		"Content-Type: text/plain" +
		"" +
		"This is a very small test file.." +
		"----------------------------756b6d74fa1a8ee2" +
		"Content-Disposition: form-data; name=\"filedata\"; filename=\"small_text_file.txt\"\r" +
		"Content-Type: text/plain\r" +
		"\r" +
		"This is another very small test file..\r" +
		"----------------------------756b6d74fa1a8ee2--\r"

	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=756b6d74fa1a8ee2",
	}); err != nil {
		strictError := v.MultipartStrictError()
		if strictError.Get() != "1" {
			t.Error("expected strict error")
		}
		if !strings.Contains(err.Error(), "multipart: NextPart: EOF") {
			t.Fatal(err)
		}
	}
}

// TestMultipartInvalidHeaderFolding tests a multipart payload where headers are folded badly (RFC 2047).
// It will fail with NextPart: EOF.
func TestMultipartInvalidHeaderFolding(t *testing.T) {
	payload := "-------------------------------69343412719991675451336310646\n" +
		"Content-Disposition: form-data;\n" +
		" name=\"a\"\n" +
		"\n" +
		"\n" +
		"-------------------------------69343412719991675451336310646\n" +
		"Content-Disposition: form-data;\n" +
		"    name=\"b\"\n" +
		"\n" +
		"2\n" +
		"-------------------------------69343412719991675451336310646--\n"
	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=69343412719991675451336310646",
	}); err != nil {
		strictError := v.MultipartStrictError()
		if strictError.Get() != "1" {
			t.Error("expected strict error")
		}
		if !strings.Contains(err.Error(), "multipart: NextPart: EOF") {
			t.Fatal(err)
		}
	}
}

// TestMultipartUnmatchedBoundary tests a multipart payload where there is an unmatched boundary.
func TestMultipartUnmatchedBoundary(t *testing.T) {
	payload := "--------------------------756b6d74fa1a8ee2\n" +
		"Content-Disposition: form-data; name=\"name\"\n" +
		"\n" +
		"test\n" +
		"--------------------------756b6d74fa1a8ee2\n" +
		"Content-Disposition: form-data; name=\"filedata\"; filename=\"small_text_file.txt\"\n" +
		"Content-Type: text/plain\n" +
		"\n" +
		"This is a very small test file..\n" +
		"--------------------------756b6d74fa1a8ee2\n" +
		"Content-Disposition: form-data; name=\"filedata\"; filename=\"small_text_file.txt\"\n" +
		"Content-Type: text/plain\n" +
		"\n" +
		"This is another very small test file..\n" +
		"\n"
	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=756b6d74fa1a8ee2",
	}); err != nil {
		strictError := v.MultipartStrictError()
		if strictError.Get() != "1" {
			t.Error("expected strict error")
		}
	}
}

func TestIncompleteMultipartPayload(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name: "inMiddleOfBoundary",
			input: `
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text default
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="a.txt"
Content-Type: text/plain

Content of a.txt.

-----------------------------905191404154484336
`,
		},
		{
			name: "inMiddleOfHeader",
			input: `
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text default
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="a.txt"
Content-Type: text/plain

Content of a.txt.

-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="fil`,
		},
		{
			name: "inMiddleOfContent",
			input: `
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text default
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="a.txt"
Content-Type: text/plain

Content of a.txt.

-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file2"; filename="a.html"
Content-Type: text/html

<!DOCTYPE html><title>Content of `,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := strings.TrimSpace(tc.input)

			mp := multipartProcessor(t)

			v := corazawaf.NewTransactionVariables()
			if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
				Mime: "multipart/form-data; boundary=---------------------------9051914041544843365972754266",
			}); err != nil {
				t.Fatal(err)
			}
			// first we validate we got the headers
			headers := v.MultipartPartHeaders()
			header1 := "Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\""
			header2 := "Content-Type: text/plain"
			if h := headers.Get("file1"); len(h) == 0 {
				t.Fatal("expected headers for file1")
			} else {
				if len(h) != 2 {
					t.Fatal("expected 2 headers for file1")
				}
				if (h[0] != header1 && h[0] != header2) || (h[1] != header1 && h[1] != header2) {
					t.Fatalf("Got invalid multipart headers")
				}
			}

			// Verify form field data was correctly processed before the incomplete part
			argsPost := v.ArgsPost()
			if textValues := argsPost.Get("text"); len(textValues) == 0 {
				t.Fatal("expected ArgsPost to contain 'text' field")
			} else if textValues[0] != "text default" {
				t.Fatalf("expected ArgsPost 'text' to be 'text default', got %q", textValues[0])
			}
		})
	}
}

func TestIncompleteMultipartPayloadInFormField(t *testing.T) {
	payload := strings.TrimSpace(`
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text defa`)

	mp := multipartProcessor(t)

	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=---------------------------9051914041544843365972754266",
	}); err != nil {
		t.Fatal(err)
	}

	// Verify the partial form field data was processed
	argsPost := v.ArgsPost()
	if textValues := argsPost.Get("text"); len(textValues) == 0 {
		t.Fatal("expected ArgsPost to contain 'text' field")
	} else if textValues[0] != "text defa" {
		t.Fatalf("expected ArgsPost 'text' to be 'text defa', got %q", textValues[0])
	}
}

// TestMultipartXMLParts covers the MultipartXMLParts option: which file parts get
// tokenized, what lands in the XML collection, and that the upload variables and
// part sizes are unaffected either way.
func TestMultipartXMLParts(t *testing.T) {
	const boundary = "----boundary"

	// part builds one multipart part. An empty filename makes it a form field.
	part := func(name, filename, contentType, body string) string {
		disposition := fmt.Sprintf("Content-Disposition: form-data; name=%q", name)
		if filename != "" {
			disposition += fmt.Sprintf("; filename=%q", filename)
		}
		s := "--" + boundary + "\r\n" + disposition + "\r\n"
		if contentType != "" {
			s += "Content-Type: " + contentType + "\r\n"
		}
		return s + "\r\n" + body + "\r\n"
	}

	tests := []struct {
		name string
		// enabled is the MultipartXMLParts option under test.
		enabled bool
		parts   []string
		// wantContents and wantAttrs are the expected XML:/* and XML://@* values.
		wantContents []string
		wantAttrs    []string
		// wantFiles is the expected FILES value, asserting the upload variables
		// keep working alongside XML extraction.
		wantFiles []string
		// wantSize, when non-empty, is the expected FILES_SIZES entry for
		// wantSizeOf, asserting the tee'd copy still counts every byte.
		wantSizeOf, wantSize string
	}{
		{
			name:      "disabled leaves the XML collection empty",
			enabled:   false,
			parts:     []string{part("f", "p.xml", "application/xml", `<?xml version="1.0"?><r>payload</r>`)},
			wantFiles: []string{"p.xml"},
		},
		{
			name:         "xml media type on the part",
			enabled:      true,
			parts:        []string{part("f", "p", "application/xml", `<r>payload</r>`)},
			wantContents: []string{"payload"},
			wantFiles:    []string{"p"},
		},
		{
			name:         "svg media type on the part",
			enabled:      true,
			parts:        []string{part("f", "p", "image/svg+xml", `<svg><desc>payload</desc></svg>`)},
			wantContents: []string{"payload"},
			wantFiles:    []string{"p"},
		},
		{
			name:    "xml declaration sniffed despite an octet-stream media type",
			enabled: true,
			// This is what curl -F sends for a file it cannot type: the
			// declaration is the only usable hint.
			parts:        []string{part("f", "p", "application/octet-stream", `<?xml version="1.0"?><r>payload</r>`)},
			wantContents: []string{"payload"},
			wantFiles:    []string{"p"},
		},
		{
			name:         "filename extension used when neither media type nor declaration help",
			enabled:      true,
			parts:        []string{part("f", "p.SVG", "application/octet-stream", `<svg><desc>payload</desc></svg>`)},
			wantContents: []string{"payload"},
			wantFiles:    []string{"p.SVG"},
		},
		{
			name:         "declaration behind a BOM and leading whitespace",
			enabled:      true,
			parts:        []string{part("f", "p", "application/octet-stream", "\xEF\xBB\xBF\n  "+`<?xml version="1.0"?><r>payload</r>`)},
			wantContents: []string{"payload"},
			wantFiles:    []string{"p"},
		},
		{
			name:      "non-xml file part is not parsed",
			enabled:   true,
			parts:     []string{part("f", "p.txt", "text/plain", "just a log line")},
			wantFiles: []string{"p.txt"},
		},
		{
			name:    "entity-encoded payload is decoded by the tokenizer",
			enabled: true,
			parts:   []string{part("f", "p.xml", "application/xml", `<r>&lt;script&gt;alert(1)&lt;/script&gt;</r>`)},
			// The point of the feature: the wire bytes are entity-encoded, the
			// value exposed to rules is not.
			wantContents: []string{"<script>alert(1)</script>"},
			wantFiles:    []string{"p.xml"},
		},
		{
			name:      "attribute values land in XML://@*",
			enabled:   true,
			parts:     []string{part("f", "p.xml", "application/xml", `<r v="&lt;script&gt;alert(1)&lt;/script&gt;"/>`)},
			wantAttrs: []string{"<script>alert(1)</script>"},
			wantFiles: []string{"p.xml"},
		},
		{
			name:    "values of several xml parts are merged, not overwritten",
			enabled: true,
			parts: []string{
				part("a", "a.xml", "application/xml", `<r v="attr-a">content-a</r>`),
				part("b", "b.xml", "application/xml", `<r v="attr-b">content-b</r>`),
			},
			wantContents: []string{"content-a", "content-b"},
			wantAttrs:    []string{"attr-a", "attr-b"},
			wantFiles:    []string{"a.xml", "b.xml"},
		},
		{
			name:    "a part that fails to parse is skipped, not fatal",
			enabled: true,
			parts: []string{
				part("bad", "bad.xml", "application/xml", `<r><unclosed "</r>`),
				part("good", "good.xml", "application/xml", `<r>payload</r>`),
			},
			wantContents: []string{"payload"},
			wantFiles:    []string{"bad.xml", "good.xml"},
		},
		{
			name:    "form fields are untouched by the option",
			enabled: true,
			parts: []string{
				part("text", "", "", `<?xml version="1.0"?><r>not a file</r>`),
				part("f", "p.xml", "application/xml", `<r>payload</r>`),
			},
			wantContents: []string{"payload"},
			wantFiles:    []string{"p.xml"},
		},
		{
			// The parsed path copies through an io.TeeReader rather than
			// io.Copy, so the byte count has to be asserted explicitly. The
			// BOM and the bytes after a parse error must be counted too.
			name:         "a parsed part is counted whole",
			enabled:      true,
			parts:        []string{part("f", "p.xml", "application/xml", "\xEF\xBB\xBF"+`<r>payload</r>`)},
			wantContents: []string{"payload"},
			wantFiles:    []string{"p.xml"},
			wantSizeOf:   "p.xml",
			wantSize:     "17", // 3 BOM bytes + len(`<r>payload</r>`)
		},
		{
			name:       "an unparsed part is counted the same way",
			enabled:    false,
			parts:      []string{part("f", "p.xml", "application/xml", "\xEF\xBB\xBF"+`<r>payload</r>`)},
			wantFiles:  []string{"p.xml"},
			wantSizeOf: "p.xml",
			wantSize:   "17",
		},
		{
			name:         "a part is counted whole even when parsing stops early",
			enabled:      true,
			parts:        []string{part("f", "p.xml", "application/xml", `<r><unclosed "</r>`+strings.Repeat("z", 32))},
			wantContents: nil,
			wantFiles:    []string{"p.xml"},
			wantSizeOf:   "p.xml",
			wantSize:     "50", // len(`<r><unclosed "</r>`) is 18, plus 32
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := multipartProcessor(t)
			v := corazawaf.NewTransactionVariables()
			payload := strings.Join(tt.parts, "") + "--" + boundary + "--\r\n"

			if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
				Mime:              "multipart/form-data; boundary=" + boundary,
				StoragePath:       t.TempDir(),
				MultipartXMLParts: tt.enabled,
			}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			assertValues(t, "XML:/*", v.RequestXML().Get("/*"), tt.wantContents)
			assertValues(t, "XML://@*", v.RequestXML().Get("//@*"), tt.wantAttrs)
			assertValues(t, "FILES", v.Files().Get(""), tt.wantFiles)

			if tt.wantSizeOf != "" {
				if got := v.FilesSizes().Get(tt.wantSizeOf); len(got) != 1 || got[0] != tt.wantSize {
					t.Errorf("FILES_SIZES[%s] = %v, want [%s]", tt.wantSizeOf, got, tt.wantSize)
				}
			}
		})
	}
}

func assertValues(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %q, want %q", name, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s = %q, want %q", name, got, want)
			return
		}
	}
}
