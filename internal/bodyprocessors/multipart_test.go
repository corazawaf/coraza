// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
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
				t.Fatal("expected headers for file2")
			} else {
				if len(h) != 2 {
					t.Fatal("expected 2 headers for file2")
				}
				if (h[0] != header1 && h[0] != header2) || (h[1] != header1 && h[1] != header2) {
					t.Fatalf("Got invalid multipart headers")
				}
			}
		})
	}
}
