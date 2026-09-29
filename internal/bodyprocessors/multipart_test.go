// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/environment"
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

// errAfterReader always fails with err once its wrapped reader is exhausted,
// simulating a hard I/O error (as opposed to a clean truncation, which
// surfaces as io.ErrUnexpectedEOF instead).
type errAfterReader struct {
	err error
}

func (e errAfterReader) Read([]byte) (int, error) {
	return 0, e.err
}

// TestMultipartTempFileRecordedOnCopyError ensures a temp file created for a
// file part is still recorded in FILES_TMPNAMES when io.Copy into it fails
// with a hard error, not just on the success path. Otherwise the file is
// leaked: it exists on disk, but transaction close only removes names it
// finds in FILES_TMPNAMES.
func TestMultipartTempFileRecordedOnCopyError(t *testing.T) {
	if !environment.HasAccessToFS {
		t.Skip("skipping test as it requires access to filesystem")
	}
	payload := "--a\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"some file content"
	// No closing boundary: once the valid payload is exhausted, the reader
	// hits a hard error instead of a clean EOF.
	copyErr := errors.New("simulated disk write failure")
	r := io.MultiReader(strings.NewReader(payload), errAfterReader{err: copyErr})

	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(r, v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=a",
	}); err == nil {
		t.Fatal("expected an error from the truncated body")
	}

	names := v.FilesTmpNames().(*collections.Map).Get("")
	if len(names) != 1 {
		t.Fatalf("expected exactly one recorded temp file, got %d", len(names))
	}
	if _, err := os.Stat(names[0]); err != nil {
		t.Fatalf("recorded temp file %q not found on disk: %v", names[0], err)
	}
	t.Cleanup(func() { os.Remove(names[0]) })
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
		name              string
		input             string
		expectStrictError bool
	}{
		{
			name:              "inMiddleOfBoundary",
			expectStrictError: true,
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
			name:              "inMiddleOfHeader",
			expectStrictError: false, // NextPart() returns io.EOF, not io.ErrUnexpectedEOF
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
			name:              "inMiddleOfContent",
			expectStrictError: true,
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

			// Verify MULTIPART_STRICT_ERROR is set for truncated bodies where io.ErrUnexpectedEOF is raised
			strictError := v.MultipartStrictError()
			if tc.expectStrictError && strictError.Get() != "1" {
				t.Error("expected MULTIPART_STRICT_ERROR to be set for incomplete multipart payload")
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

	// Verify MULTIPART_STRICT_ERROR is set for truncated bodies
	strictError := v.MultipartStrictError()
	if strictError.Get() != "1" {
		t.Error("expected MULTIPART_STRICT_ERROR to be set for incomplete multipart payload")
	}

	// Verify the partial form field data was processed
	argsPost := v.ArgsPost()
	if textValues := argsPost.Get("text"); len(textValues) == 0 {
		t.Fatal("expected ArgsPost to contain 'text' field")
	} else if textValues[0] != "text defa" {
		t.Fatalf("expected ArgsPost 'text' to be 'text defa', got %q", textValues[0])
	}
}

// TestMultipartDoesNotAccumulateOpenFileDescriptors asserts a resource-lifetime property (each
// part's temp file is closed as soon as it is copied, not deferred to function return), which
// needs a live open-fd count rather than a parsed-variable assertion, so it can't be a profile
// or a table row.
func TestMultipartDoesNotAccumulateOpenFileDescriptors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc/self/fd to observe live open file descriptors")
	}

	const parts = 200
	boundary := "fdleakboundary"
	var payload strings.Builder
	for i := 0; i < parts; i++ {
		fmt.Fprintf(&payload, "--%s\r\nContent-Disposition: form-data; name=\"f%d\"; filename=\"f%d.txt\"\r\n\r\nX\r\n", boundary, i, i)
	}
	fmt.Fprintf(&payload, "--%s--\r\n", boundary)

	openFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}

	baseline := int64(openFDs())
	var peak int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				n := int64(openFDs())
				for {
					cur := atomic.LoadInt64(&peak)
					if n <= cur || atomic.CompareAndSwapInt64(&peak, cur, n) {
						break
					}
				}
			}
		}
	}()

	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	err := mp.ProcessRequest(strings.NewReader(payload.String()), v, plugintypes.BodyProcessorOptions{
		Mime:        "multipart/form-data; boundary=" + boundary,
		StoragePath: t.TempDir(),
	})
	close(done)
	wg.Wait()

	if err != nil {
		t.Fatal(err)
	}

	if spike := atomic.LoadInt64(&peak) - baseline; spike >= parts/2 {
		t.Fatalf("temp files were not closed as they were processed: baseline=%d peak=%d spike=+%d across %d parts", baseline, atomic.LoadInt64(&peak), spike, parts)
	}
}
