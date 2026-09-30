// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
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

func TestMultipartFilenameStar(t *testing.T) {
	tests := []struct {
		name         string
		fields       string
		wantFilename string
		// wantAltFilename is the plain "filename" value expected alongside
		// wantFilename in MULTIPART_FILENAME/FILES when a well-formed
		// "filename*" picked a different value -- both readings are kept so a
		// rule catches whichever one a given backend actually resolves.
		wantAltFilename string
		// wantExtended is whether a filename* parameter was present at all --
		// when true, MULTIPART_FILENAME_CHARSET/LANGUAGE are expected to be
		// present (possibly empty, e.g. an omitted language), not absent.
		wantExtended bool
		wantCharset  string
		wantLanguage string
		wantIsFile   bool
		// wantStrictError is whether the part should raise
		// MULTIPART_STRICT_ERROR, wantDuplicate whether it should raise
		// MULTIPART_DUPLICATE_PART_HEADER, and wantInvalidQuoting whether it
		// should raise MULTIPART_INVALID_QUOTING.
		wantStrictError    bool
		wantDuplicate      bool
		wantInvalidQuoting bool
	}{
		{
			name:         "plain filename only",
			fields:       `filename="safe.jpg"`,
			wantFilename: "safe.jpg",
			wantIsFile:   true,
		},
		{
			name:            "filename* takes precedence over a decoy plain filename, both kept",
			fields:          `filename="safe.jpg"; filename*=UTF-8''shell.php`,
			wantFilename:    "shell.php",
			wantAltFilename: "safe.jpg",
			wantExtended:    true,
			wantCharset:     "UTF-8",
			wantIsFile:      true,
		},
		{
			// GHSA-3wr7-993q-jrff: mime.ParseMediaType only decodes filename*
			// for us-ascii/utf-8 charsets, silently falling back to the decoy
			// plain filename for any other charset -- including iso-8859-1,
			// which RFC 5987 explicitly permits.
			name:            "filename* under a non-utf-8 charset still overrides the decoy filename, both kept",
			fields:          `filename="safe.jpg"; filename*=iso-8859-1''shell.php`,
			wantFilename:    "shell.php",
			wantAltFilename: "safe.jpg",
			wantExtended:    true,
			wantCharset:     "iso-8859-1",
			wantIsFile:      true,
		},
		{
			// jptosso's review on this PR: making filename* unconditionally
			// authoritative doesn't close the differential, it relocates it --
			// swap which field carries the real name and the bypass reopens in
			// the other direction. Verified against Go's own multipart.Part
			// (which resolves "safe.jpg" here, the opposite of the case
			// above). Both readings are now kept so a rule catches either one,
			// instead of the engine picking a side.
			name:            "fields swapped: real name in plain filename, decoy in filename*",
			fields:          `filename="shell.php"; filename*=iso-8859-1''safe.jpg`,
			wantFilename:    "safe.jpg",
			wantAltFilename: "shell.php",
			wantExtended:    true,
			wantCharset:     "iso-8859-1",
			wantIsFile:      true,
		},
		{
			// Without the fix, a non-utf-8 filename* with no plain filename
			// fallback wasn't recognized as a file at all.
			name:         "filename* alone under a non-utf-8 charset is still recognized as a file",
			fields:       `filename*=iso-8859-1''shell.php`,
			wantFilename: "shell.php",
			wantExtended: true,
			wantCharset:  "iso-8859-1",
			wantIsFile:   true,
		},
		{
			name:         "language segment is captured",
			fields:       `filename*=UTF-8'en'shell.php`,
			wantFilename: "shell.php",
			wantExtended: true,
			wantCharset:  "UTF-8",
			wantLanguage: "en",
			wantIsFile:   true,
		},
		{
			name:         "percent-encoded value is decoded",
			fields:       `filename*=UTF-8''na%C3%AFve.txt`,
			wantFilename: "naïve.txt",
			wantExtended: true,
			wantCharset:  "UTF-8",
			wantIsFile:   true,
		},
		{
			name:            "malformed filename* falls back to no filename but is still flagged",
			fields:          `filename*=noquoteshere`,
			wantIsFile:      false,
			wantStrictError: true,
		},
		{
			name:            "filename* missing its closing language quote is flagged",
			fields:          `filename*=UTF-8'shell.php`,
			wantIsFile:      false,
			wantStrictError: true,
		},
		{
			// An empty charset is accepted and exposed as-is rather than
			// rejected: Coraza does not decide which charsets are legitimate,
			// it hands the declared value to the rule writer.
			name:         "empty charset is exposed rather than rejected",
			fields:       `filename*=''shell.php`,
			wantFilename: "shell.php",
			wantExtended: true,
			wantIsFile:   true,
		},
		{
			name:            "a Content-Disposition that cannot be parsed at all is flagged",
			fields:          `filename*=UTF-8''sh"ell.php`,
			wantIsFile:      false,
			wantStrictError: true,
		},
		{
			name:            "a repeated filename parameter is flagged as a duplicate",
			fields:          `filename="safe.jpg"; filename="shell.php"`,
			wantIsFile:      false,
			wantStrictError: true,
			wantDuplicate:   true,
		},
		{
			name:            "a repeated filename* parameter is flagged as a duplicate",
			fields:          `filename*=UTF-8''safe.jpg; filename*=UTF-8''shell.php`,
			wantIsFile:      false,
			wantStrictError: true,
			wantDuplicate:   true,
		},
		{
			// An unresolvable "%" escape must not be silently absorbed: a
			// backend decoding the same escape differently (or rejecting it,
			// as ModSecurity's GHSA-5pww-8rfg-9crf fix does) would disagree
			// with Coraza on the filename without this flag.
			name:            "an invalid percent-escape in filename* is kept as-is but flagged",
			fields:          `filename="shell.php"; filename*=UTF-8''safe.jpg%ZZ`,
			wantFilename:    "safe.jpg%ZZ",
			wantAltFilename: "shell.php",
			wantExtended:    true,
			wantCharset:     "UTF-8",
			wantIsFile:      true,
			wantStrictError: true,
		},
		{
			// RFC 5987 does not permit ext-value to be a quoted-string, but a
			// general Content-Disposition parser -- Go's mime.ParseMediaType
			// included -- accepts a quoted-string for any parameter. Without
			// unwrapping it, the literal quotes leak into the filename and
			// charset, breaking anchored rules while the backend resolves a
			// clean "shell.php".
			name:               "a quoted filename* value is unwrapped like a backend would, but flagged",
			fields:             `filename*="UTF-8''shell.php"`,
			wantFilename:       "shell.php",
			wantExtended:       true,
			wantCharset:        "UTF-8",
			wantIsFile:         true,
			wantStrictError:    true,
			wantInvalidQuoting: true,
		},
		{
			// M4tteoP's review: filename*=utf-8'' decodes to the empty string,
			// which must not misclassify the part as a field -- PHP, Go
			// mime/multipart, python-multipart and formidable all still resolve
			// it as a file, reading the plain "filename" instead.
			name:         "an empty filename* still recognizes the part as a file",
			fields:       `filename="shell.php"; filename*=utf-8''`,
			wantFilename: "shell.php",
			wantExtended: true,
			wantCharset:  "utf-8",
			wantIsFile:   true,
		},
		{
			// M4tteoP's review: mime.ParseMediaType partially handles a single
			// RFC 2231 continuation piece itself, and in doing so blanks
			// params["filename"] when the continuation's charset isn't
			// utf-8/us-ascii -- silently losing the plain filename ("safe.jpg")
			// entirely rather than just failing to decode the continuation.
			name:            "an RFC 2231 continuation (filename*0*) does not silently drop the plain filename",
			fields:          `filename="safe.jpg"; filename*0*=iso-8859-1''shell.php`,
			wantFilename:    "safe.jpg",
			wantIsFile:      true,
			wantStrictError: true,
		},
		{
			// M4tteoP's review: mime.ParseMediaType resolves a plain (non
			// extended) continuation piece as if it were the "filename" value
			// itself, silently overwriting the real plain filename
			// ("shell.php") with the continuation's ("safe.jpg"). Both
			// readings are kept -- PHP, python-multipart and formidable
			// resolve the plain filename, but a Go mime/multipart backend
			// resolves the continuation's, same as Coraza did before this
			// fix even existed.
			name:            "an RFC 2231 continuation (filename*0) keeps both readings",
			fields:          `filename="shell.php"; filename*0="safe.jpg"`,
			wantFilename:    "shell.php",
			wantAltFilename: "safe.jpg",
			wantIsFile:      true,
			wantStrictError: true,
		},
		{
			// M4tteoP's follow-up review: the first fix for RFC 2231
			// continuations discarded mime.ParseMediaType's own reading
			// entirely, which is reliable for a utf-8/us-ascii continuation
			// piece (unlike the non-utf-8 case above) -- so it silently lost
			// "shell.php", a value Coraza used to surface before this fix
			// existed, and that a Go mime/multipart backend still resolves.
			name:            "an RFC 2231 continuation (filename*0) with a plain-filename decoy keeps both readings",
			fields:          `filename="safe.jpg"; filename*0="shell.php"`,
			wantFilename:    "safe.jpg",
			wantAltFilename: "shell.php",
			wantIsFile:      true,
			wantStrictError: true,
		},
		{
			// Same follow-up, for the extended ("*0*") continuation form: a
			// utf-8 charset decodes reliably via mime.ParseMediaType's own
			// continuation handling, so "shell.php" must not be dropped.
			name:            "an RFC 2231 continuation (filename*0*) with a plain-filename decoy keeps both readings",
			fields:          `filename="safe.jpg"; filename*0*=utf-8''shell.php`,
			wantFilename:    "safe.jpg",
			wantAltFilename: "shell.php",
			wantIsFile:      true,
			wantStrictError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := "--X\r\n" +
				"Content-Disposition: form-data; name=\"upload\"; " + tc.fields + "\r\n\r\n" +
				"file content" +
				"\r\n--X--\r\n"

			mp := multipartProcessor(t)
			v := corazawaf.NewTransactionVariables()
			if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
				Mime: "multipart/form-data; boundary=X",
			}); err != nil {
				t.Fatal(err)
			}

			got := v.MultipartFilename().Get("upload")
			var want []string
			if tc.wantFilename != "" {
				want = append(want, tc.wantFilename)
				if tc.wantAltFilename != "" {
					want = append(want, tc.wantAltFilename)
				}
			}
			if !slices.Equal(got, want) {
				t.Errorf("MULTIPART_FILENAME:upload = %v, want %v", got, want)
			}

			if got := v.MultipartFilenameCharset().Get("upload"); !tc.wantExtended {
				if len(got) != 0 {
					t.Errorf("MULTIPART_FILENAME_CHARSET:upload = %v, want empty", got)
				}
			} else if len(got) != 1 || got[0] != tc.wantCharset {
				t.Errorf("MULTIPART_FILENAME_CHARSET:upload = %v, want [%q]", got, tc.wantCharset)
			}

			if got := v.MultipartFilenameLanguage().Get("upload"); !tc.wantExtended {
				if len(got) != 0 {
					t.Errorf("MULTIPART_FILENAME_LANGUAGE:upload = %v, want empty", got)
				}
			} else if len(got) != 1 || got[0] != tc.wantLanguage {
				t.Errorf("MULTIPART_FILENAME_LANGUAGE:upload = %v, want [%q]", got, tc.wantLanguage)
			}

			var gotFiles []string
			for _, m := range v.Files().FindAll() {
				gotFiles = append(gotFiles, m.Value())
			}
			isFile := len(gotFiles) != 0
			if isFile != tc.wantIsFile {
				t.Errorf("recognized as file = %v, want %v (FILES=%v)", isFile, tc.wantIsFile, gotFiles)
			}
			if isFile && !slices.Equal(gotFiles, want) {
				t.Errorf("FILES = %v, want %v", gotFiles, want)
			}

			wantStrict := ""
			if tc.wantStrictError {
				wantStrict = "1"
			}
			if got := v.MultipartStrictError().Get(); got != wantStrict {
				t.Errorf("MULTIPART_STRICT_ERROR = %q, want %q", got, wantStrict)
			}

			wantDuplicate := ""
			if tc.wantDuplicate {
				wantDuplicate = "1"
			}
			if got := v.MultipartDuplicatePartHeader().Get(); got != wantDuplicate {
				t.Errorf("MULTIPART_DUPLICATE_PART_HEADER = %q, want %q", got, wantDuplicate)
			}

			wantInvalidQuoting := ""
			if tc.wantInvalidQuoting {
				wantInvalidQuoting = "1"
			}
			if got := v.MultipartInvalidQuoting().Get(); got != wantInvalidQuoting {
				t.Errorf("MULTIPART_INVALID_QUOTING = %q, want %q", got, wantInvalidQuoting)
			}
		})
	}
}

// TestMultipartDuplicatePartHeader covers a part repeating a whole header,
// which the single-Content-Disposition payload above cannot express.
func TestMultipartDuplicatePartHeader(t *testing.T) {
	tests := []struct {
		name          string
		headers       string
		wantDuplicate bool
	}{
		{
			name:    "distinct headers",
			headers: "Content-Disposition: form-data; name=\"upload\"; filename=\"safe.jpg\"\r\n" + "Content-Type: image/jpeg\r\n",
		},
		{
			name: "repeated Content-Disposition",
			headers: "Content-Disposition: form-data; name=\"upload\"; filename*=UTF-8''shell.php\r\n" +
				"Content-Disposition: form-data; name=\"upload\"; filename=\"safe.jpg\"\r\n",
			wantDuplicate: true,
		},
		{
			name: "repeated Content-Type",
			headers: "Content-Disposition: form-data; name=\"upload\"; filename=\"safe.jpg\"\r\n" +
				"Content-Type: image/jpeg\r\n" + "Content-Type: application/x-php\r\n",
			wantDuplicate: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := "--X\r\n" + tc.headers + "\r\n" + "file content" + "\r\n--X--\r\n"

			mp := multipartProcessor(t)
			v := corazawaf.NewTransactionVariables()
			if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
				Mime: "multipart/form-data; boundary=X",
			}); err != nil {
				t.Fatal(err)
			}

			want := ""
			if tc.wantDuplicate {
				want = "1"
			}
			if got := v.MultipartDuplicatePartHeader().Get(); got != want {
				t.Errorf("MULTIPART_DUPLICATE_PART_HEADER = %q, want %q", got, want)
			}
			if got := v.MultipartStrictError().Get(); got != want {
				t.Errorf("MULTIPART_STRICT_ERROR = %q, want %q", got, want)
			}
		})
	}
}

// TestMultipartFilenameDuplicateName covers two distinct parts sharing one
// "name" (e.g. a multi-file input), which the single-part table above cannot
// express. ModSecurity's GHSA-5pww-8rfg-9crf names the equivalent bug --
// MULTIPART_FILENAME collapsing to the last part's value -- "a second,
// distinct bypass" and fixes it by keeping the variable multi-valued; every
// part's filename here must remain visible to rules regardless of order.
func TestMultipartFilenameDuplicateName(t *testing.T) {
	payload := "--X\r\n" +
		"Content-Disposition: form-data; name=\"upload\"; filename=\"shell.php\"\r\n\r\n" +
		"malicious content" +
		"\r\n--X\r\n" +
		"Content-Disposition: form-data; name=\"upload\"; filename=\"safe.jpg\"\r\n\r\n" +
		"benign content" +
		"\r\n--X--\r\n"

	mp := multipartProcessor(t)
	v := corazawaf.NewTransactionVariables()
	if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
		Mime: "multipart/form-data; boundary=X",
	}); err != nil {
		t.Fatal(err)
	}

	got := v.MultipartFilename().Get("upload")
	want := []string{"shell.php", "safe.jpg"}
	if len(got) != len(want) {
		t.Fatalf("MULTIPART_FILENAME:upload = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("MULTIPART_FILENAME:upload[%d] = %q, want %q", i, got[i], w)
		}
	}

	// FILES already retained both filenames before this fix; MULTIPART_FILENAME
	// must now agree with it instead of only keeping the last one.
	files := v.Files().FindAll()
	if len(files) != len(want) {
		t.Fatalf("FILES = %v, want %d entries", files, len(want))
	}
}

func BenchmarkMultipartFilenameStar(b *testing.B) {
	tests := []struct {
		name   string
		fields string
	}{
		{"plain filename", `filename="safe.jpg"`},
		{"filename* utf-8", `filename="safe.jpg"; filename*=UTF-8''shell.php`},
		{"filename* iso-8859-1", `filename="safe.jpg"; filename*=iso-8859-1''shell.php`},
	}

	for _, tc := range tests {
		payload := "--X\r\n" +
			"Content-Disposition: form-data; name=\"upload\"; " + tc.fields + "\r\n\r\n" +
			"file content" +
			"\r\n--X--\r\n"

		b.Run(tc.name, func(b *testing.B) {
			mp, err := bodyprocessors.GetBodyProcessor("multipart")
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < b.N; i++ {
				v := corazawaf.NewTransactionVariables()
				if err := mp.ProcessRequest(strings.NewReader(payload), v, plugintypes.BodyProcessorOptions{
					Mime: "multipart/form-data; boundary=X",
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
