// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/internal/operators"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/internal/transformations"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type testBodyProcessor struct{}

func (*testBodyProcessor) ProcessRequest(reader io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	_, err := io.Copy(io.Discard, reader)
	return err
}

func (*testBodyProcessor) ProcessResponse(reader io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	_, err := io.Copy(io.Discard, reader)
	return err
}

// The declarative engine profiles cannot assert reader consumption and
// multipart file-byte accounting across transaction entry points.
func TestRequestBodyNoFilesLimitStreaming(t *testing.T) {
	newTx := func(limit int64, action types.BodyLimitAction) *Transaction {
		waf := NewWAF()
		waf.RequestBodyAccess = true
		waf.RequestBodyLimit = 1 << 20
		waf.RequestBodyNoFilesLimit = limit
		waf.RequestBodyLimitAction = action
		tx := waf.NewTransaction()
		tx.ProcessURI("/", "POST", "HTTP/1.1")
		return tx
	}

	for _, tc := range []struct {
		name   string
		body   string
		action types.BodyLimitAction
		status int
		stored string
	}{
		{"below", strings.Repeat("x", 15), types.BodyLimitActionReject, 0, strings.Repeat("x", 15)},
		{"equal", strings.Repeat("x", 16), types.BodyLimitActionReject, 0, strings.Repeat("x", 16)},
		{"above", strings.Repeat("x", 17), types.BodyLimitActionReject, 413, strings.Repeat("x", 17)},
		{"partial", strings.Repeat("x", 17), types.BodyLimitActionProcessPartial, 0, strings.Repeat("x", 17)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := newTx(16, tc.action)
			defer tx.Close()
			tx.AddRequestHeader("Content-Type", "application/octet-stream")
			tx.ProcessRequestHeaders()
			interruption, read, err := tx.ReadRequestBodyFrom(strings.NewReader(tc.body))
			if err != nil || read != len(tc.body) {
				t.Fatalf("read=%d err=%v", read, err)
			}
			if (interruption == nil) != (tc.status == 0) {
				t.Fatalf("interruption=%v, want status %d", interruption, tc.status)
			}
			if interruption != nil && interruption.Status != tc.status {
				t.Fatalf("status=%d, want %d", interruption.Status, tc.status)
			}
			reader, err := tx.RequestBodyReader()
			if err != nil {
				t.Fatal(err)
			}
			stored, err := io.ReadAll(reader)
			if err != nil || string(stored) != tc.stored {
				t.Fatalf("stored=%q err=%v", stored, err)
			}
			if tc.status == 413 || tc.name == "partial" {
				if tx.variables.inboundDataError.Get() != "1" || tx.variables.reqbodyError.Get() != "1" {
					t.Fatal("limit error state not set")
				}
			}
		})
	}

	t.Run("multipart unknown-length reader", func(t *testing.T) {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("field", "value"); err != nil {
			t.Fatal(err)
		}
		part, err := writer.CreateFormFile("file", "upload.bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, strings.Repeat("f", 1<<15)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		tx := newTx(512, types.BodyLimitActionReject)
		defer tx.Close()
		tx.AddRequestHeader("Content-Type", writer.FormDataContentType())
		tx.ProcessRequestHeaders()
		interruption, n, err := tx.ReadRequestBodyFrom(iotest.OneByteReader(bytes.NewReader(body.Bytes())))
		if err != nil || interruption != nil || n != body.Len() {
			t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
		}
		if interruption, err := tx.ProcessRequestBody(); err != nil || interruption != nil {
			t.Fatalf("interruption=%v err=%v", interruption, err)
		}
		if got := tx.variables.argsPost.Get("field"); len(got) != 1 || got[0] != "value" {
			t.Fatalf("ARGS_POST:field=%v", got)
		}
		if got := tx.variables.files.Get(""); len(got) != 1 || got[0] != "upload.bin" {
			t.Fatalf("FILES=%v", got)
		}
	})

	for _, tc := range []struct {
		name        string
		processor   string
		contentType string
	}{
		{"absent type", "", ""},
		{"unknown type", "", "application/unknown"},
		{"explicit urlencoded", "URLENCODED", "application/octet-stream"},
		{"explicit raw", "RAW", "application/octet-stream"},
		{"explicit json", "JSON", "application/json"},
		{"explicit xml", "XML", "application/xml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := newTx(16, types.BodyLimitActionReject)
			defer tx.Close()
			if tc.contentType != "" {
				tx.AddRequestHeader("Content-Type", tc.contentType)
			}
			tx.AddRequestHeader("Content-Length", "1")
			tx.variables.reqbodyProcessor.Set(tc.processor)
			tx.ProcessRequestHeaders()
			interruption, n, err := tx.ReadRequestBodyFrom(iotest.OneByteReader(strings.NewReader(strings.Repeat("x", 32))))
			if err != nil || n != 17 || interruption == nil || interruption.Status != 413 {
				t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
			}
			if got := tx.variables.argsPost.TotalValues(); got != 0 {
				t.Fatalf("ARGS_POST populated: %d", got)
			}
		})
	}

	t.Run("multiple writes", func(t *testing.T) {
		tx := newTx(16, types.BodyLimitActionReject)
		defer tx.Close()
		tx.ProcessRequestHeaders()
		if _, n, err := tx.WriteRequestBody([]byte("12345678")); n != 8 || err != nil {
			t.Fatalf("first write=%d err=%v", n, err)
		}
		interruption, n, err := tx.WriteRequestBody([]byte("123456789"))
		if interruption == nil || interruption.Status != 413 || n != 0 || err != nil {
			t.Fatalf("interruption=%v written=%d err=%v", interruption, n, err)
		}
	})

	t.Run("forced binary never reaches collections", func(t *testing.T) {
		tx := newTx(16, types.BodyLimitActionReject)
		defer tx.Close()
		tx.ForceRequestBodyVariable = true
		tx.AddRequestHeader("Content-Type", "application/octet-stream")
		tx.ProcessRequestHeaders()
		interruption, _, err := tx.WriteRequestBody([]byte("payload=" + strings.Repeat("x", 32)))
		if err != nil || interruption == nil || interruption.Status != 413 {
			t.Fatalf("interruption=%v err=%v", interruption, err)
		}
		if got := tx.variables.requestBody.Get(); got != "" {
			t.Fatalf("REQUEST_BODY was materialized: %d bytes", len(got))
		}
		if got := tx.variables.argsPost.TotalValues(); got != 0 {
			t.Fatalf("ARGS_POST was populated: %d values", got)
		}
	})

	t.Run("reader error", func(t *testing.T) {
		tx := newTx(16, types.BodyLimitActionReject)
		defer tx.Close()
		tx.ProcessRequestHeaders()
		wantErr := errors.New("reader failed")
		interruption, n, err := tx.ReadRequestBodyFrom(io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(wantErr)))
		if interruption != nil || n != 3 || !errors.Is(err, wantErr) {
			t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
		}
	})

	t.Run("unconfigured default", func(t *testing.T) {
		tx := newTx(0, types.BodyLimitActionReject)
		defer tx.Close()
		tx.ForceRequestBodyVariable = true
		tx.ProcessRequestHeaders()
		body := "payload=" + strings.Repeat("x", 32)
		interruption, n, err := tx.ReadRequestBodyFrom(strings.NewReader(body))
		if err != nil || interruption != nil || n != len(body) {
			t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			t.Fatal(err)
		}
		if got := tx.variables.argsPost.Get("payload"); len(got) != 1 || got[0] != strings.Repeat("x", 32) {
			t.Fatalf("default ARGS_POST=%v", got)
		}
	})

	t.Run("request body access disabled", func(t *testing.T) {
		tx := newTx(16, types.BodyLimitActionReject)
		defer tx.Close()
		tx.RequestBodyAccess = false
		interruption, n, err := tx.ReadRequestBodyFrom(strings.NewReader(strings.Repeat("x", 32)))
		if err != nil || interruption != nil || n != 0 {
			t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
		}
		if tx.variables.inboundDataError.Get() != "" || tx.variables.reqbodyError.Get() != "0" {
			t.Fatalf("limit state: inbound=%q reqbody=%q", tx.variables.inboundDataError.Get(), tx.variables.reqbodyError.Get())
		}
	})

	t.Run("detection only partial", func(t *testing.T) {
		tx := newTx(16, types.BodyLimitActionProcessPartial)
		defer tx.Close()
		tx.RuleEngine = types.RuleEngineDetectionOnly
		tx.ForceRequestBodyVariable = true
		tx.ProcessRequestHeaders()
		interruption, n, err := tx.ReadRequestBodyFrom(strings.NewReader("payload=" + strings.Repeat("x", 32)))
		if err != nil || interruption != nil || n != 17 {
			t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
		}
		if tx.variables.inboundDataError.Get() != "1" || tx.variables.reqbodyError.Get() != "1" {
			t.Fatalf("limit state: inbound=%q reqbody=%q", tx.variables.inboundDataError.Get(), tx.variables.reqbodyError.Get())
		}
		if got := tx.variables.argsPost.Get("payload"); len(got) != 1 || got[0] != strings.Repeat("x", 8) {
			t.Fatalf("partial ARGS_POST=%v", got)
		}
	})

	t.Run("partial keeps probe for connector replay", func(t *testing.T) {
		tx := newTx(16, types.BodyLimitActionProcessPartial)
		defer tx.Close()
		tx.ForceRequestBodyVariable = true
		tx.ProcessRequestHeaders()
		body := "payload=" + strings.Repeat("x", 32)
		input := strings.NewReader(body)
		interruption, n, err := tx.ReadRequestBodyFrom(input)
		if err != nil || interruption != nil || n != 17 {
			t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
		}
		buffered, err := tx.RequestBodyReader()
		if err != nil {
			t.Fatal(err)
		}
		replayed, err := io.ReadAll(io.MultiReader(buffered, input))
		if err != nil || string(replayed) != body {
			t.Fatalf("replay=%q err=%v", replayed, err)
		}
		if got := tx.variables.argsPost.Get("payload"); len(got) != 1 || got[0] != strings.Repeat("x", 8) {
			t.Fatalf("partial ARGS_POST=%v", got)
		}
		if got := tx.variables.requestBodyLength.Get(); got != "16" {
			t.Fatalf("REQUEST_BODY_LENGTH=%q", got)
		}
	})

	for _, tc := range []struct {
		name       string
		fields     []string
		files      []string
		fileFirst  bool
		interleave bool
		limit      int64
		status     int
	}{
		{"large file", []string{"x"}, []string{strings.Repeat("f", 1<<18)}, false, false, 512, 0},
		{"file before field", []string{"x"}, []string{strings.Repeat("f", 1<<18)}, true, false, 512, 0},
		{"several files", []string{"x"}, []string{strings.Repeat("f", 8192), strings.Repeat("g", 8192)}, false, false, 768, 0},
		{"interleaved", []string{"x", "y"}, []string{strings.Repeat("f", 8192), strings.Repeat("g", 8192)}, false, true, 768, 0},
		{"large field", []string{strings.Repeat("a", 8192)}, nil, false, false, 512, 413},
		{"cumulative fields", []string{strings.Repeat("a", 200), strings.Repeat("b", 200)}, nil, false, false, 300, 413},
		{"many tiny fields", strings.Fields(strings.Repeat("x ", 100)), nil, false, false, 512, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			writeFields := func() {
				for i, field := range tc.fields {
					if err := writer.WriteField(fmt.Sprintf("field%d", i), field); err != nil {
						t.Fatal(err)
					}
				}
			}
			writeFiles := func() {
				for i, file := range tc.files {
					part, err := writer.CreateFormFile(fmt.Sprintf("file%d", i), "upload.bin")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := io.WriteString(part, file); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch {
			case tc.interleave:
				for i := range tc.fields {
					if err := writer.WriteField(fmt.Sprintf("field%d", i), tc.fields[i]); err != nil {
						t.Fatal(err)
					}
					part, err := writer.CreateFormFile(fmt.Sprintf("file%d", i), "upload.bin")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := io.WriteString(part, tc.files[i]); err != nil {
						t.Fatal(err)
					}
				}
			case tc.fileFirst:
				writeFiles()
				writeFields()
			default:
				writeFields()
				writeFiles()
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			tx := newTx(tc.limit, types.BodyLimitActionReject)
			defer tx.Close()
			if tc.name == "large file" && environment.HasAccessToFS {
				tx.requestBodyBuffer.options.MemoryLimit = 128
			}
			tx.AddRequestHeader("Content-Type", writer.FormDataContentType())
			tx.ProcessRequestHeaders()
			if interruption, written, err := tx.WriteRequestBody(body.Bytes()); interruption != nil || err != nil || written != body.Len() {
				t.Fatalf("write: interruption=%v written=%d err=%v", interruption, written, err)
			}
			if tc.name == "large file" && environment.HasAccessToFS && tx.requestBodyBuffer.writer == nil {
				t.Fatal("expected disk-backed request body")
			}
			interruption, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatal(err)
			}
			if (interruption == nil) != (tc.status == 0) {
				t.Fatalf("interruption=%v, want status %d", interruption, tc.status)
			}
			if interruption != nil && interruption.Status != tc.status {
				t.Fatalf("status=%d, want %d", interruption.Status, tc.status)
			}
			if tc.status == 413 && len(tc.fields) > 0 {
				last := fmt.Sprintf("field%d", len(tc.fields)-1)
				if got := tx.variables.argsPost.Get(last); len(got) != 0 {
					t.Fatalf("over-limit multipart field %s entered ARGS_POST: %v", last, got)
				}
			}
			if tc.status == 0 && len(tx.variables.files.Get("")) != len(tc.files) {
				t.Fatalf("files=%v, want %d, error=%q strict=%q", tx.variables.files.Get(""), len(tc.files), tx.variables.reqbodyErrorMsg.Get(), tx.variables.multipartStrictError.Get())
			}
			if tc.status == 0 && len(tc.fields) > 0 {
				if got := tx.variables.argsPost.Get("field0"); len(got) != 1 || got[0] != tc.fields[0] {
					t.Fatalf("ARGS_POST:field0=%v, error=%q strict=%q", got, tx.variables.reqbodyErrorMsg.Get(), tx.variables.multipartStrictError.Get())
				}
			}
		})
	}

	for _, tc := range []struct {
		name        string
		firstIsFile bool
		malformed   bool
	}{
		{"partial keeps completed field", false, false},
		{"partial keeps completed file", true, false},
		{"parser error keeps completed field", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			body.WriteString("--b\r\nContent-Disposition: form-data; name=\"keep\"")
			if tc.firstIsFile {
				body.WriteString("; filename=\"keep.txt\"")
			}
			body.WriteString("\r\n\r\nok\r\n--b\r\n")
			if tc.malformed {
				body.WriteString("malformed header\r\n\r\ndrop\r\n--b--\r\n")
			} else {
				body.WriteString("Content-Disposition: form-data; name=\"drop\"\r\n")
				if tc.firstIsFile {
					body.WriteString("X-Pad: x" + strings.Repeat(" ", 256) + "\r\n")
				}
				body.WriteString("\r\n")
				body.WriteString(strings.Repeat("x", 1024))
				body.WriteString("\r\n--b--\r\n")
			}

			tx := newTx(128, types.BodyLimitActionProcessPartial)
			defer tx.Close()
			tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=b")
			tx.ProcessRequestHeaders()
			if _, _, err := tx.WriteRequestBody(body.Bytes()); err != nil {
				t.Fatal(err)
			}
			interruption, err := tx.ProcessRequestBody()
			if err != nil || interruption != nil {
				t.Fatalf("interruption=%v err=%v", interruption, err)
			}
			if tc.malformed {
				if got := tx.variables.reqbodyProcessorError.Get(); got != "1" {
					t.Fatalf("REQBODY_PROCESSOR_ERROR=%q", got)
				}
			} else if tx.variables.inboundDataError.Get() != "1" || tx.variables.reqbodyError.Get() != "1" {
				t.Fatalf("limit state: inbound=%q reqbody=%q", tx.variables.inboundDataError.Get(), tx.variables.reqbodyError.Get())
			}
			if tc.firstIsFile {
				if got := tx.variables.files.Get(""); len(got) != 1 || got[0] != "keep.txt" {
					t.Fatalf("FILES=%v", got)
				}
				if got := tx.variables.filesCombinedSize.Get(); got != "2" {
					t.Fatalf("FILES_COMBINED_SIZE=%q", got)
				}
			} else if got := tx.variables.argsPost.Get("keep"); len(got) != 1 || got[0] != "ok" {
				t.Fatalf("ARGS_POST:keep=%v", got)
			}
			if got := tx.variables.argsPost.Get("drop"); len(got) != 0 {
				t.Fatalf("ARGS_POST:drop=%v", got)
			}
		})
	}

	// ModSecurity counts raw part headers, their blank separator, and ordinary
	// field payload. Boundary framing and file payload are excluded.
	for _, hasFile := range []bool{false, true} {
		for _, payload := range []string{"payload", ""} {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			if err := writer.SetBoundary("b"); err != nil {
				t.Fatal(err)
			}
			if hasFile {
				part, err := writer.CreateFormFile("f", "f.txt")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(part, payload); err != nil {
					t.Fatal(err)
				}
			} else if err := writer.WriteField("f", payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			counted := int64(body.Len() - len("--b\r\n") - len("\r\n--b--\r\n"))
			if hasFile {
				counted -= int64(len(payload))
			}
			for _, delta := range []int64{0, -1} {
				name := fmt.Sprintf("multipart-file=%t-empty=%t-delta=%d", hasFile, payload == "", delta)
				t.Run(name, func(t *testing.T) {
					tx := newTx(counted+delta, types.BodyLimitActionReject)
					defer tx.Close()
					tx.AddRequestHeader("Content-Type", writer.FormDataContentType())
					tx.ProcessRequestHeaders()
					if _, _, err := tx.WriteRequestBody(body.Bytes()); err != nil {
						t.Fatal(err)
					}
					interruption, err := tx.ProcessRequestBody()
					if err != nil {
						t.Fatal(err)
					}
					if (interruption == nil) != (delta == 0) {
						t.Fatalf("counted=%d limit=%d interruption=%v", counted, counted+delta, interruption)
					}
				})
			}
		}
	}

	t.Run("epilogue excluded", func(t *testing.T) {
		body := "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--b--\r\n" + strings.Repeat("e", 4096)
		counted := int64(len("Content-Disposition: form-data; name=\"f\"\r\n\r\nx"))
		tx := newTx(counted, types.BodyLimitActionReject)
		defer tx.Close()
		tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=b")
		tx.ProcessRequestHeaders()
		if _, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if interruption, err := tx.ProcessRequestBody(); err != nil || interruption != nil {
			t.Fatalf("interruption=%v err=%v", interruption, err)
		}
	})

	for _, delta := range []int64{0, -1} {
		t.Run(fmt.Sprintf("quoted-printable-delta=%d", delta), func(t *testing.T) {
			headers := "Content-Disposition: form-data; name=\"f\"\r\n" +
				"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
			payload := "=41"
			body := "--b\r\n" + headers + payload + "\r\n--b--\r\n"
			limit := int64(len(headers)+len(payload)) + delta
			tx := newTx(limit, types.BodyLimitActionReject)
			defer tx.Close()
			tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=b")
			tx.ProcessRequestHeaders()
			if _, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
				t.Fatal(err)
			}
			interruption, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatal(err)
			}
			if (interruption == nil) != (delta == 0) {
				t.Fatalf("limit=%d interruption=%v", limit, interruption)
			}
			if delta == 0 {
				if got := tx.variables.argsPost.Get("f"); len(got) != 1 || got[0] != "A" {
					t.Fatalf("ARGS_POST:f=%v", got)
				}
			}
		})
	}

	for _, tc := range []struct {
		name   string
		body   string
		action types.BodyLimitAction
		status int
	}{
		{"large header", "--b\r\nX-Long: " + strings.Repeat("h", 1<<15) + "\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--b--\r\n", types.BodyLimitActionReject, 413},
		{"trailing whitespace header", "--b\r\nContent-Disposition: form-data; name=\"f\"\r\nX-Pad: x" + strings.Repeat(" ", 1024) + "\r\n\r\nx\r\n--b--\r\n", types.BodyLimitActionReject, 413},
		{"folded whitespace header", "--b\r\nContent-Disposition: form-data; name=\"f\"\r\nX-Pad: x\r\n\t" + strings.Repeat(" ", 1024) + "y\r\n\r\nx\r\n--b--\r\n", types.BodyLimitActionReject, 413},
		{"metadata header over", "--b\r\nX-Long: " + strings.Repeat("h", 1024) + "\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--b--\r\n", types.BodyLimitActionProcessPartial, 0},
		{"truncated field", "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n" + strings.Repeat("a", 4096), types.BodyLimitActionReject, 413},
		{"truncated file", "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"upload.bin\"\r\n\r\n" + strings.Repeat("f", 4096), types.BodyLimitActionReject, 413},
		{"empty filename", "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"\"\r\n\r\n" + strings.Repeat("a", 4096) + "\r\n--b--\r\n", types.BodyLimitActionReject, 413},
		{"partial field", "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n" + strings.Repeat("a", 4096) + "\r\n--b--\r\n", types.BodyLimitActionProcessPartial, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := newTx(512, tc.action)
			defer tx.Close()
			tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=b")
			tx.ProcessRequestHeaders()
			if _, _, err := tx.WriteRequestBody([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			interruption, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatal(err)
			}
			if (interruption == nil) != (tc.status == 0) {
				t.Fatalf("interruption=%v, want status %d", interruption, tc.status)
			}
			if tx.variables.inboundDataError.Get() != "1" || tx.variables.reqbodyError.Get() != "1" {
				t.Fatalf("limit state: inbound=%q reqbody=%q", tx.variables.inboundDataError.Get(), tx.variables.reqbodyError.Get())
			}
			if tx.variables.reqbodyErrorMsg.Get() == "" || tx.variables.reqbodyProcessorError.Get() != "0" {
				t.Fatalf("processor error state: msg=%q processor=%q", tx.variables.reqbodyErrorMsg.Get(), tx.variables.reqbodyProcessorError.Get())
			}
			if tc.name != "truncated field" && tc.name != "truncated file" && tx.variables.multipartStrictError.Get() == "1" {
				t.Fatal("limit was classified as malformed multipart")
			}
			if len(tx.variables.argsPost.Get("f")) != 0 {
				t.Fatalf("over-limit field entered ARGS_POST: %d values", len(tx.variables.argsPost.Get("f")))
			}
			if tc.name == "metadata header over" && len(tx.variables.multipartPartHeaders.Get("f")) != 0 {
				t.Fatal("over-limit part header entered MULTIPART_PART_HEADERS")
			}
		})
	}

	t.Run("custom multipart processor", func(t *testing.T) {
		builtin, err := bodyprocessors.GetBodyProcessor("multipart")
		if err != nil {
			t.Fatal(err)
		}
		bodyprocessors.RegisterBodyProcessor("multipart", func() plugintypes.BodyProcessor {
			return &testBodyProcessor{}
		})
		t.Cleanup(func() {
			bodyprocessors.RegisterBodyProcessor("multipart", func() plugintypes.BodyProcessor {
				return builtin
			})
		})

		tx := newTx(16, types.BodyLimitActionReject)
		defer tx.Close()
		tx.variables.reqbodyProcessor.Set("MULTIPART")
		tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=b")
		tx.ProcessRequestHeaders()
		interruption, n, err := tx.ReadRequestBodyFrom(strings.NewReader(strings.Repeat("x", 32)))
		if err != nil || n != 17 || interruption == nil || interruption.Status != 413 {
			t.Fatalf("interruption=%v read=%d err=%v", interruption, n, err)
		}
	})
}

func TestTxSettersMultipart(t *testing.T) {
	tx := makeTransactionMultipart(t)
	exp := map[string]string{
		"%{request_headers.x-test-header}": "test456",
		"%{request_method}":                "POST",
		"%{ARGS_GET.id}":                   "123",
		"%{request_cookies.test}":          "123",
		"%{args_post.testfield}":           "456",
		"%{args.testfield}":                "456",
		"%{request_line}":                  "POST /testurl.php?id=123&b=456 HTTP/1.1",
		"%{query_string}":                  "id=123&b=456",
		"%{request_filename}":              "/testurl.php",
		"%{request_protocol}":              "HTTP/1.1",
		"%{request_uri}":                   "/testurl.php?id=123&b=456",
		"%{request_uri_raw}":               "/testurl.php?id=123&b=456",
		"%{files_names}":                   "file1",
		"%{files_combined_size}":           "72",
		"%{files_sizes.a.txt}":             "19",
	}

	validateMacroExpansion(exp, tx, t)
}

func TestTxSetters(t *testing.T) {
	tx := makeTransaction(t)
	exp := map[string]string{
		"%{request_headers.x-test-header}": "test456",
		"%{request_method}":                "POST",
		"%{ARGS_GET.id}":                   "123",
		"%{request_cookies.test}":          "123",
		"%{args_post.testfield}":           "456",
		"%{args.testfield}":                "456",
		"%{request_line}":                  "POST /testurl.php?id=123&b=456 HTTP/1.1",
		"%{query_string}":                  "id=123&b=456",
		"%{request_filename}":              "/testurl.php",
		"%{request_protocol}":              "HTTP/1.1",
		"%{request_uri}":                   "/testurl.php?id=123&b=456",
		"%{request_uri_raw}":               "/testurl.php?id=123&b=456",
	}

	validateMacroExpansion(exp, tx, t)
}

func TestTxTime(t *testing.T) {
	tx := makeTransactionTimestamped(t)
	exp := map[string]string{
		"%{TIME}":       "15:27:34",
		"%{TIME_DAY}":   "18",
		"%{TIME_EPOCH}": fmt.Sprintf("%d", tx.Timestamp/1e9), // 1731943654 in UTC, may differ in local timezone
		"%{TIME_HOUR}":  "15",
		"%{TIME_MIN}":   "27",
		"%{TIME_MON}":   "11",
		"%{TIME_SEC}":   "34",
		"%{TIME_WDAY}":  "1",
		"%{TIME_YEAR}":  "2024",
	}
	validateMacroExpansion(exp, tx, t)
}

func TestTxMultipart(t *testing.T) {
	tx := NewWAF().NewTransaction()
	body := []string{
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"text\"",
		"",
		"test-value",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"file1\"; filename=\"a.html\"",
		"Content-Type: text/html",
		"",
		"<!DOCTYPE html><title>Content of a.html.</title>",
		"",
		"-----------------------------9051914041544843365972754266--",
	}
	data := strings.Join(body, "\r\n")
	headers := []string{
		"POST / HTTP/1.1",
		"Host: localhost:8000",
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:29.0) Gecko/20100101 Firefox/29.0",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language: en-US,en;q=0.5",
		"Accept-Encoding: gzip, deflate",
		"Connection: keep-alive",
		"Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		fmt.Sprintf("Content-Length: %d", len(data)),
	}
	data = strings.Join(headers, "\r\n") + "\r\n\r\n" + data + "\r\n"
	tx.RequestBodyAccess = true
	tx.RequestBodyLimit = 9999999
	_, err := tx.ParseRequestReader(strings.NewReader(data))
	if err != nil {
		t.Fatal("Failed to parse multipart request: " + err.Error())
	}
	exp := map[string]string{
		"%{args_post.text}":      "test-value",
		"%{files_combined_size}": "60",
		"%{files}":               "a.html",
		"%{files_names}":         "file1",
	}

	validateMacroExpansion(exp, tx, t)

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxResponse(t *testing.T) {
	/*
		tx := NewWAF().NewTransaction()
		ht := []string{
			"HTTP/1.1 200 OK",
			"Content-Type: text/html",
			"Last-Modified: Mon, 14 Sep 2020 21:10:42 GMT",
			"Accept-Ranges: bytes",
			"ETag: \"0b5f480db8ad61:0\"",
			"Vary: Accept-Encoding",
			"Server: Microsoft-IIS/8.5",
			"Content-Security-Policy: default-src: https:; frame-ancestors 'self' X-Frame-Options: SAMEORIGIN",
			"Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			"Date: Wed, 16 Sep 2020 14:14:09 GMT",
			"Connection: close",
			"Content-Length: 10",
			"",
			"testcontent",
		}
		data := strings.Join(ht, "\r\n")
		tx.ParseResponseString(nil, data)

		exp := map[string]string{
			"%{response_headers.content-length}": "10",
			"%{response_headers.server}":         "Microsoft-IIS/8.5",
		}

		validateMacroExpansion(exp, tx, t)
	*/
}

var requestBodyWriters = map[string]func(tx *Transaction, body string) (*types.Interruption, int, error){
	"WriteRequestBody": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.WriteRequestBody([]byte(body))
	},
	"ReadRequestBodyFromKnownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadRequestBodyFrom(strings.NewReader(body))
	},
	"ReadRequestBodyFromUnknownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadRequestBodyFrom(struct{ io.Reader }{
			strings.NewReader(body),
		})
	},
}

func TestWriteRequestBody(t *testing.T) {
	const (
		urlencodedBody    = "some=result&second=data"
		urlencodedBodyLen = len(urlencodedBody)
	)

	testCases := []struct {
		name                            string
		requestBodyLimit                int
		requestBodyLimitAction          types.BodyLimitAction
		avoidRequestBodyLimitActionInit bool
		shouldInterrupt                 bool
		limitReached                    bool // If the limit is reached, INBOUND_DATA_ERROR should be set
	}{
		{
			name:                   "LimitNotReached",
			requestBodyLimit:       urlencodedBodyLen + 2,
			requestBodyLimitAction: types.BodyLimitAction(-1),
			limitReached:           false,
		},
		{
			name:                   "LimitReachedAndRejects",
			requestBodyLimit:       urlencodedBodyLen - 3,
			requestBodyLimitAction: types.BodyLimitActionReject,
			shouldInterrupt:        true,
			limitReached:           true,
		},
		{
			name:             "LimitReachedAndRejectsDefaultValue",
			requestBodyLimit: urlencodedBodyLen - 3,
			// Omitting requestBodyLimitAction defaults to Reject
			// requestBodyLimitAction: types.BodyLimitActionReject,
			avoidRequestBodyLimitActionInit: true,
			shouldInterrupt:                 true,
			limitReached:                    true,
		},
		{
			name:                   "LimitReachedAndPartialProcessing",
			requestBodyLimit:       urlencodedBodyLen - 3,
			requestBodyLimitAction: types.BodyLimitActionProcessPartial,
			limitReached:           true,
		},
	}

	urlencodedBodyLenThird := urlencodedBodyLen / 3
	bodyChunks := map[string][]string{
		"BodyInOneShot":     {urlencodedBody},
		"BodyInThreeChunks": {urlencodedBody[0:urlencodedBodyLenThird], urlencodedBody[urlencodedBodyLenThird : 2*urlencodedBodyLenThird], urlencodedBody[2*urlencodedBodyLenThird:]},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for name, writeRequestBody := range requestBodyWriters {
				t.Run(name, func(t *testing.T) {
					for name, chunks := range bodyChunks {
						t.Run(name, func(t *testing.T) {
							waf := NewWAF()
							waf.RuleEngine = types.RuleEngineOn
							waf.RequestBodyAccess = true
							waf.RequestBodyLimit = int64(testCase.requestBodyLimit)
							if !testCase.avoidRequestBodyLimitActionInit {
								waf.RequestBodyLimitAction = testCase.requestBodyLimitAction
							}
							tx := waf.NewTransaction()
							tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")

							it := tx.ProcessRequestHeaders()
							if it != nil {
								t.Fatal("Unexpected interruption on headers")
							}

							var err error

							for _, c := range chunks {
								if it, _, err = writeRequestBody(tx, c); err != nil {
									t.Fatalf("Failed to write body buffer: %s", err.Error())
								}
							}
							if testCase.limitReached && tx.variables.inboundDataError.Get() != "1" {
								t.Fatalf("Expected INBOUND_DATA_ERROR to be set")
							}
							if testCase.shouldInterrupt {
								if it == nil {
									t.Fatal("Expected interruption, got nil")
								}
							} else {
								it, err := tx.ProcessRequestBody()
								if err != nil {
									t.Fatal(err)
								}

								if it != nil {
									t.Fatalf("Unexpected interruption")
								}

								val := tx.variables.argsPost.Get("some")
								if len(val) != 1 || val[0] != "result" {
									t.Fatalf("Failed to set urlencoded POST data with arguments: \"%s\"", strings.Join(val, "\", \""))
								}
							}

							if err := tx.Close(); err != nil {
								t.Fatalf("Failed to close transaction: %s", err.Error())
							}
						})
					}

				})
			}

		})
	}
}

func TestWriteRequestBodyOnLimitReached(t *testing.T) {
	testCases := map[string]struct {
		requestBodyLimitAction  types.BodyLimitAction
		preexistingInterruption *types.Interruption
	}{
		"reject": {
			requestBodyLimitAction: types.BodyLimitActionReject,
			preexistingInterruption: &types.Interruption{
				RuleID: 123,
			},
		},
		"partial processing": {
			requestBodyLimitAction: types.BodyLimitActionProcessPartial,
		},
	}

	for tName, tCase := range testCases {
		waf := NewWAF()
		waf.RuleEngine = types.RuleEngineOn
		waf.RequestBodyAccess = true
		waf.RequestBodyLimit = 2
		waf.RequestBodyLimitAction = tCase.requestBodyLimitAction

		t.Run(tName, func(t *testing.T) {
			for wName, writer := range requestBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					_, err := tx.requestBodyBuffer.Write([]byte("ab"))
					if err != nil {
						t.Fatalf("unexpected error when writing to body buffer directly: %s", err.Error())
					}
					tx.interruption = tCase.preexistingInterruption

					it, n, err := writer(tx, "c")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != tCase.preexistingInterruption {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestWriteRequestBodyIsNopWhenBodyIsNotAccesible(t *testing.T) {
	testCases := []struct {
		ruleEngine        types.RuleEngineStatus
		requestBodyAccess bool
	}{
		{
			ruleEngine: types.RuleEngineOff,
		},
		{
			ruleEngine:        types.RuleEngineOn,
			requestBodyAccess: false,
		},
	}

	for _, tCase := range testCases {
		t.Run(fmt.Sprintf(
			"ruleEngine = %s and requestBodyAccess = %t",
			tCase.ruleEngine.String(),
			tCase.requestBodyAccess,
		), func(t *testing.T) {
			waf := NewWAF()
			waf.RuleEngine = tCase.ruleEngine
			waf.RequestBodyAccess = tCase.requestBodyAccess

			for wName, writer := range requestBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					it, n, err := writer(tx, "abc")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != nil {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestResponseHeader(t *testing.T) {
	tx := makeTransaction(t)
	tx.AddResponseHeader("content-type", "test")
	if tx.variables.responseContentType.Get() != "test" {
		t.Fatal("invalid RESPONSE_CONTENT_TYPE after response headers")
	}

	interruption := tx.ProcessResponseHeaders(200, "OK")
	if interruption != nil {
		t.Fatal("unexpected interruption")
	}
}

func TestProcessRequestHeadersDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff

	if !tx.IsRuleEngineOff() {
		t.Fatal("expected Engine off")
	}

	_ = tx.ProcessRequestHeaders()
	if tx.lastPhase != 0 { // 0 means no phases have been evaluated
		t.Fatal("unexpected rule evaluation")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestProcessRequestBodyDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal("failed to process request body")
	}
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestProcessResponseHeadersDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	_ = tx.ProcessResponseHeaders(200, "OK")
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
}

func TestProcessResponseBodyDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal("Failed to process response body")
	}
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
}

func TestProcessLoggingDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	tx.ProcessLogging()
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLog(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")
	al := tx.AuditLog()
	if al.Transaction().ID() != tx.id {
		t.Fatal("invalid auditlog id")
	}
	// TODO more checks
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLogPartJWithMultipartFiles(t *testing.T) {
	tx := makeTransactionMultipart(t)
	tx.AuditLogParts = types.AuditLogParts("AJZ")
	_, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatal(err)
	}
	al := tx.AuditLog()

	if !al.Transaction().HasRequest() {
		t.Fatal("expected request in audit log")
	}

	files := al.Transaction().Request().Files()
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	// Files come from the multipart body: a.txt and a.html
	names := map[string]bool{}
	for _, f := range files {
		names[f.Name()] = true
		if f.Size() == 0 {
			t.Errorf("file %s has size 0", f.Name())
		}
	}
	if !names["a.txt"] {
		t.Error("missing file a.txt")
	}
	if !names["a.html"] {
		t.Error("missing file a.html")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLogPartJWithoutFiles(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("AJZ")
	al := tx.AuditLog()

	if !al.Transaction().HasRequest() {
		t.Fatal("expected request in audit log")
	}

	files := al.Transaction().Request().Files()
	if len(files) != 0 {
		t.Fatalf("expected 0 files, got %d", len(files))
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLogPartJFileSizeParseError(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("AJZ")

	// Manually inject a file with an unparseable size
	tx.variables.files.Add("", "bad_size.bin")
	tx.variables.filesSizes.SetIndex("bad_size.bin", 0, "not_a_number")

	al := tx.AuditLog()
	files := al.Transaction().Request().Files()
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name() != "bad_size.bin" {
		t.Errorf("expected file name bad_size.bin, got %s", files[0].Name())
	}
	// Size should default to 0 on parse error
	if files[0].Size() != 0 {
		t.Errorf("expected size 0 on parse error, got %d", files[0].Size())
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

var responseBodyWriters = map[string]func(tx *Transaction, body string) (*types.Interruption, int, error){
	"WriteResponseBody": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.WriteResponseBody([]byte(body))
	},
	"ReadResponseBodyFromKnownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadResponseBodyFrom(strings.NewReader(body))
	},
	"ReadResponseBodyFromUnknownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadResponseBodyFrom(struct{ io.Reader }{
			strings.NewReader(body),
		})
	},
}

func TestWriteResponseBody(t *testing.T) {
	const (
		urlencodedBody    = "some=result&second=data"
		urlencodedBodyLen = len(urlencodedBody)
	)

	testCases := []struct {
		name                    string
		responseBodyLimit       int
		responseBodyLimitAction types.BodyLimitAction
		shouldInterrupt         bool
		limitReached            bool // If the limit is reached, OUTBOUND_DATA_ERROR should be set
	}{
		{
			name:                    "LimitNotReached",
			responseBodyLimit:       urlencodedBodyLen + 2,
			responseBodyLimitAction: types.BodyLimitAction(-1),
			limitReached:            false,
		},
		{
			name:                    "LimitReachedAndRejects",
			responseBodyLimit:       urlencodedBodyLen - 3,
			responseBodyLimitAction: types.BodyLimitActionReject,
			shouldInterrupt:         true,
			limitReached:            true,
		},
		{
			name:                    "LimitReachedAndPartialProcessing",
			responseBodyLimit:       urlencodedBodyLen - 3,
			responseBodyLimitAction: types.BodyLimitActionProcessPartial,
			limitReached:            true,
		},
		{
			name:              "LimitReachedAndPartialProcessingDefaultValue",
			responseBodyLimit: urlencodedBodyLen - 3,
			// Omitting requestBodyLimitAction defaults to ProcessPartial
			// responseBodyLimitAction: types.BodyLimitActionProcessPartial,
			limitReached: true,
		},
	}

	urlencodedBodyLenThird := urlencodedBodyLen / 3
	bodyChunks := map[string][]string{
		"BodyInOneShot":     {urlencodedBody},
		"BodyInThreeChunks": {urlencodedBody[0:urlencodedBodyLenThird], urlencodedBody[urlencodedBodyLenThird : 2*urlencodedBodyLenThird], urlencodedBody[2*urlencodedBodyLenThird:]},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for name, writeResponseBody := range responseBodyWriters {
				t.Run(name, func(t *testing.T) {
					for name, chunks := range bodyChunks {
						t.Run(name, func(t *testing.T) {
							waf := NewWAF()
							waf.RuleEngine = types.RuleEngineOn
							waf.ResponseBodyMimeTypes = []string{"text/plain"}
							waf.ResponseBodyAccess = true
							waf.ResponseBodyLimit = int64(testCase.responseBodyLimit)
							waf.ResponseBodyLimitAction = testCase.responseBodyLimitAction

							if err := waf.Validate(); err != nil {
								t.Fatalf("failed to validate the WAF: %s", err.Error())
							}

							tx := waf.NewTransaction()
							tx.AddResponseHeader("content-type", "text/plain")

							it := tx.ProcessResponseHeaders(200, "HTTP/1")
							if it != nil {
								t.Fatal("Unexpected interruption on headers")
							}

							var err error

							for _, c := range chunks {
								if it, _, err = writeResponseBody(tx, c); err != nil {
									t.Fatalf("Failed to write body buffer: %s", err.Error())
								}
							}
							if testCase.limitReached && tx.variables.outboundDataError.Get() != "1" {
								t.Fatalf("Expected OUTBOUND_DATA_ERROR to be set")
							}
							if testCase.shouldInterrupt {
								if it == nil {
									t.Fatal("Expected interruption, got nil")
								}
							} else {
								it, err := tx.ProcessResponseBody()
								if err != nil {
									t.Fatal(err)
								}

								if it != nil {
									t.Fatalf("Unexpected interruption")
								}
								// checking if the body has been populated up to the first POST arg
								index := strings.Index(urlencodedBody, "&")
								if tx.variables.responseBody.Get()[:index] != urlencodedBody[:index] {
									t.Fatal("failed to set response body")
								}
							}

							if err := tx.Close(); err != nil {
								t.Fatalf("Failed to close transaction: %s", err.Error())
							}
						})
					}

				})
			}

		})
	}
}

func TestWriteResponseBodyOnLimitReached(t *testing.T) {
	testCases := map[string]struct {
		responseBodyLimitAction types.BodyLimitAction
		preexistingInterruption *types.Interruption
	}{
		"reject": {
			responseBodyLimitAction: types.BodyLimitActionReject,
			preexistingInterruption: &types.Interruption{
				RuleID: 123,
			},
		},
		"partial processing": {
			responseBodyLimitAction: types.BodyLimitActionProcessPartial,
		},
	}

	for tName, tCase := range testCases {
		waf := NewWAF()
		waf.RuleEngine = types.RuleEngineOn
		waf.ResponseBodyAccess = true
		waf.ResponseBodyLimit = 2
		waf.ResponseBodyLimitAction = tCase.responseBodyLimitAction

		t.Run(tName, func(t *testing.T) {
			for wName, writer := range responseBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					_, err := tx.responseBodyBuffer.Write([]byte("ab"))
					if err != nil {
						t.Fatalf("unexpected error when writing to body buffer directly: %s", err.Error())
					}
					tx.interruption = tCase.preexistingInterruption

					it, n, err := writer(tx, "c")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != tCase.preexistingInterruption {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestWriteResponseBodyIsNopWhenBodyIsNotAccesible(t *testing.T) {
	testCases := []struct {
		ruleEngine         types.RuleEngineStatus
		responseBodyAccess bool
	}{
		{
			ruleEngine: types.RuleEngineOff,
		},
		{
			ruleEngine:         types.RuleEngineOn,
			responseBodyAccess: false,
		},
	}

	for _, tCase := range testCases {
		t.Run(fmt.Sprintf(
			"ruleEngine = %s and responseBodyAccess = %t",
			tCase.ruleEngine.String(),
			tCase.responseBodyAccess,
		), func(t *testing.T) {
			waf := NewWAF()
			waf.RuleEngine = tCase.ruleEngine
			waf.ResponseBodyAccess = tCase.responseBodyAccess

			for wName, writer := range responseBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					it, n, err := writer(tx, "abc")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != nil {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestAuditLogFields(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")
	tx.AddRequestHeader("test", "test")
	tx.AddResponseHeader("test", "test")
	rule := NewRule()
	rule.ID_ = 131
	rule.Log = true
	rule.Audit = true
	tx.MatchRule(rule, []types.MatchData{
		&corazarules.MatchData{
			Variable_: variables.UniqueID,
		},
	})
	if len(tx.matchedRules) == 0 || tx.matchedRules[0].Rule().ID() != rule.ID_ {
		t.Fatal("failed to match rule for audit")
	}
	al := tx.AuditLog()
	if len(al.Messages()) == 0 || al.Messages()[0].Data().ID() != rule.ID_ {
		t.Fatal("failed to add rules to audit logs")
	}

	if len(al.Transaction().Request().Headers()) == 0 || al.Transaction().Request().Headers()["test"][0] != "test" {
		t.Fatal("failed to add request header to audit log")
	}
	if len(al.Transaction().Response().Headers()) == 0 || al.Transaction().Response().Headers()["test"][0] != "test" {
		t.Fatal("failed to add Response header to audit log")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLogMessageFiltering(t *testing.T) {
	tests := []struct {
		name           string
		log            bool
		audit          bool
		wantInAuditLog bool
		wantInErrorLog bool
		desc           string
	}{
		{
			name:           "log action (log=true, audit=true)",
			log:            true,
			audit:          true,
			wantInAuditLog: true,
			wantInErrorLog: true,
			desc:           "log sets both flags: rule appears in error log and audit log",
		},
		{
			name:           "nolog action (log=false, audit=false)",
			log:            false,
			audit:          false,
			wantInAuditLog: false,
			wantInErrorLog: false,
			desc:           "nolog clears both flags: rule appears in neither",
		},
		{
			name:           "nolog,auditlog (log=false, audit=true)",
			log:            false,
			audit:          true,
			wantInAuditLog: true,
			wantInErrorLog: false,
			desc:           "nolog,auditlog: rule appears in audit log only",
		},
		{
			name:           "log,noauditlog (log=true, audit=false)",
			log:            true,
			audit:          false,
			wantInAuditLog: false,
			wantInErrorLog: true,
			desc:           "log,noauditlog: rule appears in error log only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")

			var errorLogCalled bool
			tx.WAF.ErrorLogCb = func(_ types.MatchedRule) {
				errorLogCalled = true
			}

			rule := NewRule()
			rule.ID_ = 100
			rule.Log = tt.log
			rule.Audit = tt.audit
			tx.MatchRule(rule, []types.MatchData{
				&corazarules.MatchData{
					Variable_: variables.UniqueID,
				},
			})

			al := tx.AuditLog()

			if got := len(al.Messages()) > 0; got != tt.wantInAuditLog {
				t.Errorf("%s: audit log messages: got present=%v, want present=%v", tt.desc, got, tt.wantInAuditLog)
			}

			if errorLogCalled != tt.wantInErrorLog {
				t.Errorf("%s: error log callback: got called=%v, want called=%v", tt.desc, errorLogCalled, tt.wantInErrorLog)
			}

			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}
}

func TestAuditLogHPartMessageFiltering(t *testing.T) {
	// When only H (AuditLogTrailer) is set without K (RulesMatched),
	// error messages should still be filtered by the Audit flag.
	tests := []struct {
		name           string
		log            bool
		audit          bool
		wantInAuditLog bool
	}{
		{
			name:           "log,audit: appears in H-only messages",
			log:            true,
			audit:          true,
			wantInAuditLog: true,
		},
		{
			name:           "log,noaudit: excluded from H-only messages",
			log:            true,
			audit:          false,
			wantInAuditLog: false,
		},
		{
			name:           "nolog,audit: appears in H-only messages",
			log:            false,
			audit:          true,
			wantInAuditLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			// H without K
			tx.AuditLogParts = types.AuditLogParts("ABCDEFGH")

			rule := NewRule()
			rule.ID_ = 200
			rule.Log = tt.log
			rule.Audit = tt.audit
			tx.MatchRule(rule, []types.MatchData{
				&corazarules.MatchData{
					Variable_: variables.UniqueID,
				},
			})

			al := tx.AuditLog()

			if got := len(al.Messages()) > 0; got != tt.wantInAuditLog {
				t.Errorf("H-only audit log: got present=%v, want present=%v", got, tt.wantInAuditLog)
			}

			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}
}

func TestMatchRuleDisruptiveActionPopulated(t *testing.T) {
	tests := []struct {
		name                         string
		engine                       types.RuleEngineStatus
		wantDisruptive               bool
		wantAction                   corazarules.DisruptiveAction
		wantInterrupted              bool
		wantDetectionOnlyInterrupted bool
	}{
		{
			name:                         "engine on",
			engine:                       types.RuleEngineOn,
			wantDisruptive:               true,
			wantAction:                   corazarules.DisruptiveActionDeny,
			wantInterrupted:              true,
			wantDetectionOnlyInterrupted: false,
		},
		{
			name:                         "engine detection only",
			engine:                       types.RuleEngineDetectionOnly,
			wantDisruptive:               false,
			wantAction:                   corazarules.DisruptiveActionDeny,
			wantInterrupted:              false,
			wantDetectionOnlyInterrupted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := NewWAF()
			tx := waf.NewTransaction()
			tx.RuleEngine = tt.engine

			rule := NewRule()
			rule.ID_ = 1
			if err := rule.AddVariable(variables.ArgsGet, "", false); err != nil {
				t.Fatal(err)
			}
			rule.SetOperator(&dummyEqOperator{}, "@eq", "0")
			_ = rule.AddAction("deny", &dummyDenyAction{})

			tx.AddGetRequestArgument("test", "0")

			var matchedValues []types.MatchData
			rule.doEvaluate(debuglog.Noop(), types.PhaseRequestHeaders, tx, &matchedValues, 0, tx.transformationCache)

			if len(tx.matchedRules) != 1 {
				t.Fatalf("expected 1 matched rule, got %d", len(tx.matchedRules))
			}
			mr := tx.matchedRules[0].(*corazarules.MatchedRule)
			if mr.Disruptive_ != tt.wantDisruptive {
				t.Errorf("Disruptive_: got %t, want %t", mr.Disruptive_, tt.wantDisruptive)
			}
			if mr.DisruptiveAction_ != tt.wantAction {
				t.Errorf("DisruptiveAction_: got %d, want %d", mr.DisruptiveAction_, tt.wantAction)
			}
			if tx.IsInterrupted() != tt.wantInterrupted {
				t.Errorf("IsInterrupted: got %t, want %t", tx.IsInterrupted(), tt.wantInterrupted)
			}
			if tx.IsDetectionOnlyInterrupted() != tt.wantDetectionOnlyInterrupted {
				t.Errorf("IsDetectionOnlyInterrupted: got %t, want %t", tx.IsDetectionOnlyInterrupted(), tt.wantDetectionOnlyInterrupted)
			}
		})
	}
}

func TestResetCapture(t *testing.T) {
	tx := makeTransaction(t)
	tx.Capture = true
	tx.CaptureField(5, "test")
	if tx.variables.tx.Get("5")[0] != "test" {
		t.Fatal("failed to set capture field from tx")
	}
	tx.resetCaptures()
	if tx.variables.tx.Get("5")[0] != "" {
		t.Fatal("failed to reset capture field from tx")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestRelevantAuditLogging(t *testing.T) {
	tests := []struct {
		name         string
		status       string
		interruption *types.Interruption
		relevantLog  bool
	}{
		{
			name:         "TestRelevantAuditLogging",
			status:       "403",
			interruption: nil,
			relevantLog:  true,
		},
		{
			name:         "TestNotRelevantAuditLogging",
			status:       "200",
			interruption: nil,
			relevantLog:  false,
		},
		{
			name: "TestRelevantAuditLoggingWithInterruption",
			interruption: &types.Interruption{
				Status: 403,
				Action: "deny",
			},
			relevantLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			debugLog := bytes.Buffer{}
			tx.debugLogger = debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(&debugLog)
			tx.WAF.AuditLogRelevantStatus = regexp.MustCompile(`(403)`)
			tx.variables.responseStatus.Set(tt.status)
			tx.interruption = tt.interruption
			tx.AuditEngine = types.AuditEngineRelevantOnly
			tx.audit = true // Mimics that there is something to audit
			tx.ProcessLogging()
			// TODO how do we check if the log was written?
			if err := tx.Close(); err != nil {
				t.Error(err)
			}
			if tt.relevantLog && strings.Contains(debugLog.String(), "Transaction status not marked for audit logging") {
				t.Errorf("unexpected debug log: %q. Transaction status should be marked for audit logging", debugLog.String())
			}
			if !tt.relevantLog && !strings.Contains(debugLog.String(), "Transaction status not marked for audit logging") {
				t.Errorf("missing debug log. Transaction status should be not marked for audit logging not being relevant")
			}
		})
	}
}

func TestRelevantAuditLoggingWithoutAuditFlag(t *testing.T) {
	// Regression test for https://github.com/corazawaf/coraza/issues/1576
	// When tx.audit is false (no rule with auditlog action matched),
	// SecAuditLogRelevantStatus should still cause logging if the status matches.
	tests := []struct {
		name         string
		status       string
		audit        bool
		interruption *types.Interruption
		shouldLog    bool
	}{
		{
			name:      "audit=false, relevant status via response → should log",
			status:    "403",
			audit:     false,
			shouldLog: true,
		},
		{
			name:      "audit=false, non-relevant status → should not log",
			status:    "200",
			audit:     false,
			shouldLog: false,
		},
		{
			name:  "audit=false, relevant status via interruption → should log",
			audit: false,
			interruption: &types.Interruption{
				Status: 403,
				Action: "deny",
			},
			shouldLog: true,
		},
		{
			name:      "audit=true, relevant status → should log",
			status:    "403",
			audit:     true,
			shouldLog: true,
		},
		{
			name:      "audit=true, non-relevant status → should not log",
			status:    "200",
			audit:     true,
			shouldLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			debugLog := bytes.Buffer{}
			tx.debugLogger = debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(&debugLog)
			tx.WAF.AuditLogRelevantStatus = regexp.MustCompile(`^(?:5|4[0-9][0-35-9])`)
			tx.variables.responseStatus.Set(tt.status)
			tx.interruption = tt.interruption
			tx.AuditEngine = types.AuditEngineRelevantOnly
			tx.audit = tt.audit
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				t.Error(err)
			}
			logged := strings.Contains(debugLog.String(), "Transaction marked for audit logging")
			if tt.shouldLog && !logged {
				t.Errorf("expected transaction to be audit logged, debug: %q", debugLog.String())
			}
			if !tt.shouldLog && logged {
				t.Errorf("expected transaction NOT to be audit logged, debug: %q", debugLog.String())
			}
		})
	}
}

// TestTransactionFieldCount is a tripwire against pool-reuse state leaks such as
// https://github.com/corazawaf/coraza/issues/1640. Transactions are pooled and
// reused, so every field must be reset before a transaction is handed out again
// (in newTransaction, or in place in Close); a field left set leaks into the next
// request. This test fails whenever a field is added to or removed from
// Transaction: when it does, make sure the field is reset on pool reuse, then
// update wantFields.
func TestTransactionFieldCount(t *testing.T) {
	const wantFields = 37
	if got := reflect.TypeFor[Transaction]().NumField(); got != wantFields {
		t.Fatalf("Transaction has %d fields, want %d. If you added a field, make sure it "+
			"is reset on pool reuse in newTransaction() (or Close()), then update wantFields.", got, wantFields)
	}
}

func TestLogCallback(t *testing.T) {

	testCases := []struct {
		name            string
		engineStatus    types.RuleEngineStatus
		action          plugintypes.Action
		shouldInterrupt bool
		expectedLogLine string
	}{
		{
			name:            "disruptive action",
			engineStatus:    types.RuleEngineOn,
			action:          &dummyDenyAction{},
			shouldInterrupt: true,
			expectedLogLine: "Coraza: Access denied",
		},
		{
			name:            "disruptive action detection only",
			engineStatus:    types.RuleEngineDetectionOnly,
			action:          &dummyDenyAction{},
			shouldInterrupt: false,
			expectedLogLine: "Coraza: Warning",
		},
		{
			name:            "no disruptive action",
			engineStatus:    types.RuleEngineOn,
			action:          &dummyNonDisruptiveAction{},
			shouldInterrupt: false,
			expectedLogLine: "Coraza: Warning",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			waf := NewWAF()
			buffer := ""
			waf.SetErrorCallback(func(mr types.MatchedRule) {
				buffer = mr.ErrorLog()
			})
			waf.RuleEngine = testCase.engineStatus
			tx := waf.NewTransaction()
			rule := NewRule()
			rule.ID_ = 1
			rule.LogID_ = "1"
			rule.Phase_ = 1
			rule.Log = true
			_ = rule.AddAction("deny", testCase.action)
			tx.MatchRule(rule, []types.MatchData{
				&corazarules.MatchData{
					Variable_: variables.UniqueID,
				},
			})
			tx.WAF.Rules.rules = append(tx.WAF.Rules.rules, *rule)

			it := tx.ProcessRequestHeaders()
			if testCase.shouldInterrupt {
				if it == nil {
					t.Fatal("Expected interruption on headers with disruptive action")
				}
			} else {
				if it != nil {
					t.Fatal("Unexpected interruption on headers without disruptive action")
				}
			}

			if buffer == "" || !strings.Contains(buffer, tx.id) {
				t.Fatal("failed to call error log callback")
			}
			if !strings.Contains(buffer, testCase.expectedLogLine) {
				t.Fatalf("Expected string \"%s\" with disruptive rule, got %s", testCase.expectedLogLine, buffer)

				if err := tx.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHeaderSetters(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.AddRequestHeader("cookie", "abc=def;hij=klm")
	tx.AddRequestHeader("test1", "test2")
	c := tx.variables.requestCookies.Get("abc")[0]
	if c != "def" {
		t.Fatalf("failed to set cookie, got %q", c)
	}
	if tx.variables.requestHeaders.Get("cookie")[0] != "abc=def;hij=klm" {
		t.Fatal("failed to set request header")
	}
	if !utils.InSlice("cookie", collectionValues(t, tx.variables.requestHeadersNames)) {
		t.Fatal("failed to set header name", collectionValues(t, tx.variables.requestHeadersNames))
	}
	if !utils.InSlice("abc", collectionValues(t, tx.variables.requestCookiesNames)) {
		t.Fatal("failed to set cookie name")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestCookiesNotUrldecoded(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	fullCookie := "abc=%7Bd+e+f%7D;hij=%7Bklm%7D"
	expectedUrlencodedAbcCookieValue := "%7Bd+e+f%7D"
	unexpectedUrldencodedAbcCookieValue := "{d e f}"
	tx.AddRequestHeader("cookie", fullCookie)
	c := tx.variables.requestCookies.Get("abc")[0]
	if c != expectedUrlencodedAbcCookieValue {
		if c == unexpectedUrldencodedAbcCookieValue {
			t.Errorf("failed to set cookie, unexpected urldecoding. Got: %q, expected: %q", unexpectedUrldencodedAbcCookieValue, expectedUrlencodedAbcCookieValue)
		} else {
			t.Errorf("failed to set cookie, got %q", c)
		}
	}
	if tx.variables.requestHeaders.Get("cookie")[0] != fullCookie {
		t.Errorf("failed to set request header, got: %q, expected: %q", tx.variables.requestHeaders.Get("cookie")[0], fullCookie)
	}
	if !utils.InSlice("cookie", collectionValues(t, tx.variables.requestHeadersNames)) {
		t.Error("failed to set header name", collectionValues(t, tx.variables.requestHeadersNames))
	}
	if !utils.InSlice("abc", collectionValues(t, tx.variables.requestCookiesNames)) {
		t.Error("failed to set cookie name")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestMultipleCookiesWithSpaceBetweenThem(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	multipleCookies := "cookie1=value1; cookie2=value2;    cookie1=value2"
	tx.AddRequestHeader("cookie", multipleCookies)
	v11 := tx.variables.requestCookies.Get("cookie1")[0]
	if v11 != "value1" {
		t.Errorf("failed to set cookie, got %q", v11)
	}
	v12 := tx.variables.requestCookies.Get("cookie1")[1]
	if v12 != "value2" {
		t.Errorf("failed to set cookie, got %q", v12)
	}
	v2 := tx.variables.requestCookies.Get("cookie2")[0]
	if v2 != "value2" {
		t.Errorf("failed to set cookie, got %q", v2)
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func collectionValues(t *testing.T, col collection.Collection) []string {
	t.Helper()
	all := col.FindAll()
	values := make([]string, 0, len(all))
	for _, v := range all {
		values = append(values, v.Value())
	}
	return values
}

func TestRequestBodyProcessingAlgorithm(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.RuleEngine = types.RuleEngineOn
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	tx.AddRequestHeader("content-type", "text/plain")
	tx.AddRequestHeader("content-length", "7")
	tx.ProcessRequestHeaders()
	if _, err := tx.requestBodyBuffer.Write([]byte("test123")); err != nil {
		t.Fatal("Failed to write request body buffer")
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal("failed to process request body")
	}
	if tx.variables.requestBody.Get() != "test123" {
		t.Fatal("failed to set request body")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// TestDuplicateContentTypeHeaderUsesFirstForBodyProcessorSelection is a
// regression test for GHSA-w253-m66g-rx24: it needs two Content-Type headers
// on one request, which testing/profile's StageInput.Headers
// (map[string]string) cannot express, so it cannot be a profile.
//
// It is also the home for how a single Content-Type value selects the
// processor: leading Unicode whitespace is trimmed as mime.ParseMediaType does.
//
// Only the first Content-Type header may select the body processor, matching
// ProcessRequestBody's mimeType and a typical backend's Header.Get. Otherwise
// e.g. a genuine multipart body gets the URLENCODED processor, which parses
// it without error and leaves ARGS_POST and FILES empty.
func TestDuplicateContentTypeHeaderUsesFirstForBodyProcessorSelection(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{"single urlencoded", []string{"application/x-www-form-urlencoded"}, "URLENCODED"},
		{"multipart then urlencoded", []string{"multipart/form-data; boundary=XyZ", "application/x-www-form-urlencoded"}, "MULTIPART"},
		{"urlencoded then multipart", []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=XyZ"}, "URLENCODED"},
		{"unrecognized then multipart", []string{"text/plain", "multipart/form-data; boundary=XyZ"}, ""},
		{"json then urlencoded", []string{"application/json", "application/x-www-form-urlencoded"}, ""},
		// mime.ParseMediaType (and so the backend) trims Unicode whitespace
		// around the media type; selection must too.
		{"U+0085 before urlencoded", []string{"\u0085application/x-www-form-urlencoded"}, "URLENCODED"},
		{"U+00A0 before urlencoded", []string{"\u00a0application/x-www-form-urlencoded"}, "URLENCODED"},
		{"U+3000 before multipart", []string{"\u3000multipart/form-data; boundary=XyZ"}, "MULTIPART"},
		{"tab before multipart", []string{"\tmultipart/form-data; boundary=XyZ"}, "MULTIPART"},
		{"non-space prefix before urlencoded", []string{"xapplication/x-www-form-urlencoded"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := NewWAF().NewTransaction()
			defer func() { _ = tx.Close() }()
			for _, h := range tt.headers {
				tx.AddRequestHeader("Content-Type", h)
			}
			if got := tx.variables.reqbodyProcessor.Get(); got != tt.want {
				t.Errorf("reqbodyProcessor = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProcessBodiesSkippedIfHeadersPhasesNotReached(t *testing.T) {
	logBuffer := &bytes.Buffer{}
	waf := NewWAF()
	waf.SetDebugLogOutput(logBuffer)
	_ = waf.SetDebugLogLevel(debuglog.LevelDebug)
	tx := waf.NewTransaction()
	tx.RuleEngine = types.RuleEngineOn
	tx.RequestBodyAccess = true
	// Current phase is PhaseUnknown (ProcessRequestHeaders has not been called)
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatal(err)
	}
	if it != nil {
		t.Fatal("Unexpected interruption")
	}
	it, err = tx.ProcessResponseBody()
	if err != nil {
		t.Fatal(err)
	}
	if it != nil {
		t.Fatal("Unexpected interruption")
	}
	logEntries := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
	// At this point we are expecting three log entries:
	// [0] New transaction log
	// [1] Anomalous call before request headers evaluation
	// [2] Anomalous call before response headers evaluation
	if want, have := 3, len(logEntries); want != have {
		t.Fatalf("unexpected number of log entries, want %d, have %d", want, have)
	}
	if want, have := "has been called before request headers evaluation", logEntries[1]; !strings.Contains(have, want) {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}
	if want, have := "has been called before response headers evaluation", logEntries[2]; !strings.Contains(have, want) {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxVariables(t *testing.T) {
	tx := makeTransaction(t)
	rv := ruleVariableParams{
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
	}
	if len(tx.GetField(rv)) != 1 || tx.GetField(rv)[0].Value() != "www.test.com:80" {
		t.Fatalf("failed to match rule variable REQUEST_HEADERS:host, %d matches, %v", len(tx.GetField(rv)), tx.GetField(rv))
	}
	rv.Count = true
	if len(tx.GetField(rv)) == 0 || tx.GetField(rv)[0].Value() != "1" {
		t.Fatalf("failed to get count for regexp variable")
	}
	// now nil key
	rv.KeyRx = nil
	if len(tx.GetField(rv)) == 0 {
		t.Fatal("failed to match rule variable REQUEST_HEADERS with nil key")
	}
	rv.KeyStr = ""
	f := tx.GetField(rv)
	if len(f) == 0 {
		t.Fatal("failed to count variable REQUEST_HEADERS ")
	}
	count, err := strconv.Atoi(f[0].Value())
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("failed to match rule variable REQUEST_HEADERS with count, %v", rv)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTxVariablesExceptions(t *testing.T) {
	tx := makeTransaction(t)
	rv := ruleVariableParams{
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
		Exceptions: []ruleVariableException{
			{KeyStr: "host"},
		},
	}
	fields := tx.GetField(rv)
	if len(fields) != 0 {
		t.Fatalf("REQUEST_HEADERS:host should not match, got %d matches, %v", len(fields), fields)
	}
	rv.Exceptions = nil
	fields = tx.GetField(rv)
	if len(fields) != 1 || fields[0].Value() != "www.test.com:80" {
		t.Fatalf("failed to match rule variable REQUEST_HEADERS:host, %d matches, %v", len(fields), fields)
	}
	rv.Exceptions = []ruleVariableException{
		{
			KeyRx: regexp.MustCompile("ho.*"),
		},
	}
	fields = tx.GetField(rv)
	if len(fields) != 0 {
		t.Fatalf("REQUEST_HEADERS:host should not match, got %d matches, %v", len(fields), fields)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionSyncPool(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.matchedRules = append(tx.matchedRules, &corazarules.MatchedRule{
		Rule_: &corazarules.RuleMetadata{
			ID_: 1234,
		},
	})
	for i := range 1000 {
		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}
		tx = waf.NewTransaction()
		if len(tx.matchedRules) != 0 {
			t.Fatalf("failed to sync transaction pool, %d rules found after %d attempts", len(tx.matchedRules), i+1)
			return
		}
	}
}

func TestTxPhase4Magic(t *testing.T) {
	waf := NewWAF()
	waf.ResponseBodyAccess = true
	waf.ResponseBodyLimit = 3
	waf.ResponseBodyLimitAction = types.BodyLimitActionProcessPartial
	waf.ResponseBodyMimeTypes = []string{"text/html"}
	tx := waf.NewTransaction()
	tx.AddResponseHeader("content-type", "text/html")
	tx.ProcessRequestHeaders()
	_, _ = tx.ProcessRequestBody()
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if it, _, err := tx.WriteResponseBody([]byte("more bytes")); it != nil || err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal(err)
	}
	if tx.variables.outboundDataError.Get() != "1" {
		t.Fatal("failed to set outbound data error")
	}
	if tx.variables.responseBody.Get() != "mor" {
		t.Fatal("failed to set response body")
	}
}

func TestCollectionReturnsExpectedTypes(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()

	// Dynamically iterate over all possible RuleVariable values so this test
	// stays in sync when new variables are added.
	for i := range 256 {
		v := variables.RuleVariable(i)
		name := v.Name()

		if name == "UNKNOWN" || name == "INVALID_VARIABLE" {
			continue
		}

		c := tx.Collection(v)

		// JSON is explicitly unimplemented (returns nil).
		if v == variables.JSON {
			if c != nil {
				t.Errorf("Collection(%s) should return nil, got %v", name, c)
			}
			continue
		}

		// Variables that exist in the variables package but are not backed by
		// a collection in Transaction.Collection() fall through to the default
		// Noop case. We just verify they don't panic.
		if c == nil {
			t.Errorf("Collection(%s) returned nil, expected non-nil collection", name)
		}
	}
}

func TestVariablesMatch(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.matchVariable(&corazarules.MatchData{
		Variable_: variables.ArgsNames,
		Key_:      "sample",
		Value_:    "samplevalue",
	})
	expect := map[variables.RuleVariable]string{
		variables.MatchedVar:     "samplevalue",
		variables.MatchedVarName: "ARGS_NAMES:sample",
	}

	for k, v := range expect {
		if m := (tx.Collection(k)).(*collections.Single).Get(); m != v {
			t.Fatalf("failed to match variable %s, Expected: %s, got: %s", k.Name(), v, m)
		}
	}

	if len(tx.variables.matchedVars.Get("ARGS_NAMES:sample")) == 0 {
		t.Fatalf("failed to match variable %s, got 0", variables.MatchedVars.Name())
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxReqBodyForce(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	if _, err := tx.requestBodyBuffer.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if tx.variables.requestBody.Get() != "test" {
		t.Fatal("failed to set request body")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxReqBodyForceNegative(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = false
	if _, err := tx.requestBodyBuffer.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if tx.variables.requestBody.Get() == "test" {
		t.Fatal("reqbody should not be there")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxProcessConnection(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.2", 8080)
	if tx.variables.remoteAddr.Get() != "127.0.0.1" {
		t.Fatal("failed to set client ip")
	}
	if rp, _ := strconv.Atoi(tx.variables.remotePort.Get()); rp != 80 {
		t.Fatal("failed to set client port")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxSetServerName(t *testing.T) {
	logBuffer := &bytes.Buffer{}

	waf := NewWAF()
	waf.SetDebugLogOutput(logBuffer)
	_ = waf.SetDebugLogLevel(debuglog.LevelWarn)

	tx := waf.NewTransaction()
	tx.lastPhase = types.PhaseRequestHeaders
	tx.SetServerName("coraza.io")
	if tx.variables.serverName.Get() != "coraza.io" {
		t.Fatal("failed to set server name")
	}
	logEntries := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
	if want, have := 1, len(logEntries); want != have {
		t.Fatalf("unexpected number of log entries, want %d, have %d", want, have)
	}

	if want, have := "SetServerName has been called after ProcessRequestHeaders", logEntries[0]; !strings.Contains(have, want) {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxAddArgument(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.2", 8080)
	tx.AddGetRequestArgument("test", "testvalue")
	if tx.variables.argsGet.Get("test")[0] != "testvalue" {
		t.Fatal("failed to set args get")
	}
	tx.AddPostRequestArgument("ptest", "ptestvalue")
	if tx.variables.argsPost.Get("ptest")[0] != "ptestvalue" {
		t.Fatal("failed to set args post")
	}
	tx.AddPathRequestArgument("ptest2", "ptestvalue")
	if tx.variables.argsPath.Get("ptest2")[0] != "ptestvalue" {
		t.Fatal("failed to set args post")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxGetField(t *testing.T) {
	tx := makeTransaction(t)
	rvp := ruleVariableParams{
		Variable: variables.Args,
	}
	if f := tx.GetField(rvp); len(f) != 3 {
		t.Fatalf("failed to get field, expected 2, got %d", len(f))
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func BenchmarkTxGetField(b *testing.B) {
	tx := makeTransaction(b)
	rvp := ruleVariableParams{
		Variable: variables.Args,
	}
	for b.Loop() {
		tx.GetField(rvp)
	}
	if err := tx.Close(); err != nil {
		b.Fatalf("Failed to close transaction: %s", err.Error())
	}
	b.ReportAllocs()
}

// makeTransactionWithJSONArgs creates a transaction that includes JSON-array-style
// GET arguments (json.0.field … json.9.field) on top of the standard args.
// This simulates the real-world pattern that motivates regex key exceptions.
func makeTransactionWithJSONArgs(t testing.TB) *Transaction {
	t.Helper()
	tx := makeTransaction(t)
	for i := 0; i < 10; i++ {
		tx.AddGetRequestArgument(fmt.Sprintf("json.%d.jobdescription", i), "value")
	}
	return tx
}

// BenchmarkTxGetFieldWithShortRegexException measures the overhead of GetField
// when a short regex exception (e.g. ^id$) is applied against the args collection.
func BenchmarkTxGetFieldWithShortRegexException(b *testing.B) {
	tx := makeTransactionWithJSONArgs(b)
	rvp := ruleVariableParams{
		Variable: variables.Args,
		Exceptions: []ruleVariableException{
			{KeyRx: regexp.MustCompile(`^id$`)},
		},
	}
	b.ReportAllocs()

	for b.Loop() {
		tx.GetField(rvp)
	}
	b.StopTimer()
	if err := tx.Close(); err != nil {
		b.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// BenchmarkTxGetFieldWithMediumRegexException measures the overhead of GetField
// when a medium-complexity regex exception (e.g. ^json\.\d+\.jobdescription$) is
// applied — the typical pattern used in URI-scoped CRS exclusions.
func BenchmarkTxGetFieldWithMediumRegexException(b *testing.B) {
	tx := makeTransactionWithJSONArgs(b)
	rvp := ruleVariableParams{
		Variable: variables.Args,
		Exceptions: []ruleVariableException{
			{KeyRx: regexp.MustCompile(`^json\.\d+\.jobdescription$`)},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx.GetField(rvp)
	}
	b.StopTimer()
	if err := tx.Close(); err != nil {
		b.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxProcessURI(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	uri := "http://example.com/path/to/file.html?query=string&other=value"
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	if s := tx.variables.requestURI.Get(); s != uri {
		t.Fatalf("failed to set request uri, got %s", s)
	}
	if s := tx.variables.requestBasename.Get(); s != "file.html" {
		t.Fatalf("failed to set request path, got %s", s)
	}
	if tx.variables.queryString.Get() != "query=string&other=value" {
		t.Fatal("failed to set request query")
	}
	if v := tx.variables.args.FindAll(); len(v) != 2 {
		t.Fatalf("failed to set request args, got %d", len(v))
	}
	if v := tx.variables.args.FindString("other"); v[0].Value() != "value" {
		t.Fatalf("failed to set request args, got %v", v)
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func BenchmarkTransactionCreation(b *testing.B) {
	for b.Loop() {
		makeTransaction(b)
	}
}

func makeTransaction(t testing.TB) *Transaction {
	t.Helper()
	tx := NewWAF().NewTransaction()
	tx.RequestBodyAccess = true
	ht := []string{
		"POST /testurl.php?id=123&b=456 HTTP/1.1",
		"Host: www.test.com:80",
		"Cookie: test=123",
		"Content-Type: application/x-www-form-urlencoded",
		"X-Test-Header: test456",
		"Content-Length: 13",
		"",
		"testfield=456",
	}
	data := strings.Join(ht, "\r\n")
	_, err := tx.ParseRequestReader(strings.NewReader(data))
	if err != nil {
		panic(err)
	}
	return tx
}

func makeTransactionTimestamped(t testing.TB) *Transaction {
	t.Helper()
	tx := NewWAF().NewTransaction()
	timestamp, err := time.ParseInLocation(time.DateTime, "2024-11-18 15:27:34", time.Local)
	if err != nil {
		panic(err)
	}
	tx.Timestamp = timestamp.UnixNano()
	tx.setTimeVariables()
	return tx
}

func BenchmarkTransactionTimestamped(b *testing.B) {
	tx := NewWAF().NewTransaction()
	tx.Timestamp = time.Now().Unix()

	for b.Loop() {
		tx.setTimeVariables()
	}
}

func makeTransactionMultipart(t *testing.T) *Transaction {
	if t != nil {
		t.Helper()
	}
	tx := NewWAF().NewTransaction()
	tx.RequestBodyAccess = true
	ht := []string{
		"POST /testurl.php?id=123&b=456 HTTP/1.1",
		"Host: www.test.com:80",
		"Cookie: test=123",
		"Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		"X-Test-Header: test456",
		"Content-Length: 545",
		"",
		`-----------------------------9051914041544843365972754266`,
		`Content-Disposition: form-data; name="testfield"`,
		``,
		`456`,
		`-----------------------------9051914041544843365972754266`,
		`Content-Disposition: form-data; name="file1"; filename="a.txt"`,
		`Content-Type: text/plain`,
		``,
		`Content of a.txt.`,
		``,
		`-----------------------------9051914041544843365972754266`,
		`Content-Disposition: form-data; name="file2"; filename="a.html"`,
		`Content-Type: text/html`,
		``,
		`<!DOCTYPE html><title>Content of a.html.</title>`,
		``,
		`-----------------------------9051914041544843365972754266--`,
	}
	data := strings.Join(ht, "\r\n")
	_, err := tx.ParseRequestReader(strings.NewReader(data))
	if err != nil {
		panic(err)
	}
	return tx
}

func validateMacroExpansion(tests map[string]string, tx *Transaction, t *testing.T) {
	for k, v := range tests {
		m, err := macro.NewMacro(k)
		if err != nil {
			t.Fatal(err)
		}
		res := m.Expand(tx)
		if res != v {
			if testing.Verbose() {
				fmt.Println(tx)
				fmt.Println("===STACK===\n", string(debug.Stack())+"\n===STACK===")
			}
			t.Fatal("Failed set transaction for " + k + ", expected " + v + ", got " + res)
		}
	}
}

func TestMacro(t *testing.T) {
	tx := makeTransaction(t)
	tx.variables.tx.Set("some", []string{"secretly"})
	m, err := macro.NewMacro("%{unique_id}")
	if err != nil {
		t.Fatal(err)
	}
	if m.Expand(tx) != tx.id {
		t.Fatalf("%s != %s", m.Expand(tx), tx.id)
	}
	m, err = macro.NewMacro("some complex text %{tx.some} wrapped in m")
	if err != nil {
		t.Fatal(err)
	}
	if m.Expand(tx) != "some complex text secretly wrapped in m" {
		t.Fatalf("failed to expand m, got %s\n%v", m.Expand(tx), m)
	}

	_, err = macro.NewMacro("some complex text %{tx.some} wrapped in m %{tx.some}")
	if err != nil {
		t.Fatal(err)
		return
	}
	// TODO(anuraaga): Decouple this test from transaction implementation.
	// if !macro.IsExpandable() || len(macro.tokens) != 4 || macro.Expand(tx) != "some complex text secretly wrapped in m secretly" {
	//   t.Fatalf("failed to parse replacements %v", macro.tokens)
	// }

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func BenchmarkMacro(b *testing.B) {
	tests := []string{
		"%{tx.a}",
		"%{tx.a} %{tx.b}",
		"goodbye world",
	}

	tx := makeTransaction(b)
	tx.variables.tx.Set("a", []string{"hello"})
	tx.variables.tx.Set("b", []string{"world"})

	for _, tc := range tests {
		m, err := macro.NewMacro(tc)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				m.Expand(tx)
			}
		})
	}
}

func TestProcessorsIdempotencyWithAlreadyRaisedInterruption(t *testing.T) {
	logBuffer := &bytes.Buffer{}

	waf := NewWAF()
	waf.SetDebugLogOutput(logBuffer)
	_ = waf.SetDebugLogLevel(debuglog.LevelError)

	expectedInterruption := &types.Interruption{
		RuleID: 123,
	}

	tx := waf.NewTransaction()
	tx.interruption = expectedInterruption

	testCases := map[string]func(tx *Transaction) *types.Interruption{
		"ProcessRequestHeaders": func(tx *Transaction) *types.Interruption {
			return tx.ProcessRequestHeaders()
		},
		"ProcessRequestBody": func(tx *Transaction) *types.Interruption {
			it, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatal("unexpected error when processing request body")
			}
			return it
		},
		"ProcessResponseHeaders": func(tx *Transaction) *types.Interruption {
			return tx.ProcessResponseHeaders(200, "HTTP/1")
		},
		"ProcessResponseBody": func(tx *Transaction) *types.Interruption {
			it, err := tx.ProcessResponseBody()
			if err != nil {
				t.Fatal("unexpected error when processing response body")
			}
			return it
		},
	}

	for processor, tCase := range testCases {
		t.Run(processor, func(t *testing.T) {
			logBuffer.Reset()

			it := tCase(tx)
			if it == nil {
				t.Fatal("expected interruption")
			}

			if it != expectedInterruption {
				t.Fatal("unexpected interruption")
			}

			logEntries := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
			if want, have := 1, len(logEntries); want != have {
				t.Fatalf("unexpected number of log entries, want %d, have %d", want, have)
			}

			expectedMessage := fmt.Sprintf("Calling %s but there is a preexisting interruption", processor)

			if want, have := expectedMessage, logEntries[0]; !strings.Contains(have, want) {
				t.Fatalf("unexpected message, want to contain %q in %q", want, have)
			}
		})
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestIterationStops(t *testing.T) {
	// This is a valid test of iteration mechanics but is really overkill. We mostly do it for
	// code coverage.

	waf := NewWAF()
	tx := waf.NewTransaction()

	// Order doesn't matter, iterate once without stopping to know the order
	var allVars []variables.RuleVariable
	tx.Variables().All(func(v variables.RuleVariable, _ collection.Collection) bool {
		allVars = append(allVars, v)
		return true
	})

	for i, stopV := range allVars {
		t.Run(stopV.Name(), func(t *testing.T) {
			var haveVars []variables.RuleVariable
			tx.Variables().All(func(v variables.RuleVariable, _ collection.Collection) bool {
				haveVars = append(haveVars, v)
				return v != stopV
			})

			if want, have := i+1, len(haveVars); want != have {
				t.Fatalf("stopped with unexpected number of variables, want %d, have %d", want, have)
			}

			for j, v := range haveVars {
				if want, have := allVars[j], v; want != have {
					t.Fatalf("unexpected variable at index %d, want %s, have %s", j, want.Name(), have.Name())
				}
			}
		})
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxAddResponseArgs(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.AddResponseArgument("samplekey", "samplevalue")
	if tx.variables.responseArgs.Get("samplekey")[0] != "samplevalue" {
		t.Fatalf("failed to add response argument")
	}
}

func TestAddGetArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddGetRequestArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.argsGet.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add get args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

func TestAddPostArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddPostRequestArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.argsPost.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add post args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

func TestAddPathArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddPathRequestArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.argsPath.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add path args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

func TestAddResponseArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddResponseArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.responseArgs.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add response args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

// TestAddArgsRepeatedKeyOverlimit is a regression test for
// GHSA-3ww9-vw83-9w5x: checkArgumentLimit used to compare against Len (the
// number of distinct keys), so many values added under a single repeated key
// never tripped the limit no matter how many times Add was called. It must
// now be bounded by TotalValues (every individual value) instead.
func TestAddArgsRepeatedKeyOverlimit(t *testing.T) {
	const limit = 5
	const attempts = 1000

	adders := map[string]func(tx *Transaction, key, value string){
		"get":      func(tx *Transaction, key, value string) { tx.AddGetRequestArgument(key, value) },
		"post":     func(tx *Transaction, key, value string) { tx.AddPostRequestArgument(key, value) },
		"path":     func(tx *Transaction, key, value string) { tx.AddPathRequestArgument(key, value) },
		"response": func(tx *Transaction, key, value string) { tx.AddResponseArgument(key, value) },
	}

	for name, add := range adders {
		t.Run(name, func(t *testing.T) {
			waf := NewWAF()
			tx := waf.NewTransaction()
			tx.WAF.ArgumentLimit = limit
			for i := 0; i < attempts; i++ {
				add(tx, "repeated", "samplevalue")
			}

			var total int
			switch name {
			case "get":
				total = tx.variables.argsGet.TotalValues()
			case "post":
				total = tx.variables.argsPost.TotalValues()
			case "path":
				total = tx.variables.argsPath.TotalValues()
			case "response":
				total = tx.variables.responseArgs.TotalValues()
			}
			if total > limit {
				t.Fatalf("expected at most %d total values under a repeated key, got %d", limit, total)
			}

			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}
}

// TestExtractGetArgumentsRepeatedKeyOverlimit confirms ExtractGetArguments
// (the query-string entry point, as opposed to calling AddGetRequestArgument
// directly) is bounded the same way, and sets ARGUMENTS_LIMIT_REACHED.
func TestExtractGetArgumentsRepeatedKeyOverlimit(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.WAF.ArgumentLimit = 5

	uri := "/x?" + strings.TrimSuffix(strings.Repeat("a=1&", 1000), "&")
	tx.ExtractGetArguments(uri)

	if got := tx.variables.argsGet.TotalValues(); got > 5 {
		t.Fatalf("expected at most 5 total ARGS_GET values, got %d", got)
	}
	if tx.variables.argumentsLimitReached.Get() != "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be set")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestResponseBodyForceProcessing(t *testing.T) {
	waf := NewWAF()
	waf.ResponseBodyAccess = true
	tx := waf.NewTransaction()
	tx.ForceResponseBodyVariable = true
	tx.variables.ResponseBodyProcessor().(*collections.Single).Set("JSON")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, _, err := tx.WriteResponseBody([]byte(`{"key":"value"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal(err)
	}
	f := tx.variables.responseArgs.FindString("json.key")
	if len(f) == 0 {
		t.Fatal("json.key not found")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestForceRequestBodyOverride(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	tx := waf.NewTransaction()
	tx.ForceRequestBodyVariable = true
	tx.variables.RequestBodyProcessor().(*collections.Single).Set("JSON")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("foo=bar&baz=qux")); err != nil {
		t.Fatalf("Failed to write request body: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("Failed to process request body: %v", err)
	}
	if tx.variables.RequestBodyProcessor().Get() != "JSON" {
		t.Fatalf("Failed to force request body variable")
	}
	tx = waf.NewTransaction()
	tx.ForceRequestBodyVariable = true
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("foo=bar&baz=qux")); err != nil {
		t.Fatalf("Failed to write request body: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("Failed to process request body: %v", err)
	}
	if tx.variables.RequestBodyProcessor().Get() != "URLENCODED" {
		t.Fatalf("Failed to force request body variable, got RBP: %q", tx.variables.RequestBodyProcessor().Get())
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestCloseFails(t *testing.T) {
	if !environment.HasAccessToFS {
		t.Skip("skipping test as it requires access to filesystem")
	}
	waf := NewWAF()
	tx := waf.NewTransaction()
	col := tx.Variables().FilesTmpNames().(*collections.Map)
	col.Add("", "unexisting")
	err := tx.Close()
	if err == nil {
		t.Fatalf("expected error when closing transaction")
	}

	if !strings.Contains(err.Error(), "removing temporary file") {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}

func TestUploadKeepFiles(t *testing.T) {
	if !environment.HasAccessToFS {
		t.Skip("skipping test as it requires access to filesystem")
	}

	createTmpFile := func(t *testing.T) string {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "crztest*")
		if err != nil {
			t.Fatal(err)
		}
		name := f.Name()
		if err := f.Close(); err != nil {
			t.Fatalf("failed to close temp file: %v", err)
		}
		return name
	}

	t.Run("Off deletes files", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesOff
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatal("expected temp file to be deleted when UploadKeepFiles is Off")
		}
	})

	t.Run("On keeps files", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesOn
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); err != nil {
			t.Fatal("expected temp file to be kept when UploadKeepFiles is On")
		}
	})

	t.Run("RelevantOnly keeps files when log rules matched", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		// Simulate a matched rule with Log enabled
		tx.matchedRules = append(tx.matchedRules, &corazarules.MatchedRule{Log_: true})

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); err != nil {
			t.Fatal("expected temp file to be kept when UploadKeepFiles is RelevantOnly and log rules matched")
		}
	})

	t.Run("RelevantOnly deletes files when only nolog rules matched", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		// Simulate a matched rule with Log disabled (e.g. CRS initialization rules)
		tx.matchedRules = append(tx.matchedRules, &corazarules.MatchedRule{Log_: false})

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatal("expected temp file to be deleted when UploadKeepFiles is RelevantOnly and only nolog rules matched")
		}
	})

	t.Run("RelevantOnly deletes files when no rules matched", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatal("expected temp file to be deleted when UploadKeepFiles is RelevantOnly and no rules matched")
		}
	})
}

func TestRequestFilename(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "simple",
			uri:      "/foo",
			expected: "/foo",
		},
		{
			name:     "with query",
			uri:      "/foo?bar=baz",
			expected: "/foo",
		},
		{
			name:     "with query and fragment",
			uri:      "/foo?bar=baz#qux",
			expected: "/foo",
		},
		{
			name:     "subdirectory",
			uri:      "/foo/bar",
			expected: "/foo/bar",
		},
		{
			name:     "subdirectory with query",
			uri:      "/foo/bar?baz=qux",
			expected: "/foo/bar",
		},
		{
			name:     "multiple leading slashes",
			uri:      "//foo/bar",
			expected: "//foo/bar",
		},
		{
			name:     "multiple leading slashes - 2",
			uri:      "///foo/bar",
			expected: "///foo/bar",
		},
		{ // url.ParseRequestURI fails on invalid percent-encoding; the "?" fallback
			// split still recovers the path/query boundary. See GHSA-x26q-wvhg-fh4m.
			name:     "invalid encoding",
			uri:      "/foo%zz?a=b",
			expected: "/foo%zz",
		},
		{
			name:     "valid encoding",
			uri:      "/foo%20bar",
			expected: "/foo bar",
		},
		{
			name:     "trailing slash",
			uri:      "/foo/bar/",
			expected: "/foo/bar/",
		},
		{
			name:     "duplicated slashes",
			uri:      "//foo//bar",
			expected: "//foo//bar",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			waf := NewWAF()
			tx := waf.NewTransaction()
			tx.ProcessURI(test.uri, http.MethodGet, "HTTP/1.1")
			if tx.variables.requestFilename.Get() != test.expected {
				t.Fatalf("Expected REQUEST_FILENAME %q, got %q", test.expected, tx.variables.requestFilename.Get())
			}
		})
	}
}

// GHSA-x26q-wvhg-fh4m: a URI containing raw control bytes (e.g. a NUL, as a
// non-net/http integration like coraza-spoa or coraza-proxy-wasm might forward)
// fails url.ParseRequestURI, and previously left QUERY_STRING/ARGS_GET empty,
// silently dropping the entire attack payload from GET-side rule matching.
func TestProcessURIFallbackOnParseError(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessURI("/search?q=ATTACK_HERE_XYZ\x00&y=1", http.MethodGet, "HTTP/1.1")

	if got := tx.variables.uriParseError.Get(); got != "1" {
		t.Errorf("Expected URI_PARSE_ERROR to be \"1\", got %q", got)
	}
	if got := tx.variables.queryString.Get(); got != "q=ATTACK_HERE_XYZ\x00&y=1" {
		t.Errorf("Expected QUERY_STRING to be recovered from the raw URI, got %q", got)
	}
	if got := tx.variables.argsGet.Get("q"); len(got) == 0 || got[0] != "ATTACK_HERE_XYZ\x00" {
		t.Errorf("Expected ARGS_GET q to be populated on best effort, got %v", got)
	}
	if got := tx.variables.requestURIRaw.Get(); got != "/search?q=ATTACK_HERE_XYZ\x00&y=1" {
		t.Errorf("Expected REQUEST_URI_RAW to hold the untouched URI, got %q", got)
	}
}

func BenchmarkRuleEvalWithTransformations(b *testing.B) {
	waf := NewWAF()
	op, err := operators.Get("unconditionalMatch", plugintypes.OperatorOptions{})
	if err != nil {
		b.Fatal(err)
	}
	lowercaseFn, err := transformations.GetTransformation("lowercase")
	if err != nil {
		b.Fatal(err)
	}

	rule := NewRule()
	rule.ID_ = 1000
	rule.LogID_ = "1000"
	rule.Phase_ = types.PhaseRequestHeaders
	rule.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	if err := rule.AddTransformation("lowercase", lowercaseFn); err != nil {
		b.Fatal(err)
	}
	rule.variables = append(rule.variables, ruleVariableParams{
		Variable: variables.Args,
	})
	if err := waf.Rules.Add(rule); err != nil {
		b.Fatal(err)
	}

	tx := waf.NewTransaction()
	b.Cleanup(func() {
		if err := tx.Close(); err != nil {
			b.Fatalf("failed to close transaction: %v", err)
		}
	})
	tx.ProcessURI("/test?a=1&b=2&c=3&d=4&e=5", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	if it := tx.ProcessRequestHeaders(); it != nil {
		b.Fatalf("unexpected interruption during request headers processing: %+v", it)
	}
	b.ReportAllocs()

	for b.Loop() {
		waf.Rules.Eval(types.PhaseRequestHeaders, tx)
	}
}

func newTestUnconditionalMatch(t testing.TB) plugintypes.Operator {
	t.Helper()
	op, err := operators.Get("unconditionalMatch", plugintypes.OperatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestRemoveRuleByID(t *testing.T) {
	waf := NewWAF()
	op := newTestUnconditionalMatch(t)

	// Add two rules with different IDs
	rule1 := NewRule()
	rule1.ID_ = 100
	rule1.LogID_ = "100"
	rule1.Phase_ = types.PhaseRequestHeaders
	rule1.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	rule1.Log = true
	if err := waf.Rules.Add(rule1); err != nil {
		t.Fatal(err)
	}

	rule2 := NewRule()
	rule2.ID_ = 200
	rule2.LogID_ = "200"
	rule2.Phase_ = types.PhaseRequestHeaders
	rule2.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	rule2.Log = true
	if err := waf.Rules.Add(rule2); err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	// Remove rule 100
	tx.RemoveRuleByID(100)

	// Verify the map was lazily initialized
	if tx.ruleRemoveByID == nil {
		t.Fatal("ruleRemoveByID should not be nil after RemoveRuleByID")
	}

	// Remove another rule
	tx.RemoveRuleByID(100) // duplicate removal should be idempotent
	tx.RemoveRuleByID(200)

	if len(tx.ruleRemoveByID) != 2 {
		t.Errorf("expected 2 entries in ruleRemoveByID map, got %d", len(tx.ruleRemoveByID))
	}
}

func TestRemoveRuleByIDRange(t *testing.T) {
	waf := NewWAF()

	// Use nil-operator rules (SecAction-style): they always match regardless of variables.
	for _, id := range []int{100, 150, 200, 300} {
		r := NewRule()
		r.ID_ = id
		r.LogID_ = strconv.Itoa(id)
		r.Phase_ = types.PhaseRequestHeaders
		// nil operator means the rule always matches
		if err := waf.Rules.Add(r); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("range is stored", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.RemoveRuleByIDRange(100, 200)
		if len(tx.ruleRemoveByIDRanges) != 1 {
			t.Fatalf("expected 1 range entry, got %d", len(tx.ruleRemoveByIDRanges))
		}
		if tx.ruleRemoveByIDRanges[0][0] != 100 || tx.ruleRemoveByIDRanges[0][1] != 200 {
			t.Errorf("unexpected range: %v", tx.ruleRemoveByIDRanges[0])
		}
	})

	t.Run("rules in range are skipped during eval", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		// Remove rules with IDs 100-200; rule 300 should still be evaluated.
		tx.RemoveRuleByIDRange(100, 200)
		waf.Rules.Eval(types.PhaseRequestHeaders, tx)

		matchedIDs := make(map[int]bool)
		for _, mr := range tx.MatchedRules() {
			matchedIDs[mr.Rule().ID()] = true
		}

		for _, skipped := range []int{100, 150, 200} {
			if matchedIDs[skipped] {
				t.Errorf("rule %d should have been skipped but was matched", skipped)
			}
		}
		if !matchedIDs[300] {
			t.Errorf("rule 300 should have been matched but was not")
		}
	})

	t.Run("multiple ranges", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.RemoveRuleByIDRange(100, 100)
		tx.RemoveRuleByIDRange(300, 300)
		if len(tx.ruleRemoveByIDRanges) != 2 {
			t.Fatalf("expected 2 range entries, got %d", len(tx.ruleRemoveByIDRanges))
		}

		waf.Rules.Eval(types.PhaseRequestHeaders, tx)

		matchedIDs := make(map[int]bool)
		for _, mr := range tx.MatchedRules() {
			matchedIDs[mr.Rule().ID()] = true
		}
		if matchedIDs[100] {
			t.Error("rule 100 should have been skipped")
		}
		if matchedIDs[300] {
			t.Error("rule 300 should have been skipped")
		}
		if !matchedIDs[150] {
			t.Error("rule 150 should have been matched")
		}
		if !matchedIDs[200] {
			t.Error("rule 200 should have been matched")
		}
	})

	t.Run("range reset on transaction reuse", func(t *testing.T) {
		tx := waf.NewTransaction()
		tx.RemoveRuleByIDRange(100, 200)
		tx.Close()

		// Get a new transaction (pool reuse may return the same object)
		tx2 := waf.NewTransaction()
		defer tx2.Close()

		if len(tx2.ruleRemoveByIDRanges) != 0 {
			t.Errorf("expected ruleRemoveByIDRanges to be reset, got %d entries", len(tx2.ruleRemoveByIDRanges))
		}
	})
}

func BenchmarkRuleEvalWithRemovedRules(b *testing.B) {
	waf := NewWAF()
	op := newTestUnconditionalMatch(b)

	rule := NewRule()
	rule.ID_ = 1000
	rule.LogID_ = "1000"
	rule.Phase_ = types.PhaseRequestHeaders
	rule.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	if err := waf.Rules.Add(rule); err != nil {
		b.Fatal(err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	for i := 1; i <= 100; i++ {
		tx.RemoveRuleByID(i)
	}

	b.ReportAllocs()

	for b.Loop() {
		waf.Rules.Eval(types.PhaseRequestHeaders, tx)
	}
}
