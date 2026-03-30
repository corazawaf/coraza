// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestWriteHeader(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()
	rw, responseProcessor := wrap(res, req, tx)
	rw.WriteHeader(204)
	rw.WriteHeader(205)
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 204, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// although we called a second time with 205, status code should remain the first
	// value.
	if want, have := 204, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestWrite(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	rw, responseProcessor := wrap(res, req, tx)
	_, err = rw.Write([]byte("hello"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = rw.Write([]byte("world"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 200, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestWriteWithWriteHeader(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	rw, responseProcessor := wrap(res, req, tx)
	rw.WriteHeader(201)
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 201, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	_, err = rw.Write([]byte("hello"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = rw.Write([]byte("world"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 201, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestFlush(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("WriteHeader before Flush", func(t *testing.T) {
		tx := waf.NewTransaction()
		req, _ := http.NewRequest("GET", "", nil)
		res := httptest.NewRecorder()
		rw, responseProcessor := wrap(res, req, tx)
		rw.WriteHeader(204)
		rw.(http.Flusher).Flush()
		// although we called WriteHeader, status code should be applied until
		// responseProcessor is called.
		if unwanted, have := 204, res.Code; unwanted == have {
			t.Errorf("unexpected status code %d", have)
		}

		err = responseProcessor(tx, req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if want, have := 204, res.Code; want != have {
			t.Errorf("unexpected status code, want %d, have %d", want, have)
		}
	})

	t.Run("Flush before WriteHeader", func(t *testing.T) {
		tx := waf.NewTransaction()
		req, _ := http.NewRequest("GET", "", nil)
		res := httptest.NewRecorder()
		rw, responseProcessor := wrap(res, req, tx)
		rw.(http.Flusher).Flush()
		rw.WriteHeader(204)

		if want, have := 200, res.Code; want != have {
			t.Errorf("unexpected status code, want %d, have %d", want, have)
		}

		err = responseProcessor(tx, req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if want, have := 200, res.Code; want != have {
			t.Errorf("unexpected status code, want %d, have %d", want, have)
		}
	})
}

type testReaderFrom struct {
	io.Writer
}

func (x *testReaderFrom) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(x, r)
}

func TestReadFrom(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	type responseWriter interface {
		http.ResponseWriter
		http.Flusher
	}

	resWithReaderFrom := struct {
		responseWriter
		io.ReaderFrom
	}{
		res,
		&testReaderFrom{res},
	}

	rw, responseProcessor := wrap(resWithReaderFrom, req, tx)
	rw.WriteHeader(201)
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 201, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	_, err = rw.(io.ReaderFrom).ReadFrom(bytes.NewBuffer([]byte("hello world")))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = rw.(io.ReaderFrom).ReadFrom(struct{ io.Reader }{bytes.NewBuffer([]byte("hello world"))})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 201, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

type testPusher struct{}

func (x *testPusher) Push(string, *http.PushOptions) error {
	return nil
}

type testHijacker struct{}

func (x *testHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

func TestInterface(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	t.Run("default", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
		}{
			res,
		}, req, tx)

		_, ok := rw.(http.Pusher)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Pusher")
		}

		_, ok = rw.(http.Hijacker)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Hijacker")
		}
	})

	t.Run("http.Pusher", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
			http.Pusher
		}{
			res,
			&testPusher{},
		}, req, tx)

		_, ok := rw.(http.Pusher)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Pusher")
		}

		_, ok = rw.(http.Hijacker)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Hijacker")
		}
	})

	t.Run("http.Hijacker", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
			http.Hijacker
		}{
			res,
			&testHijacker{},
		}, req, tx)

		_, ok := rw.(http.Hijacker)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Hijacker")
		}

		_, ok = rw.(http.Pusher)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Pusher")
		}
	})

	t.Run("http.Hijacker and http.Pusher", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
		}{
			res,
			&testHijacker{},
			&testPusher{},
		}, req, tx)

		_, ok := rw.(http.Hijacker)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Hijacker")
		}

		_, ok = rw.(http.Pusher)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Pusher")
		}
	})
}

func TestResponseBody(t *testing.T) {
	const (
		contentWithoutDataLeak    = "No data leak"
		contentWithDataLeak       = "data leak: SQL Error!!"
		limitActionReject         = "Reject"
		limitActionProcessPartial = "ProcessPartial"
	)
	testCases := []struct {
		name                      string
		content                   string
		responseBodyRelativeLimit int
		responseBodyLimitAction   string
		expectedStatusCode        int
	}{
		{
			name:                      "OneByteLongerThanLimitAndRejects",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: -1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusInternalServerError, // used to be StatusRequestEntityTooLarge, see https://github.com/corazawaf/coraza/pull/1379
		},
		{
			name:                      "JustEqualToLimitAndAccepts",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: 0,
			responseBodyLimitAction:   limitActionReject,
			// NOTE: According to https://coraza.io/docs/seclang/directives/#secresponsebodylimit
			// expectedStatusCode should be http.StatusOK, but actually it is http.StatusInternalServerError.
			// Coraza should be fixed.
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name:                      "OneByteShorterThanLimitAndAccepts",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: 1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusOK,
		},
		{
			name:                      "DataLeakAndRejects",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: 1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusForbidden,
		},
		{
			name:                      "LimitReachedNoDataLeakPartialProcessing",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: -3,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusOK,
		},
		{
			name:                      "DataLeakFoundInPartialProcessing",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: -2,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusForbidden,
		},
		{
			name:                      "DataLeakAroundLimitPartialProcessing",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: -3,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusOK,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bodyLenThird := len(testCase.content) / 3
			bodyChunks := map[string][]string{
				"BodyInOneShot":     {testCase.content},
				"BodyInThreeChunks": {testCase.content[0:bodyLenThird], testCase.content[bodyLenThird : 2*bodyLenThird], testCase.content[2*bodyLenThird:]},
			}

			for name, chunks := range bodyChunks {
				t.Run(name, func(t *testing.T) {
					directives := fmt.Sprintf(`
						SecRuleEngine On
						SecResponseBodyAccess On
						SecResponseBodyMimeType text/plain
						SecResponseBodyLimit %d
						SecResponseBodyLimitAction %s
						SecRule RESPONSE_BODY "SQL Error" "id:100,phase:4,deny"
					`, len(testCase.content)+testCase.responseBodyRelativeLimit, testCase.responseBodyLimitAction)

					waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
					if err != nil {
						t.Fatal(err)
					}

					handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if len(chunks) == 1 {
							w.Header().Set("Content-Length", strconv.Itoa(len(testCase.content)))
						}
						w.Header().Set("Content-Type", "text/plain")
						for _, chunk := range chunks {
							if n, err := fmt.Fprint(w, chunk); err != nil {
								t.Logf("failed to write response: %s", err)
							} else if got, want := n, len(chunk); got != want {
								t.Errorf("written response byte count mismatch, got=%d, want=%d", got, want)
							}
							if f, ok := w.(http.Flusher); ok && len(chunks) > 1 {
								f.Flush()
							}
						}
					}))

					ts := httptest.NewServer(handler)
					t.Cleanup(ts.Close)

					res, err := http.Get(ts.URL)
					if err != nil {
						t.Fatalf("unexpected error performing request: %v", err)
					}
					defer res.Body.Close()

					if got, want := res.StatusCode, testCase.expectedStatusCode; got != want {
						t.Errorf("unexpected status code, got=%d, want=%d", got, want)
					}

					if testCase.expectedStatusCode == http.StatusOK {
						body, err := io.ReadAll(res.Body)
						if err != nil {
							t.Fatalf("failed to read response body: %v", err)
						}
						if got, want := string(body), testCase.content; got != want {
							t.Errorf("unexpected response body, got=%q, want=%q", got, want)
						}
					}
				})
			}
		})
	}
}
