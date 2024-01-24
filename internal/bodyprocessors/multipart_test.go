// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v4/internal/corazawaf"
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
