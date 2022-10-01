// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

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
	mp := &multipartBodyProcessor{}
	collections := createCollections()
	if err := mp.ProcessRequest(strings.NewReader(payload), collections, Options{
		Mime: "multipart/form-data; boundary=---------------------------9051914041544843365972754266",
	}); err != nil {
		t.Fatal(err)
	}
	// first we validate we got the headers
	headers := collections[variables.MultipartPartHeaders].(*collection.Map)
	if h := headers.Get("file2"); len(h) == 0 {
		t.Fatal("expected headers for file2")
	} else {
		if len(h) != 2 {
			t.Fatal("expected 2 headers for file2")
		}
		if h[0] != "Content-Disposition: form-data; name=\"file2\"; filename=\"a.html\"" {
			t.Fatalf("expected Content-Disposition header for file2, got %s", h[0])
		}
		if h[1] != "Content-Type: text/html" {
			t.Fatalf("expected Content-Type header for file2, got %s", h[1])
		}
	}
}

func createCollections() [types.VariablesCount]collection.Collection {
	collections := [types.VariablesCount]collection.Collection{}
	collections[variables.Files] = collection.NewMap(variables.Files)
	collections[variables.FilesTmpNames] = collection.NewMap(variables.FilesTmpNames)
	collections[variables.FilesSizes] = collection.NewMap(variables.FilesSizes)
	collections[variables.ArgsPost] = collection.NewMap(variables.ArgsPost)
	collections[variables.FilesCombinedSize] = collection.NewSimple(variables.FilesCombinedSize)
	collections[variables.FilesNames] = collection.NewMap(variables.FilesNames)
	collections[variables.MultipartPartHeaders] = collection.NewMap(variables.MultipartPartHeaders)
	return collections
}
