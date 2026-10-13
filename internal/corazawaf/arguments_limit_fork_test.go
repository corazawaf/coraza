// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/collections"
)

// The tests in this file pin how the fork reports a SecArgumentsLimit trip. On
// top of upstream's ARGUMENTS_LIMIT_REACHED, the fork raises REQBODY_ERROR
// (RES_BODY_ERROR on the response path) with a message naming the limit, so a
// deployment whose rules only know the error variables still rejects the
// request (DEF-51539, DEF-57620).

func oversizedJSONBody(members int) string {
	body := strings.Builder{}
	body.WriteString("{")
	for i := 0; i < members; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, `"k%d":"v"`, i)
	}
	body.WriteString("}")
	return body.String()
}

// TestProcessRequestBodyArgumentsLimit asserts that a body holding more members
// than SecArgumentsLimit raises REQBODY_ERROR and ARGUMENTS_LIMIT_REACHED, names
// SecArgumentsLimit in REQBODY_ERROR_MSG, whichever processor parsed it, and
// leaves the REQBODY_PROCESSOR_ERROR family untouched: the processor itself did
// not fail. The collection keeps exactly SecArgumentsLimit members, so what
// fits under the limit stays available to the rules.
func TestProcessRequestBodyArgumentsLimit(t *testing.T) {
	const members = 50

	for _, tc := range []struct {
		name        string
		processor   string
		contentType string
		body        string
		count       func(tx *Transaction) int
	}{
		{
			name:        "json",
			processor:   "JSON",
			contentType: "application/json",
			body:        oversizedJSONBody(members),
			count:       func(tx *Transaction) int { return tx.variables.argsPost.Len() },
		},
		{
			name:        "urlencoded",
			processor:   "URLENCODED",
			contentType: "application/x-www-form-urlencoded",
			body: func() string {
				pairs := make([]string, 0, members)
				for i := 0; i < members; i++ {
					pairs = append(pairs, fmt.Sprintf("k%d=v", i))
				}
				return strings.Join(pairs, "&")
			}(),
			count: func(tx *Transaction) int { return tx.variables.argsPost.Len() },
		},
		{
			// REQUEST_XML is budgeted at MaxNodesPerArgument members per unit of
			// SecArgumentsLimit, so the body carries that many attributes per
			// member and the count is converted back into those units.
			name:        "xml",
			processor:   "XML",
			contentType: "application/xml",
			body: func() string {
				var b strings.Builder
				b.WriteString("<root>")
				for i := 0; i < members*bodyprocessors.MaxNodesPerArgument; i++ {
					fmt.Fprintf(&b, `<e a="v%d"/>`, i)
				}
				b.WriteString("</root>")
				return b.String()
			}(),
			count: func(tx *Transaction) int {
				return len(tx.variables.requestXML.FindAll()) / bodyprocessors.MaxNodesPerArgument
			},
		},
		{
			name:        "multipart",
			processor:   "MULTIPART",
			contentType: "multipart/form-data; boundary=X",
			body: func() string {
				var b strings.Builder
				for i := 0; i < members; i++ {
					fmt.Fprintf(&b, "--X\r\nContent-Disposition: form-data; name=\"k%d\"\r\n\r\nv\r\n", i)
				}
				b.WriteString("--X--\r\n")
				return b.String()
			}(),
			count: func(tx *Transaction) int { return tx.variables.argsPost.Len() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waf := NewWAF()
			waf.RequestBodyAccess = true
			waf.ArgumentLimit = 10
			tx := waf.NewTransaction()
			tx.AddRequestHeader("content-type", tc.contentType)
			tx.ProcessRequestHeaders()
			tx.variables.reqbodyProcessor.Set(tc.processor)
			if _, err := tx.requestBodyBuffer.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Fatal(err)
			}
			if want, have := "1", tx.variables.reqbodyError.Get(); want != have {
				t.Errorf("unexpected REQBODY_ERROR, want %q, have %q", want, have)
			}
			if want, have := argumentsLimitErrorMsg, tx.variables.reqbodyErrorMsg.Get(); want != have {
				t.Errorf("unexpected REQBODY_ERROR_MSG, want %q, have %q", want, have)
			}
			if want, have := "1", tx.variables.argumentsLimitReached.Get(); want != have {
				t.Errorf("unexpected ARGUMENTS_LIMIT_REACHED, want %q, have %q", want, have)
			}
			for _, v := range []struct {
				name string
				have string
			}{
				{"REQBODY_PROCESSOR_ERROR", tx.variables.reqbodyProcessorError.Get()},
				{"REQBODY_PROCESSOR_ERROR_MSG", tx.variables.reqbodyProcessorErrorMsg.Get()},
			} {
				if v.have != "" && v.have != "0" {
					t.Errorf("a count trip must not fail the body processor, %s is %q", v.name, v.have)
				}
			}
			if want, have := waf.ArgumentLimit, tc.count(tx); want != have {
				t.Errorf("truncation must fill the collection to the limit and stop, want %d members, have %d", want, have)
			}
			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}
}

// TestProcessResponseBodyArgumentsLimit asserts that a response body holding
// more members than SecArgumentsLimit raises RES_BODY_ERROR and
// ARGUMENTS_LIMIT_REACHED, names SecArgumentsLimit in RES_BODY_ERROR_MSG, and
// leaves the RES_BODY_PROCESSOR_ERROR family untouched: the processor itself
// did not fail. The collection keeps exactly SecArgumentsLimit members.
func TestProcessResponseBodyArgumentsLimit(t *testing.T) {
	const members = 50

	waf := NewWAF()
	waf.ResponseBodyAccess = true
	waf.ArgumentLimit = 10
	tx := waf.NewTransaction()
	tx.ForceResponseBodyVariable = true
	tx.variables.ResponseBodyProcessor().(*collections.Single).Set("JSON")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, _, err := tx.WriteResponseBody([]byte(oversizedJSONBody(members))); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal(err)
	}
	if want, have := "1", tx.variables.resBodyError.Get(); want != have {
		t.Errorf("unexpected RES_BODY_ERROR, want %q, have %q", want, have)
	}
	if want, have := argumentsLimitErrorMsg, tx.variables.resBodyErrorMsg.Get(); want != have {
		t.Errorf("unexpected RES_BODY_ERROR_MSG, want %q, have %q", want, have)
	}
	if want, have := "1", tx.variables.argumentsLimitReached.Get(); want != have {
		t.Errorf("unexpected ARGUMENTS_LIMIT_REACHED, want %q, have %q", want, have)
	}
	for _, v := range []struct {
		name string
		have string
	}{
		{"RES_BODY_PROCESSOR_ERROR", tx.variables.resBodyProcessorError.Get()},
		{"RES_BODY_PROCESSOR_ERROR_MSG", tx.variables.resBodyProcessorErrorMsg.Get()},
	} {
		if v.have != "" && v.have != "0" {
			t.Errorf("a count trip must not fail the body processor, %s is %q", v.name, v.have)
		}
	}
	if want, have := waf.ArgumentLimit, tx.variables.responseArgs.Len(); want != have {
		t.Errorf("truncation must fill the collection to the limit and stop, want %d members, have %d", want, have)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}
