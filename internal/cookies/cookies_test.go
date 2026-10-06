// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package cookies

import (
	"strings"
	"testing"
)

func equalMaps(map1 map[string][]string, map2 map[string][]string) bool {
	if len(map1) != len(map2) {
		return false
	}

	// Iterate through the key-value pairs of the first map
	for key, slice1 := range map1 {
		// Check if the key exists in the second map
		slice2, ok := map2[key]
		if !ok {
			return false
		}

		// Compare the values of the corresponding keys
		for i, val1 := range slice1 {
			val2 := slice2[i]

			// Compare the elements
			if val1 != val2 {
				return false
			}
		}
	}

	return true
}

func TestParseCookies(t *testing.T) {
	type args struct {
		rawCookies string
	}
	tests := []struct {
		name string
		args args
		want map[string][]string
	}{
		{
			name: "EmptyString",
			args: args{rawCookies: "  "},
			want: map[string][]string{},
		},
		{
			name: "SimpleCookie",
			args: args{rawCookies: "test=test_value"},
			want: map[string][]string{"test": {"test_value"}},
		},
		{
			name: "MultipleCookies",
			args: args{rawCookies: "test1=test_value1; test2=test_value2"},
			want: map[string][]string{"test1": {"test_value1"}, "test2": {"test_value2"}},
		},
		{
			name: "SpacesInCookieName",
			args: args{rawCookies: " test1  =test_value1; test2  =test_value2"},
			want: map[string][]string{"test1": {"test_value1"}, "test2": {"test_value2"}},
		},
		{
			name: "SpacesInCookieValue",
			args: args{rawCookies: "test1=test   _value1; test2  =test_value2"},
			want: map[string][]string{"test1": {"test   _value1"}, "test2": {"test_value2"}},
		},
		{
			name: "EmptyCookie",
			args: args{rawCookies: ";;foo=bar"},
			want: map[string][]string{"foo": {"bar"}},
		},
		// A pair whose name is empty, or trims to empty, is kept under ""
		// so its value stays inspectable: Node's cookie package still
		// exposes it to the application. See GHSA-g4qm-m288-5cp9.
		{
			name: "EmptyName",
			args: args{rawCookies: "=bar;"},
			want: map[string][]string{"": {"bar"}},
		},
		{
			name: "CTLOnlyName",
			args: args{rawCookies: "a=1; \x01\x02=bar"},
			want: map[string][]string{"a": {"1"}, "": {"bar"}},
		},
		{
			name: "EmptyNameAndValue",
			args: args{rawCookies: "=; foo=bar"},
			want: map[string][]string{"foo": {"bar"}},
		},
		{
			name: "MultipleEqualsInValues",
			args: args{rawCookies: "test1=val==ue1;test2=value2"},
			want: map[string][]string{"test1": {"val==ue1"}, "test2": {"value2"}},
		},
		{
			name: "RepeatedCookieNameShouldGiveList",
			args: args{rawCookies: "test1=value1;test1=value2"},
			want: map[string][]string{"test1": {"value1", "value2"}},
		},
		// A CTL character (RFC 2616) directly adjacent to '=' used to be
		// kept as part of the cookie name instead of being treated as a
		// boundary, letting the name/value split land somewhere a real
		// cookie parser wouldn't put it. See GHSA-g4qm-m288-5cp9: RFC 6265
		// excludes CTLs from a name, and Python's http.cookies lands on
		// name "a", value "'".
		{
			name: "CTLAdjacentToEqualsIsTrimmedFromName",
			args: args{rawCookies: "a\v=\t'"},
			want: map[string][]string{"a": {"'"}},
		},
		{
			name: "CTLAndSpaceTrimmedFromBothEnds",
			args: args{rawCookies: "\ftest1\v = \tvalue1\r; test2=value2"},
			want: map[string][]string{"test1": {"value1"}, "test2": {"value2"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCookies(tt.args.rawCookies)
			if !equalMaps(got, tt.want) {
				t.Errorf("ParseCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkParseCookies(b *testing.B) {
	// Named rather than using the raw input as the sub-benchmark name:
	// several inputs contain spaces, which produce benchmark lines that
	// benchstat cannot parse.
	tests := []struct {
		name string
		in   string
	}{
		{"Empty", ""},
		{"Single", "test=test_value"},
		{"Pair", "test1=test_value1; test2=test_value2"},
		{"PaddedNames", " test1  =test_value1; test2  =test_value2"},
		{"SpaceInValue", "test1=test   _value1; test2  =test_value2"},
		{"LeadingSemicolons", ";;foo=bar"},
		{"EqualsInValue", "test1=val==ue1;test2=value2"},
		{"DuplicateName", "test1=value1;test1=value2"},
		{"CTLBoundary", "a\v=\t'"},
		// Attacker-controlled worst case: a CTL-saturated header forces the
		// trim to scan every byte rather than stopping at the first token
		// character. Guards trimCTLAndSpace's hot path against a regression
		// to a per-byte indirect call (e.g. strings.TrimFunc), which
		// measured ~5x slower here.
		{"CTLFlood", strings.Repeat("\x00", 64<<10) + "name=value"},
	}

	var sink map[string][]string
	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sink = ParseCookies(tt.in)
			}
		})
	}
	_ = sink
}
