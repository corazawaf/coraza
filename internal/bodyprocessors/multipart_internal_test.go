// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import "testing"

func TestFindFilenameStar(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue string
		wantOK    bool
	}{
		{
			name:      "simple utf-8",
			input:     `form-data; name="upload"; filename*=UTF-8''shell.php`,
			wantValue: "UTF-8''shell.php",
			wantOK:    true,
		},
		{
			name:   "not present",
			input:  `form-data; name="upload"; filename="safe.jpg"`,
			wantOK: false,
		},
		{
			name:      "case-insensitive parameter name",
			input:     `form-data; name="upload"; FILENAME*=UTF-8''shell.php`,
			wantValue: "UTF-8''shell.php",
			wantOK:    true,
		},
		{
			name:      "unrelated occurrence inside a quoted value is not mistaken for the parameter",
			input:     `form-data; name="upload"; filename="x; filename*=evil.php"; filename*=UTF-8''real.php`,
			wantValue: "UTF-8''real.php",
			wantOK:    true,
		},
		{
			name:      "escaped quote inside a quoted value does not end the quoted-string early",
			input:     `form-data; name="upload"; filename="a\"; filename*=evil.php\""; filename*=UTF-8''real.php`,
			wantValue: "UTF-8''real.php",
			wantOK:    true,
		},
		{
			name:      "trailing parameters after filename* are not included",
			input:     `form-data; name="upload"; filename*=UTF-8''shell.php; foo=bar`,
			wantValue: "UTF-8''shell.php",
			wantOK:    true,
		},
		{
			name:      "whitespace around the parameter is trimmed",
			input:     `form-data; name="upload"; filename* = UTF-8''shell.php `,
			wantValue: "UTF-8''shell.php",
			wantOK:    true,
		},
		{
			name:   "empty input",
			input:  "",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, ok := findFilenameStar(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("findFilenameStar(%q) ok = %v, want %v", tc.input, ok, tc.wantOK)
			}
			if ok && value != tc.wantValue {
				t.Errorf("findFilenameStar(%q) = %q, want %q", tc.input, value, tc.wantValue)
			}
		})
	}
}

func TestHasDuplicateParam(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "no duplicates",
			input: `form-data; name="upload"; filename="safe.jpg"`,
			want:  false,
		},
		{
			name:  "filename and filename* are distinct parameters",
			input: `form-data; name="upload"; filename="safe.jpg"; filename*=UTF-8''shell.php`,
			want:  false,
		},
		{
			name:  "repeated filename",
			input: `form-data; name="upload"; filename="safe.jpg"; filename="shell.php"`,
			want:  true,
		},
		{
			name:  "repeated filename*",
			input: `form-data; name="upload"; filename*=UTF-8''a.php; filename*=UTF-8''b.php`,
			want:  true,
		},
		{
			name:  "repetition differing only in case",
			input: `form-data; name="upload"; filename="safe.jpg"; FileName="shell.php"`,
			want:  true,
		},
		{
			name:  "a repeated parameter name inside a quoted value is not a duplicate",
			input: `form-data; name="upload"; filename="x; filename=evil.php"`,
			want:  false,
		},
		{
			name:  "a single empty parameter name is not a duplicate",
			input: `form-data; name="upload"; =x`,
			want:  false,
		},
		{
			name:  "a repeated empty parameter name is a duplicate",
			input: `form-data; name="upload"; =x; =y`,
			want:  true,
		},
		{
			name:  "empty input",
			input: "",
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasDuplicateParam(tc.input); got != tc.want {
				t.Errorf("hasDuplicateParam(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestPercentDecodeLenient(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        string
		wantInvalid bool
	}{
		{
			name:  "no percent signs",
			input: "shell.php",
			want:  "shell.php",
		},
		{
			name:  "single-byte escape",
			input: "na%EFve.txt",
			want:  "na\xefve.txt",
		},
		{
			name:  "multi-byte utf-8 escape",
			input: "na%C3%AFve.txt",
			want:  "naïve.txt",
		},
		{
			name:  "lowercase hex digits",
			input: "%2e%2e%2fetc%2fpasswd",
			want:  "../etc/passwd",
		},
		{
			name:        "percent not followed by hex digits is left as-is but flagged",
			input:       "100% done",
			want:        "100% done",
			wantInvalid: true,
		},
		{
			name:        "invalid hex digit is left as-is but flagged",
			input:       "safe.jpg%ZZ",
			want:        "safe.jpg%ZZ",
			wantInvalid: true,
		},
		{
			name:        "truncated escape at end of string is left as-is but flagged",
			input:       "shell.php%4",
			want:        "shell.php%4",
			wantInvalid: true,
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, invalid := percentDecodeLenient(tc.input)
			if got != tc.want {
				t.Errorf("percentDecodeLenient(%q) = %q, want %q", tc.input, got, tc.want)
			}
			if invalid != tc.wantInvalid {
				t.Errorf("percentDecodeLenient(%q) invalidEscape = %v, want %v", tc.input, invalid, tc.wantInvalid)
			}
		})
	}
}

func TestUnquoteIfQuoted(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantValue  string
		wantQuoted bool
	}{
		{
			name:       "unquoted token is returned unchanged",
			input:      "UTF-8''shell.php",
			wantValue:  "UTF-8''shell.php",
			wantQuoted: false,
		},
		{
			name:       "quoted value is unwrapped",
			input:      `"UTF-8''shell.php"`,
			wantValue:  "UTF-8''shell.php",
			wantQuoted: true,
		},
		{
			name:       "escaped quote inside a quoted value is unescaped",
			input:      `"UTF-8''shell\".php"`,
			wantValue:  `UTF-8''shell".php`,
			wantQuoted: true,
		},
		{
			name:       "single quote character is not treated as quoted",
			input:      `"`,
			wantValue:  `"`,
			wantQuoted: false,
		},
		{
			name:       "empty string",
			input:      "",
			wantValue:  "",
			wantQuoted: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, quoted := unquoteIfQuoted(tc.input)
			if quoted != tc.wantQuoted {
				t.Fatalf("unquoteIfQuoted(%q) ok = %v, want %v", tc.input, quoted, tc.wantQuoted)
			}
			if value != tc.wantValue {
				t.Errorf("unquoteIfQuoted(%q) = %q, want %q", tc.input, value, tc.wantValue)
			}
		})
	}
}

func BenchmarkFindFilenameStar(b *testing.B) {
	tests := []string{
		`form-data; name="upload"; filename="safe.jpg"; filename*=UTF-8''shell.php`,
		`form-data; name="upload"; filename="safe.jpg"`,
	}
	for _, tc := range tests {
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				findFilenameStar(tc)
			}
		})
	}
}

func BenchmarkPercentDecodeLenient(b *testing.B) {
	tests := []string{
		"shell.php",
		"na%C3%AFve%2Dresume.txt",
	}
	for _, tc := range tests {
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = percentDecodeLenient(tc)
			}
		})
	}
}
