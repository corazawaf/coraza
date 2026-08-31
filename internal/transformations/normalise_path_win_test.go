// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestNormalisePathWin(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: `C:\inetpub\wwwroot\index.html`,
			want:  "C:/inetpub/wwwroot/index.html",
		},
		{
			input: `..\..\etc\passwd`,
			want:  "../../etc/passwd",
		},
		{
			input: `foo\..\bar`,
			want:  "bar",
		},
		// Windows silently strips trailing dots and spaces from every path
		// component before resolving it, and resolves an NTFS Alternate
		// Data Stream suffix ("file:stream", "file::$DATA") against the
		// base file. Neither was stripped, so a rule matching a
		// blocklisted filename/extension against the normalized path could
		// be defeated by appending either. See
		// https://github.com/corazawaf/coraza/issues/1656.
		{
			input: `C:\inetpub\wwwroot\web.config.`,
			want:  "C:/inetpub/wwwroot/web.config",
		},
		{
			input: `C:\inetpub\wwwroot\web.config `,
			want:  "C:/inetpub/wwwroot/web.config",
		},
		{
			input: `C:\inetpub\wwwroot\web.config::$DATA`,
			want:  "C:/inetpub/wwwroot/web.config",
		},
		{
			input: `C:\inetpub\wwwroot\web.config:hidden`,
			want:  "C:/inetpub/wwwroot/web.config",
		},
		{
			// A leading ".." run that filepath.Clean can't resolve further
			// must not be mistaken for a trailing-dot filename and
			// stripped away.
			input: `..\..\web.config.`,
			want:  "../../web.config",
		},
		{
			// A drive letter alone must not be misread as an ADS-suffixed
			// filename.
			input: `C:`,
			want:  "C:",
		},
		{
			// A trailing separator after an ADS suffix must not push the
			// ADS-bearing component out of "last segment" position and
			// bypass the colon truncation.
			input: `C:\path\web.config:$DATA\`,
			want:  "C:/path/web.config/",
		},
		{
			// A component that is entirely spaces trims down to nothing;
			// Windows drops it rather than resolving through an empty
			// component, which would otherwise surface as "//".
			input: `C:\ \file.txt`,
			want:  "C:/file.txt",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := normalisePathWin(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			wantChanged := tt.input != tt.want
			if changed != wantChanged {
				t.Errorf("input %q: changed = %t, want %t (have %q)", tt.input, changed, wantChanged, have)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
		})
	}
}

func BenchmarkNormalisePathWin(b *testing.B) {
	tests := []string{
		"",
		`C:\inetpub\wwwroot\index.html`,
		`..\..\etc\passwd`,
		`C:\inetpub\wwwroot\web.config.`,
		`C:\inetpub\wwwroot\web.config::$DATA`,
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := normalisePathWin(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
