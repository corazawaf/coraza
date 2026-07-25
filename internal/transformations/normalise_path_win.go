// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
)

func normalisePathWin(data string) (string, bool, error) {
	if len(data) < 1 {
		return data, false, nil
	}
	original := data

	clean, _, err := normalisePath(strings.ReplaceAll(data, "\\", "/"))
	if err != nil {
		return clean, false, err
	}

	// Windows resolves an NTFS Alternate Data Stream suffix ("file:stream",
	// "file::$DATA") against the base file, and silently strips trailing
	// dots and spaces from every path component before resolving it
	// ("file.txt.", "file.txt " both open "file.txt"). Neither is a no-op
	// for a WAF: a rule matching a blocklisted filename/extension against
	// the normalized path can be defeated by appending either, while
	// Windows/IIS still resolves the request to the exact blocked resource.
	stripped := stripWindowsTrailingDotsAndSpaces(stripWindowsADS(clean))

	// Compare against the true original input rather than reusing
	// normalisePath's own changed flag, which only sees the
	// already-slash-converted string and so misses a pure backslash-only
	// path (no other change needed) as "unchanged".
	return stripped, original != stripped, nil
}

// stripWindowsADS truncates the final path segment at its first ':',
// mirroring how Windows resolves an Alternate Data Stream suffix
// ("file.txt::$DATA" or "file.txt:hidden" both open "file.txt"'s data). A
// leading drive letter ("C:/...") is left untouched.
func stripWindowsADS(data string) string {
	prefix := ""
	if len(data) >= 2 && data[1] == ':' && isASCIILetter(data[0]) {
		prefix, data = data[:2], data[2:]
	}

	if idx := strings.LastIndexByte(data, '/'); idx >= 0 {
		if colon := strings.IndexByte(data[idx+1:], ':'); colon >= 0 {
			data = data[:idx+1+colon]
		}
	} else if colon := strings.IndexByte(data, ':'); colon >= 0 {
		data = data[:colon]
	}

	return prefix + data
}

// stripWindowsTrailingDotsAndSpaces mimics the Windows API (CreateFile et
// al.), which silently strips trailing '.' and ' ' from every path
// component before resolving it. A component that is entirely dots (".",
// "..", a leading ".." that filepath.Clean couldn't resolve further, or an
// empty component from a repeated "/") is left untouched -- those are
// navigation syntax, not a filename to canonicalize.
func stripWindowsTrailingDotsAndSpaces(data string) string {
	segments := strings.Split(data, "/")
	for i, seg := range segments {
		if isAllDots(seg) {
			continue
		}
		segments[i] = strings.TrimRight(seg, ". ")
	}
	return strings.Join(segments, "/")
}

func isAllDots(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '.' {
			return false
		}
	}
	return true
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
