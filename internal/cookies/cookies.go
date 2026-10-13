// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package cookies

import (
	"strings"
)

// ParseCookies parses cookies and splits in name, value pairs. Won't check for valid names nor values.
// If there are multiple cookies with the same name, it will append to the list with the same name key.
// Loosely based in the stdlib src/net/http/cookie.go
func ParseCookies(rawCookies string) map[string][]string {
	cookies := make(map[string][]string)

	rawCookies = trimCTLAndSpace(rawCookies)

	if rawCookies == "" {
		return cookies
	}

	var part string
	for len(rawCookies) > 0 { // continue since we have rest
		part, rawCookies, _ = strings.Cut(rawCookies, ";")
		part = trimCTLAndSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		name = trimCTLAndSpace(name)
		val = trimCTLAndSpace(val)
		// A name that is empty, or only CTLs and spaces, is kept under ""
		// rather than skipped: Node's cookie package still hands
		// "=payload" and "\x01=payload" to the application, so dropping
		// the pair would hide its value from REQUEST_COOKIES. Only a
		// pair with nothing left to inspect ("=") is skipped.
		// See GHSA-g4qm-m288-5cp9.
		if name == "" && val == "" {
			continue
		}
		cookies[name] = append(cookies[name], val)
	}
	return cookies
}

// trimCTLAndSpace trims leading/trailing ASCII control characters (RFC 2616
// CTL: octets 0x00-0x1F and 0x7F) and spaces -- a superset of
// net/textproto.TrimString's space/tab-only trim. Per RFC 6265, neither a
// cookie-name (token) nor a cookie-value (cookie-octet) may contain CTLs.
// The `<= 0x20` comparison covers octets 0x00-0x20, i.e. every CTL plus
// space (0x20); 0x7F is the one CTL above that range.
//
// A stray CTL character (e.g. a vertical tab) directly adjacent to '='
// used to be kept as part of the cookie name instead of being treated as a
// boundary, letting the name/value split land somewhere a real consumer
// wouldn't put it -- see GHSA-g4qm-m288-5cp9. RFC 6265's token and
// cookie-octet grammar excludes CTLs, and Python's http.cookies splits
// "a\v=x" as name "a". Backends disagree, though: Node's cookie package
// and Werkzeug keep "a\v" as the name. The trim follows the RFC; where a
// CTL lands in the interior of an otherwise-plausible name is left
// unresolved.
//
// Deliberately hand-rolled rather than strings.TrimFunc: TrimFunc invokes
// its predicate through a func value once per byte scanned, which measured
// ~5x slower on a CTL-saturated header. Cookie headers are attacker
// controlled and parsed on every request, so that constant factor is a
// CPU-amplification primitive, not just a micro-optimization. See
// BenchmarkParseCookies/CTLFlood. strings.TrimSpace is not a substitute
// either: it misses most CTLs and additionally trims U+0085/U+00A0, whose
// multi-byte encodings a backend would not strip -- reintroducing the very
// parser-disagreement class this fix closes.
func trimCTLAndSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] <= 0x20 || s[start] == 0x7f) {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] <= 0x20 || s[end-1] == 0x7f) {
		end--
	}
	return s[start:end]
}
