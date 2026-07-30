// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"github.com/corazawaf/coraza/v3/internal/strings"
)

func urlDecodeUni(data string) (string, bool, error) {
	for i := 0; i < len(data); i++ {
		if data[i] == '%' || data[i] == '+' {
			// The presence of '%' or '+' does not guarantee a change: an invalid
			// or truncated percent-encoding (e.g. "%zz" or a trailing "%") decodes
			// to itself.
			transformed, changed := inplaceUniDecode(data, []byte(data), i)
			return transformed, changed, nil
		}
	}
	return data, false, nil
}

// hexNibble maps an ASCII byte to its hex nibble value (0-15), or -1 if the
// byte is not a valid hex digit. It replaces repeated strings.ValidHex +
// strings.X2c calls with a single branch-free array lookup, since this table
// is read up to 4 times per %uXXXX escape in the hot decode loop below.
var hexNibble = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for c := byte('0'); c <= '9'; c++ {
		t[c] = int8(c - '0')
	}
	for c := byte('a'); c <= 'f'; c++ {
		t[c] = int8(c-'a') + 10
	}
	for c := byte('A'); c <= 'F'; c++ {
		t[c] = int8(c-'A') + 10
	}
	return t
}()

func inplaceUniDecode(input string, d []byte, pos int) (string, bool) {
	inputLen := len(d)
	i := pos
	c := pos
	// changed tracks whether an actual decode or space substitution took
	// place. Skipped (invalid/truncated) percent sequences are copied verbatim and
	// do not lead to a change.
	changed := false

	for i < inputLen {
		ch := input[i]

		if ch != '%' && ch != '+' {
			// Bulk-copy the literal run up to the next '%' or '+' instead of
			// shifting one byte at a time.
			start := i
			i++
			for i < inputLen && input[i] != '%' && input[i] != '+' {
				i++
			}
			// copy()'s runtime.memmove call costs more than it saves on short
			// runs; a direct store (n==1) or manual loop wins until the run
			// is long enough to amortize that call.
			switch n := i - start; {
			case n == 1:
				d[c] = input[start]
			case n == 2:
				d[c] = input[start]
				d[c+1] = input[start+1]
			case n <= 8:
				for k := range n {
					d[c+k] = input[start+k]
				}
			default:
				copy(d[c:], input[start:i])
			}
			c += i - start
			continue
		}

		if ch == '+' {
			d[c] = ' '
			c++
			i++
			changed = true
			continue
		}

		// ch == '%'
		if i+1 < inputLen && (input[i+1] == 'u' || input[i+1] == 'U') {
			/* IIS-specific %u encoding. */
			if i+5 < inputLen {
				h2 := hexNibble[input[i+2]]
				h3 := hexNibble[input[i+3]]
				h4 := hexNibble[input[i+4]]
				h5 := hexNibble[input[i+5]]
				if h2 >= 0 && h3 >= 0 && h4 >= 0 && h5 >= 0 {
					code := rune(h2)<<12 | rune(h3)<<8 | rune(h4)<<4 | rune(h5)
					if b, ok := unicodeBestFitASCII[code]; ok {
						d[c] = b
					} else {
						/* We first make use of the lower byte here,
						 * ignoring the higher byte. */
						low := byte(h4)<<4 | byte(h5)

						/* Full width ASCII (ff01 - ff5e) needs 0x20 added. */
						if low > 0x00 && low < 0x5f && h2 == 15 && h3 == 15 {
							low += 0x20
						}
						d[c] = low
					}
					c++
					i += 6
					changed = true
					continue
				}
			}
			/* Invalid or truncated %u escape: copy "%u" verbatim. */
			d[c] = input[i]
			d[c+1] = input[i+1]
			c += 2
			i += 2
			continue
		}

		/* Standard URL encoding. */
		if i+2 < inputLen {
			h1 := hexNibble[input[i+1]]
			h2 := hexNibble[input[i+2]]
			if h1 >= 0 && h2 >= 0 {
				d[c] = byte(h1)<<4 | byte(h2)
				c++
				i += 3
				changed = true
				continue
			}
		}
		/* Not a valid (or truncated) encoding, skip this '%'. */
		d[c] = input[i]
		i++
		c++
	}

	return strings.WrapUnsafe(d[0:c]), changed
}
