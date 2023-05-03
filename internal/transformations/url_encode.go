// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "strings"

func urlEncode(data string) (string, bool, error) {
	transformedData, changed := doURLEncode(data)
	return transformedData, changed, nil
}

func doURLEncode(input string) (string, bool) {
	inputLen := len(input)
	if inputLen == 0 {
		return "", false
	}
	changed := false
	leng := inputLen * 3
	var d strings.Builder
	d.Grow(leng)
	c2xTable := []byte("0123456789abcdef")

	/* ENH Only encode the characters that really need to be encoded. */

	for i := 0; i < inputLen; i++ {
		cc := input[i]

		if cc == ' ' {
			d.WriteByte('+')
			changed = true
		} else {
			if (cc == 42) || ((cc >= 48) && (cc <= 57)) || ((cc >= 65) && (cc <= 90)) || ((cc >= 97) && (cc <= 122)) {
				d.WriteByte(cc)
			} else {
				d.Write([]byte{'%', c2xTable[(cc&0xff)>>4], c2xTable[(cc&0xff)&0x0f]})
				changed = true
			}
		}
	}

	return d.String(), changed
}
