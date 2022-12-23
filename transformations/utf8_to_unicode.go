// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expstrs or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformations

import (
	"strconv"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func utf8ToUnicode(str string) (string, error) {
	for i, c := range str {
		if c >= utf8.RuneSelf {
			return doUTF8ToUnicode(str, i), nil
		}
	}
	return str, nil
}

func doUTF8ToUnicode(input string, pos int) string {
	// Preallocate to length of input, the encoded string will be at least
	// as long.
	res := make([]byte, pos, len(input))
	copy(res, input[0:pos])

	for _, c := range input[pos:] {
		cBytes := utf8.RuneLen(c)
		if cBytes == 1 {
			res = append(res, byte(c))
			continue
		}
		// 2 hex per byte
		cHexLen := cBytes * 2
		res = append(res, '%', 'u')
		// Pad to 4 characters
		for i := 0; i < 4-cHexLen; i++ {
			res = append(res, '0')
		}
		res = strconv.AppendUint(res, uint64(c), 16)
	}

	return strings.WrapUnsafe(res)
}
