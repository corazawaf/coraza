// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformations

import (
	"fmt"
	"strconv"
	"unicode/utf8"
)

func Utf8ToUnicode(str string) string {
	res := ""
	for len(str) > 0 {
		if str[0] == ' ' {
			str = str[1:]
			res += " "
			// Modsecurity handles normal space as " " but special spaces like %u009c and %u00a0 differently
			// Golang will consider special spaces just spaces
			// TODO It requires more research
			continue
		}
		r, size := utf8.DecodeRuneInString(str)
		c := strconv.QuoteRuneToASCII(r)
		res += fmt.Sprintf("%%%s", c[2:len(c)-1])

		str = str[size:]
	}
	return res
}
