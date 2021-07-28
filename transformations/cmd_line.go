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
	"unicode"
)

/*
https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/actions/transformations/cmd_line.cc
Copied from modsecurity
deleting all backslashes [\]
deleting all double quotes ["]
deleting all single quotes [']
deleting all carets [^]
deleting spaces before a slash /
deleting spaces before an open parentesis [(]
replacing all commas [,] and semicolon [;] into a space
replacing all multiple spaces (including tab, newline, etc.) into one space
transform all characters to lowercase
*/
func CmdLine(data string, utils *Tools) string {
	space := false
	ret := []byte{}
	for _, a := range data {
		if a == '"' || a == '\'' || a == '\\' || a == '^' {
			/* remove some characters */
		} else if a == ' ' || a == ',' || a == ';' || a == '\t' || a == '\r' || a == '\n' {
			/* replace some characters to space (only one) */
			if !space {
				ret = append(ret, ' ')
				space = true
			}
		} else if a == '/' || a == '(' {
			/* remove space before / or ( */
			if space {
				ret = ret[:len(ret)-1]
			}
			space = false

			ret = append(ret, byte(a))
		} else {
			b := unicode.ToLower(a)
			ret = append(ret, byte(b))
			space = false
		}
	}
	return string(ret)
}
