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

import "github.com/jptosso/coraza-waf/v2"

func RemoveComments(value string, utils coraza.RuleTransformationTools) string {
	inputLen := len(value)
	// we must add one pad to the right
	input := []byte(value + "\x00")

	var i, j int
	incomment := false

	for i < inputLen {
		if !incomment {
			if (input[i] == '/') && (i+1 < inputLen) && (input[i+1] == '*') {
				incomment = true
				i += 2
			} else if (input[i] == '<') && (i+1 < inputLen) && (input[i+1] == '!') && (i+2 < inputLen) && (input[i+2] == '-') && (i+3 < inputLen) && (input[i+3] == '-') && !incomment {
				incomment = true
				i += 4
			} else if (input[i] == '-') && (i+1 < inputLen) && (input[i+1] == '-') && !incomment {
				input[i] = ' '
				break
			} else if input[i] == '#' && !incomment {
				input[i] = ' '
				break
			} else {
				input[j] = input[i]
				i++
				j++
			}
		} else {
			if (input[i] == '*') && (i+1 < inputLen) && (input[i+1] == '/') {
				incomment = false
				i += 2
				input[j] = input[i]
				i++
				j++
			} else if (input[i] == '-') && (i+1 < inputLen) && (input[i+1] == '-') && (i+2 < inputLen) && (input[i+2] == '>') {
				incomment = false
				i += 3
				input[j] = input[i]
				i++
				j++
			} else {
				i++
			}
		}
	}

	if incomment {
		input[j] = ' '
		j++
	}
	return string(input[0:j])
}
