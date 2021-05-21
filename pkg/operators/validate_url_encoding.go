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

package operators

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type ValidateUrlEncoding struct {
	data string
}

func (o *ValidateUrlEncoding) Init(data string) {
	// Does not require initialization
}

func (o *ValidateUrlEncoding) Evaluate(tx *engine.Transaction, value string) bool {
	if len(value) == 0 {
		return false
	}

	rc := validateUrlEncoding(value, len(value))
	switch rc {
	case 1:
		/* Encoding is valid */
		return false
	case -2:
		// Invalid URL Encoding: Non-hexadecimal
		return true
	case -3:
		//Invalid URL Encoding: Not enough characters at the end of input
		return true
	case -1:

	default:
		//Invalid URL Encoding: Internal error
		return true
	}
	return true
}

func validateUrlEncoding(input string, input_length int) int {
	var i int

	if input_length == 0 {
		return -1
	}

	for i < input_length {
		if input[i] == '%' {
			if i+2 >= input_length {
				/* Not enough bytes. */
				return -3
			} else {
				/* Here we only decode a %xx combination if it is valid,
				 * leaving it as is otherwise.
				 */
				c1 := input[i+1]
				c2 := input[i+2]

				if (((c1 >= '0') && (c1 <= '9')) || ((c1 >= 'a') && (c1 <= 'f')) || ((c1 >= 'A') && (c1 <= 'F'))) && (((c2 >= '0') && (c2 <= '9')) || ((c2 >= 'a') && (c2 <= 'f')) || ((c2 >= 'A') && (c2 <= 'F'))) {
					i += 3
				} else {
					/* Non-hexadecimal characters used in encoding. */
					return -2
				}
			}
		} else {
			i++
		}
	}
	return 1
}
