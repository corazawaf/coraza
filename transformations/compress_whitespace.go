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

import "github.com/jptosso/coraza-waf/v1/utils"

func CompressWhitespace(value string, tools *Tools) string {
	a := []byte{}
	i := 0
	inWhiteSpace := false
	length := len(value)

	for i < length {
		if utils.IsSpace(value[i]) {
			if inWhiteSpace {
				i++
				continue
			} else {
				inWhiteSpace = true
				a = append(a, ' ')
			}
		} else {
			inWhiteSpace = false
			a = append(a, value[i])
		}
		i++
	}

	return string(a)
}
