// Copyright 2020 Juan Pablo Tosso
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
import(
	"github.com/jptosso/coraza-waf/pkg/utils"
)

func RemoveWhitespace(data string) string{
    // loop through all the chars
    newstr := make([]byte, len(data))
    var i, c int
	for (i < len(data)) {
		// remove whitespaces and non breaking spaces (NBSP)
		if (utils.IsSpace(data[i]) || (data[i] == 160)) {
			i++
			continue
		} else {
			newstr[c] += data[i]
			c++
			i++
		}
	}

	//Don't forget to remove the after padding
	return string(newstr[0:c])
}