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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expstrs or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformations

import (
	"fmt"
	"strings"
)

func utf8ToUnicode(str string) (string, error) {
	str = fmt.Sprintf("%+q", str)
	if len(str) > 2 {
		str = str[1 : len(str)-1]
	}
	return strings.ReplaceAll(str, "\\\"", "\""), nil
}
