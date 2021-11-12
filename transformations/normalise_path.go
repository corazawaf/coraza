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
	"path/filepath"

	"github.com/jptosso/coraza-waf/v2"
)

func normalisePath(data string, utils coraza.RuleTransformationTools) string {
	leng := len(data)
	if leng < 1 {
		return data
	}
	clean := filepath.Clean(data)
	if clean == "." {
		return ""
	}
	if leng >= 2 && clean[0] == '.' && clean[1] == '/' {
		clean = clean[2:]
	}
	if data[len(data)-1] == '/' {
		return clean + "/"
	} else {
		return clean
	}
}
