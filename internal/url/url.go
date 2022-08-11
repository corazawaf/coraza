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
	"strings"
)

// ParseQuery parses the URL-encoded query string and returns the corresponding map.
// It takes separators as parameter, for example: & or ; or &;
// It returns error if the query string is malformed.
func ParseQuery(query string, separator byte) map[string][]string {
	m := make(map[string][]string)
	for query != "" {
		key := query
		if i := strings.IndexByte(key, separator); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key = QueryUnescape(key)
		value = QueryUnescape(value)
		m[key] = append(m[key], value)
	}
	return m
}

// QueryUnescape is a non-strict version of net/url.QueryUnescape.
func QueryUnescape(input string) string {
	ilen := len(input)
	res := strings.Builder{}
	res.Grow(ilen)
	for i := 0; i < ilen; i++ {
		ci := input[i]
		if ci == '+' {
			res.WriteByte(' ')
			continue
		}
		if ci == '%' {
			if i+2 >= ilen {
				res.WriteByte(ci)
				continue
			}
			hi := input[i+1]
			lo := input[i+2]
			switch {
			case hi >= '0' && hi <= '9':
				hi -= '0'
			case hi >= 'a' && hi <= 'f':
				hi -= 'a' - 10
			case hi >= 'A' && hi <= 'F':
				hi -= 'A' - 10
			default:
				res.WriteByte(ci)
				continue
			}
			switch {
			case lo >= '0' && lo <= '9':
				lo -= '0'
			case lo >= 'a' && lo <= 'f':
				lo -= 'a' - 10
			case lo >= 'A' && lo <= 'F':
				lo -= 'A' - 10
			default:
				res.WriteByte(ci)
				continue
			}
			res.WriteByte(byte(hi<<4 | lo))
			i += 2
			continue
		}
		res.WriteByte(ci)
	}
	return res.String()
}
