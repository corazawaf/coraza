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

package url

import (
	"net/url"
	"strings"
)

// ParseQuery parses the URL-encoded query string and returns the corresponding map.
// It takes separators as parameter, for example: & or ; or &;
// It returns error if the query string is malformed.
func ParseQuery(query string, separator string) (map[string][]string, error) {
	m := make(map[string][]string)
	for query != "" {
		key := query
		if i := strings.IndexAny(key, separator); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.Index(key, "="); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key, err := url.QueryUnescape(key)
		if err != nil {
			return nil, err
		}
		value, err = url.QueryUnescape(value)
		if err != nil {
			return nil, err
		}
		m[key] = append(m[key], value)
	}
	return m, nil
}
