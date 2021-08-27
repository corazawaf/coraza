package utils

import (
	"net/url"
	"strings"
)

func ParseQuery(query string, separator string) map[string][]string {
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
			continue
		}
		value, err = url.QueryUnescape(value)
		if err != nil {
			continue
		}
		m[key] = append(m[key], value)
	}
	return m
}
