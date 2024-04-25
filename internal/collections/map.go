// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Map is a default collection.Map.
type Map struct {
	isCaseSensitive bool
	data            map[string][]keyValue
	variable        variables.RuleVariable
}

var _ collection.Map = &Map{}

func NewMap(variable variables.RuleVariable) *Map {
	return &Map{
		isCaseSensitive: false,
		variable:        variable,
		data:            map[string][]keyValue{},
	}
}

func NewCaseSensitiveKeyMap(variable variables.RuleVariable) *Map {
	return &Map{
		isCaseSensitive: true,
		variable:        variable,
		data:            map[string][]keyValue{},
	}
}

func (c *Map) Get(key string) []string {
	if len(c.data) == 0 {
		return nil
	}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	var values []string
	for _, a := range c.data[key] {
		values = append(values, a.value)
	}
	return values
}

func (c *Map) FindRegex(key *regexp.Regexp) []types.MatchData {
	var result []types.MatchData
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, d := range data {
				result = append(result, &corazarules.MatchData{
					Variable_: c.variable,
					Key_:      d.key,
					Value_:    d.value,
				})
			}
		}
	}
	return result
}

// FindString
func (c *Map) FindString(key string) []types.MatchData {
	var result []types.MatchData
	if key == "" {
		return c.FindAll()
	}
	if len(c.data) == 0 {
		return nil
	}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	// if key is not empty
	if e, ok := c.data[key]; ok {
		for _, aVar := range e {
			result = append(result, &corazarules.MatchData{
				Variable_: c.variable,
				Key_:      aVar.key,
				Value_:    aVar.value,
			})
		}
	}
	return result
}

func (c *Map) FindAll() []types.MatchData {
	var result []types.MatchData
	for _, data := range c.data {
		for _, d := range data {
			result = append(result, &corazarules.MatchData{
				Variable_: c.variable,
				Key_:      d.key,
				Value_:    d.value,
			})
		}
	}
	return result
}

func (c *Map) Add(key string, value string) {
	aVal := keyValue{key: key, value: value}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	c.data[key] = append(c.data[key], aVal)
}

func (c *Map) Set(key string, values []string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	c.data[key] = make([]keyValue, 0, len(values))
	for _, v := range values {
		c.data[key] = append(c.data[key], keyValue{key: originalKey, value: v})
	}
}

func (c *Map) SetIndex(key string, index int, value string) {
	keyL := strings.ToLower(key)
	values := c.data[keyL]
	av := keyValue{key: key, value: value}

	switch {
	case len(values) == 0:
		c.data[keyL] = []keyValue{av}
	case len(values) <= index:
		c.data[keyL] = append(c.data[keyL], av)
	default:
		c.data[keyL][index] = av
	}
}

func (c *Map) Remove(key string) {
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	if len(c.data) == 0 {
		return
	}
	delete(c.data, key)
}

func (c *Map) Name() string {
	return c.variable.Name()
}

func (c *Map) Reset() {
	for k := range c.data {
		delete(c.data, k)
	}
}

func (c *Map) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(":\n")
	for k, v := range c.data {
		res.WriteString("    ")
		res.WriteString(k)
		res.WriteString(": ")
		for i, vv := range v {
			if i > 0 {
				res.WriteString(",")
			}
			res.WriteString(vv.value)
		}
		res.WriteByte('\n')
	}
}

func (c *Map) String() string {
	res := strings.Builder{}
	c.Format(&res)
	return res.String()
}

func (c *Map) Len() int {
	return len(c.data)
}

// keyValue stores the case preserved original key and value
// of the variable
type keyValue struct {
	key   string
	value string
}
