// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"strings"

	"github.com/corazawaf/coraza/v3/internal/regexp"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Map is a default collection.Map.
type Map struct {
	data     map[string][]keyValue
	variable variables.RuleVariable
}

var _ collection.Map = &Map{}

func NewMap(variable variables.RuleVariable) *Map {
	return &Map{
		variable: variable,
		data:     map[string][]keyValue{},
	}
}

func (c *Map) Get(key string) []string {
	if len(c.data) == 0 {
		return nil
	}
	keyL := strings.ToLower(key)
	var values []string
	for _, a := range c.data[keyL] {
		values = append(values, a.value)
	}
	return values
}

func (c *Map) FindRegex(key regexp.Regexp) []types.MatchData {
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

func (c *Map) FindString(key string) []types.MatchData {
	var result []types.MatchData
	if key == "" {
		return c.FindAll()
	}
	if len(c.data) == 0 {
		return nil
	}
	keyL := strings.ToLower(key)
	// if key is not empty
	if e, ok := c.data[keyL]; ok {
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
	keyL := strings.ToLower(key)
	aVal := keyValue{key: key, value: value}
	c.data[keyL] = append(c.data[keyL], aVal)
}

func (c *Map) Set(key string, values []string) {
	keyL := strings.ToLower(key)
	c.data[keyL] = make([]keyValue, 0, len(values))
	for _, v := range values {
		c.data[keyL] = append(c.data[keyL], keyValue{key: key, value: v})
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
	if len(c.data) == 0 {
		return
	}
	keyL := strings.ToLower(key)
	delete(c.data, keyL)
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
