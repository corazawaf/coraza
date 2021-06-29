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

package engine

import (
	"github.com/jptosso/coraza-waf/pkg/utils"
	regex"github.com/jptosso/coraza-waf/pkg/utils/regex"
	"strconv"
	"strings"
)

type Collection struct {
	data map[string][]string `json:"data"`
	name string
}

func (c *Collection) Init(name string) {
	c.data = map[string][]string{}
	c.data[""] = []string{}
	c.name = name
}

func (c *Collection) Get(key string) []string {
	return c.data[key]
}

//PCRE compatible collection with exceptions
func (c *Collection) GetWithExceptions(key string, exceptions []string) []*MatchData {
	cdata := c.data
	//we return every value in case there is no key but there is a collection
	if len(key) == 0 {
		data := []*MatchData{}
		for k := range c.data {
			if utils.ArrayContains(exceptions, k) {
				continue
			}
			for _, v := range c.data[k] {

				data = append(data, &MatchData{
					Collection: c.name,
					Key:        k,
					Value:      v,
				})
			}
		}
		return data
	}

	// Regex
	if key[0] == '/' {
		key = key[1 : len(key)-1] //we strip slashes
		re := regex.MustCompile(key, 0)
		result := []*MatchData{}
		for k := range cdata {
			if utils.ArrayContains(exceptions, k) {
				continue
			}
			m := re.Matcher([]byte(k), 0)
			if m.Matches() {
				for _, d := range cdata[k] {
					result = append(result, &MatchData{
						Collection: c.name,
						Key:        k,
						Value:      d,
					})
				}
			}
		}
		return result
	} else {
		ret := []*MatchData{}
		//We pass through every record to apply filters
		for k := range cdata {
			if utils.ArrayContains(exceptions, k) {
				continue
			}
			if k == key {
				for _, kd := range cdata[k] {
					ret = append(ret, &MatchData{
						Collection: c.name,
						Key:        k,
						Value:      kd,
					})
				}
			}
		}
		return ret
	}
}

func (c *Collection) GetFirstString(key string) string {
	a := c.data[key]
	if len(a) > 0 {
		return a[0]
	} else {
		return ""
	}
}

func (c *Collection) GetFirstInt64(key string) int64 {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.ParseInt(a[0], 10, 64)
		return i
	} else {
		return 0
	}
}

func (c *Collection) GetFirstInt(key string) int {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.Atoi(a[0])
		return i
	} else {
		return 0
	}
}

func (c *Collection) Add(key string, value string) {
	//TODO check for
	c.data[key] = append(c.data[key], value)
}

func (c *Collection) AddUnique(key string, value string) {
	pass := false
	for _, v := range c.data[key] {
		if v == value {
			pass = true
		}
	}
	if !pass {
		return
	}
	c.data[key] = append(c.data[key], value)
}

func (c *Collection) Set(key string, value []string) {
	c.data[key] = value
}

func (c *Collection) AddMap(data map[string][]string) {
	for k, v := range data {
		c.data[strings.ToLower(k)] = v
	}
}

func (c *Collection) Remove(key string) {
	delete(c.data, key)
}

func (c *Collection) GetData() map[string][]string {
	return c.data
}

func (c *Collection) GetName() string {
	return c.name
}

func (c *Collection) SetData(data map[string][]string) {
	c.data = data
}

func (c *Collection) Reset() {
	c.data = map[string][]string{}
	c.data[""] = []string{}
}

// Creates a new collection
func NewCollection(name string) *Collection {
	col := &Collection{}
	col.Init(name)
	return col
}
