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
	pcre "github.com/jptosso/coraza-waf/pkg/utils/pcre"
	"strconv"
	"strings"
)

type Collection struct {
	Name string
	Key  string
}

type LocalCollection struct {
	data map[string][]string `json:"data"`
	Name string
}

func NewCollection(name string) *LocalCollection {
	col := &LocalCollection{}
	col.Init(name)
	return col
}

func (c *LocalCollection) Init(name string) {
	c.data = map[string][]string{}
	c.data[""] = []string{}
	c.Name = name
}

func (c *LocalCollection) InitCollection(key string) {
	c.data[key] = []string{}
}

func (c *LocalCollection) Get(key string) []string {
	return c.data[key]
}

func (c *LocalCollection) GetSimple(key string) []string {
	return c.data[key]
}

//PCRE compatible collection with exceptions
func (c *LocalCollection) GetWithExceptions(key string, exceptions []string) []*MatchData {
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
					Collection: c.Name,
					Key:        k,
					Value:      v,
				})
			}
		}
		return data
	}

	if key[0] == '/' {
		key = key[1 : len(key)-1] //we strip slashes
		re := pcre.MustCompile(key, 0)
		result := []*MatchData{}
		for k := range cdata {
			if utils.ArrayContains(exceptions, k) {
				continue
			}
			m := re.Matcher([]byte(k), 0)
			if m.Matches() {
				for _, d := range cdata[k] {
					result = append(result, &MatchData{
						Collection: c.Name,
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
						Collection: c.Name,
						Key:        k,
						Value:      kd,
					})
				}
			}
		}
		return ret
	}
}

func (c *LocalCollection) GetFirstString(key string) string {
	a := c.data[key]
	if len(a) > 0 {
		return a[0]
	} else {
		return ""
	}
}

func (c *LocalCollection) GetFirstInt64(key string) int64 {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.ParseInt(a[0], 10, 64)
		return i
	} else {
		return 0
	}
}

func (c *LocalCollection) GetFirstInt(key string) int {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.Atoi(a[0])
		return i
	} else {
		return 0
	}
}

func (c *LocalCollection) Add(key string, value []string) {
	c.data[key] = value
}

func (c *LocalCollection) AddToKey(key string, value string) {
	c.data[key] = append(c.data[key], value)
}

func (c *LocalCollection) AddToKeyUnique(key string, value string) {
	pass := false
	for _, v := range c.data[key] {
		if v == value{
			pass = true
		}
	}
	if !pass{
		return
	}
	c.data[key] = append(c.data[key], value)
}

func (c *LocalCollection) Set(key string, value []string) {
	c.data[key] = value
}

func (c *LocalCollection) AddMap(data map[string][]string) {
	for k, v := range data {
		c.data[strings.ToLower(k)] = v
	}
}

func (c *LocalCollection) Update(key string, value []string) {
	c.data[key] = value
}

func (c *LocalCollection) Remove(key string) {
	delete(c.data, key)
}

func (c *LocalCollection) GetData() map[string][]string {
	return c.data
}

func (c *LocalCollection) SetData(data map[string][]string) {
	c.data = data
}

func (c *LocalCollection) Reset() {
	c.Init(c.Name)
}
