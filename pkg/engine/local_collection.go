// Copyright 2020 Juan Pablo Tosso
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
	"sync"
)

type Collection struct {
	Name string
	Key  string
}

type LocalCollection struct {
	Data map[string][]string `json:"data"`
	mux  *sync.RWMutex
	Name string
}

func NewCollection(name string) *LocalCollection {
	col := &LocalCollection{}
	col.Init(name)
	return col
}

func (c *LocalCollection) Init(name string) {
	c.Data = map[string][]string{}
	c.Data[""] = []string{}
	c.mux = &sync.RWMutex{}
	c.Name = name
}

func (c *LocalCollection) InitCollection(key string) {
	c.Data[key] = []string{}
}

func (c *LocalCollection) Get(key string) []string {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.Data[key]
}

func (c *LocalCollection) GetSimple(key string) []string {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.Data[key]
}

//PCRE compatible collection with exceptions
func (c *LocalCollection) GetWithExceptions(key string, exceptions []string) []*MatchData {
	c.mux.RLock()
	defer c.mux.RUnlock()
	cdata := c.Data
	//we return every value in case there is no key but there is a collection
	if len(key) == 0 {
		data := []*MatchData{}
		for k := range c.Data {
			if utils.ArrayContains(exceptions, k) {
				continue
			}
			for _, v := range c.Data[k] {

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

func (c *LocalCollection) GetFirstString() string {
	c.mux.RLock()
	defer c.mux.RUnlock()
	a := c.Data[""]
	if len(a) > 0 {
		return a[0]
	} else {
		return ""
	}
}

func (c *LocalCollection) GetFirstInt64() int64 {
	c.mux.RLock()
	defer c.mux.RUnlock()
	a := c.Data[""]
	if len(a) > 0 {
		i, _ := strconv.ParseInt(a[0], 10, 64)
		return i
	} else {
		return 0
	}
}

func (c *LocalCollection) GetFirstInt() int {
	c.mux.RLock()
	defer c.mux.RUnlock()
	a := c.Data[""]
	if len(a) > 0 {
		i, _ := strconv.Atoi(a[0])
		return i
	} else {
		return 0
	}
}

func (c *LocalCollection) Add(key string, value []string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.Data[key] = value
}

func (c *LocalCollection) AddToKey(key string, value string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.Data[key] = append(c.Data[key], value)
}

func (c *LocalCollection) Set(key string, value []string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.Data[key] = value
}

func (c *LocalCollection) AddMap(data map[string][]string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	for k, v := range data {
		c.Data[strings.ToLower(k)] = v
	}
}

func (c *LocalCollection) Update(key string, value []string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.Data[key] = value
}

func (c *LocalCollection) Remove(key string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.Data, key)
}

func (c *LocalCollection) GetData() map[string][]string {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.Data
}

func (c *LocalCollection) SetData(data map[string][]string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.Data = data
}
