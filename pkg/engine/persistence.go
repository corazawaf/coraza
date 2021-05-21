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
	"fmt"
	"strconv"
	"time"
)

/*
Important notes
Persistent collections are stored as collection-key, where key is the key to the collection, ex. an IP Address

TODO
Add a thread to keep deleting timedout keys
Take care of race conditions between instances?If there are two transactions in place at the same time, data is going to be loaded and updated async
*/

type PersistenceEngine interface {
	Init(url string) error
	Get(key string) map[string][]string
	Set(key string, data map[string][]string) error
}

type PersistentCollection struct {
	collection string
	key        string
	ttl        int
	changed    bool
	data       map[string][]string
	engine     PersistenceEngine
	webapp     string
}

func (c *PersistentCollection) Init(engine PersistenceEngine, webappid string, collection string, key string) {
	c.engine = engine
	c.webapp = webappid
	c.collection = fmt.Sprintf("c-%s-%s-%s", webappid, collection, key)
	c.key = key
	err := c.Reload()
	if err != nil || c.data == nil {
		c.New(engine, webappid, collection, key, 0)
	}
}

func (c *PersistentCollection) New(engine PersistenceEngine, webappid string, collection string, key string, ttl int) {
	c.collection = fmt.Sprintf("c-%s-%s-%s", webappid, collection, key)
	c.ttl = ttl
	c.key = key
	c.engine = engine
	c.changed = true
	c.webapp = webappid
	timenow := strconv.FormatInt(time.Now().UnixNano(), 10)
	c.data = map[string][]string{
		"CREATE_TIME":      []string{timenow},
		"IS_NEW":           []string{"1"},
		"LAST_UPDATE_TIME": []string{timenow},
		"TIMEOUT":          []string{"0"},
		"UPDATE_COUNTER":   []string{"0"},
		"UPDATE_RATE":      []string{"0"},
	}
}

func (c *PersistentCollection) Reload() error {
	c.data = c.engine.Get(c.collection)
	return nil
}

func (c *PersistentCollection) Save() error {
	if c.changed {
		count, _ := strconv.Atoi(c.data["UPDATE_COUNTER"][0])
		newcount := strconv.Itoa(count + 1)
		timenow := strconv.FormatInt(time.Now().UnixNano(), 10)
		c.data["UPDATE_COUNTER"] = []string{newcount}
		c.data["LAST_UPDATE_TIME"] = []string{timenow}
		//TODO additional vars
	}
	c.engine.Set(c.collection, c.data)
	return nil
}

func (c *PersistentCollection) GetData() map[string][]string {
	return c.data
}

func (c *PersistentCollection) SetData(data map[string][]string) {
	c.changed = true
	c.data = data
}
