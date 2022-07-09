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
package persistence

import (
	"errors"
	"strconv"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
)

var persistenceEngines = map[string]PersistenceEngine{}

var ErrPersistenceEngineNotFound = errors.New("Persistence Engine not found")

type Persistence struct {
	engine  PersistenceEngine
	timeout int
}

func (p *Persistence) SetEngine(name string) error {
	if engine, ok := persistenceEngines[name]; !ok {
		return ErrPersistenceEngineNotFound
	} else {
		p.engine = engine
	}
	return nil
}

func (p *Persistence) SetTimeout(timeout int) {
	p.timeout = timeout
}

func (p *Persistence) Get(collection *collection.CollectionMap, key string) error {
	err := p.engine.Get(collection, key)
	if err != nil {
		return err
	}
	// TODO validate expire
	return p.updateMetadata(collection, key, true)
}

func (p *Persistence) Delete(collection *collection.CollectionMap, key string) error {
	if err := p.engine.Delete(collection, key); err != nil {
		return err
	}
	return nil
}

func (p *Persistence) SumTo(collection string, key string, value int) {

}

func (p *Persistence) SubstractTo(collection string, key string, value int) {

}

func (p *Persistence) Set(collection *collection.CollectionMap, key string, value string) error {
	if err := p.updateMetadata(collection, key, true); err != nil {
		return err
	}
	return p.engine.Set(collection, key, value)
}

func (p *Persistence) updateMetadata(collection *collection.CollectionMap, key string, isUpdate bool) error {
	ts := time.Now().UnixNano()
	tss := strconv.FormatInt(ts, 10)
	tsstimeout := strconv.FormatInt(ts+(int64(p.timeout*1000)), 10)
	rm := map[string]string{
		"IS_NEW":  "0",
		"KEY":     key,
		"TIMEOUT": tsstimeout,
	}
	if collection.Get("CREATE_TIME") == nil {
		rm["CREATE_TIME"] = tss
		rm["IS_NEW"] = "1"
		rm["UPDATE_COUNTER"] = "0"
		rm["UPDATE_RATE"] = "0"
		rm["LAST_UPDATE_TIME"] = tss
	}
	if isUpdate {
		counter := 0
		if collection.Get("UPDATE_COUNTER") != nil {
			c := collection.Get("UPDATE_COUNTER")[0]
			counter, _ = strconv.Atoi(c)
		}
		rm["UPDATE_COUNTER"] = strconv.Itoa(counter + 1)
		rm["UPDATE_RATE"] = "0"
	}
	for k, v := range rm {
		if err := p.engine.Set(collection, k, v); err != nil {
			return err
		}
	}
	return nil
}

type PersistenceEngine interface {
	// Init will attempt initialization of the persistence engine
	Init(arguments string, timeout int) error
	// Get will return a collection data for the specific collection and key
	// For example, if you want USER for user id 15, you will request Get(USER, 15)
	Get(collection *collection.CollectionMap, key string) error
	SumTo(collection *collection.CollectionMap, key string, value int)
	SubstractTo(collection *collection.CollectionMap, key string, value int)
	Set(collection *collection.CollectionMap, key string, value string) error
	Delete(collection *collection.CollectionMap, key string) error
	// Close will close the persistence engine
	Close() error
}
